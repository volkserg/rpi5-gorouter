// Package dnsproxy — DNS-прокси routerd на :53: форвардит
// запросы клиентов в Pi-hole, отдельные домены — в свои upstream
// (dns_override.txt), а адреса доменов из списка VPN сообщает в nft-set
// с учётом TTL. Кэша нет: кэширует Pi-hole.
package dnsproxy

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"

	"github.com/volkserg/rpi5-gorouter/internal/domain"
)

// SetUpdater принимает адреса, узнанные из ответов на запросы доменов из
// списка; ttl — минимальный TTL A-записей ответа.
type SetUpdater interface {
	Learn(addrs []netip.Addr, ttl time.Duration)
}

// LocalZone — локальная зона LAN (имена клиентов из DHCP-аренд).
type LocalZone interface {
	// Domain — имя зоны (lan).
	Domain() string
	// LookupName — адрес клиента с именем label (одна метка, без зоны).
	LookupName(label string) (netip.Addr, bool)
	// LookupAddr — имя (без зоны) клиента с адресом a.
	LookupAddr(a netip.Addr) (string, bool)
}

// localTTL — TTL ответов из локальной зоны.
const localTTL = 60

// Значения Rules.FilterAAAA.
const (
	FilterAAAAVPN  = "vpn"
	FilterAAAAAll  = "all"
	FilterAAAANone = "none"
)

// Rules — то, что меняется при перезагрузке без перезапуска слушателей.
type Rules struct {
	// Upstream — следующий DNS в цепочке (Pi-hole).
	Upstream netip.AddrPort
	// Overrides — домены со своими upstream (пробуются по порядку).
	Overrides *domain.Matcher[[]netip.AddrPort]
	// VPN — домены, адреса которых идут в nft-set.
	VPN *domain.Matcher[struct{}]
	// FilterAAAA — для каких доменов AAAA отвечается пустым ответом.
	FilterAAAA string
	// ECS — передавать в Upstream адрес клиента (EDNS Client Subnet /32).
	// В override-upstream адрес клиента не уходит никогда.
	ECS bool
	// Local — локальная зона; запросы в неё никогда не уходят наружу.
	Local LocalZone
}

// Options — параметры сервера.
type Options struct {
	Listen []netip.AddrPort
	Rules  Rules
	Sets   SetUpdater
	Log    *slog.Logger
	// MaxInflight — одновременных запросов к upstream (dns-forward-max).
	MaxInflight int
	// UpstreamTimeout — ожидание ответа одного upstream.
	UpstreamTimeout time.Duration
}

// Server — DNS-прокси.
type Server struct {
	opts    Options
	rules   atomic.Pointer[Rules]
	sem     chan struct{}
	udp     *dns.Client
	tcp     *dns.Client
	mu      sync.Mutex
	servers []*dns.Server
}

// New создаёт сервер; слушатели открывает Start.
func New(o Options) *Server {
	if o.MaxInflight <= 0 {
		o.MaxInflight = 300
	}
	if o.UpstreamTimeout <= 0 {
		o.UpstreamTimeout = 3 * time.Second
	}
	if o.Log == nil {
		o.Log = slog.New(slog.DiscardHandler)
	}
	s := &Server{
		opts: o,
		sem:  make(chan struct{}, o.MaxInflight),
		udp:  &dns.Client{Net: "udp", Timeout: o.UpstreamTimeout, UDPSize: dns.DefaultMsgSize},
		tcp:  &dns.Client{Net: "tcp", Timeout: o.UpstreamTimeout},
	}
	s.SetRules(o.Rules)
	return s
}

// SetRules атомарно заменяет правила (на SIGHUP).
func (s *Server) SetRules(r Rules) {
	if r.Overrides == nil {
		r.Overrides = domain.NewMatcher[[]netip.AddrPort]()
	}
	if r.VPN == nil {
		r.VPN = domain.NewMatcher[struct{}]()
	}
	s.rules.Store(&r)
}

// Start открывает UDP- и TCP-слушатели на всех адресах Listen. Ошибка
// привязки любого из них — ошибка запуска (открытые закрываются).
func (s *Server) Start() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	lc := net.ListenConfig{Control: freebind}
	for _, ap := range s.opts.Listen {
		addr := ap.String()
		pc, err := lc.ListenPacket(context.Background(), "udp", addr)
		if err != nil {
			s.closeLocked()
			return fmt.Errorf("DNS udp %s: %w", addr, err)
		}
		ln, err := lc.Listen(context.Background(), "tcp", addr)
		if err != nil {
			pc.Close()
			s.closeLocked()
			return fmt.Errorf("DNS tcp %s: %w", addr, err)
		}
		for _, srv := range []*dns.Server{
			{PacketConn: pc, Handler: s},
			{Listener: ln, Handler: s},
		} {
			s.servers = append(s.servers, srv)
			go func() {
				if err := srv.ActivateAndServe(); err != nil {
					s.opts.Log.Error("DNS-слушатель остановился", "адрес", addr, "ошибка", err)
				}
			}()
		}
	}
	return nil
}

// Shutdown закрывает слушатели.
func (s *Server) Shutdown() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closeLocked()
}

func (s *Server) closeLocked() {
	for _, srv := range s.servers {
		_ = srv.Shutdown()
		// Если ActivateAndServe ещё не стартовал, Shutdown не закроет сокет.
		if srv.PacketConn != nil {
			srv.PacketConn.Close()
		}
		if srv.Listener != nil {
			srv.Listener.Close()
		}
	}
	s.servers = nil
}

// ServeDNS обрабатывает запрос клиента.
func (s *Server) ServeDNS(w dns.ResponseWriter, req *dns.Msg) {
	resp := s.handle(w, req)
	if resp != nil {
		_ = w.WriteMsg(resp)
	}
}

func (s *Server) handle(w dns.ResponseWriter, req *dns.Msg) *dns.Msg {
	r := s.rules.Load()
	udp := isUDP(w.RemoteAddr())
	client := addrOf(w.RemoteAddr())

	if len(req.Question) != 1 || req.Opcode != dns.OpcodeQuery {
		return s.forwardAndFix(req, []netip.AddrPort{r.Upstream}, udp, netip.Addr{})
	}
	q := req.Question[0]
	if r.Local != nil {
		if resp, ok := localAnswer(req, q, r.Local); ok {
			return resp
		}
	}
	_, _, isVPN := r.VPN.Lookup(q.Name)

	switch {
	case q.Qtype == dns.TypePTR && bogusPriv(q.Name):
		// bogus-priv: обратные запросы для частных сетей не уходят наружу.
		return reply(req, dns.RcodeNameError)
	case q.Qtype == dns.TypeAAAA && (r.FilterAAAA == FilterAAAAAll || (r.FilterAAAA == FilterAAAAVPN && isVPN)):
		// Без AAAA клиент пойдёт по IPv4 — туда, где работает маршрутизация.
		return reply(req, dns.RcodeSuccess)
	}

	upstreams, ecsClient := []netip.AddrPort{r.Upstream}, netip.Addr{}
	if r.ECS {
		ecsClient = client
	}
	if ups, _, ok := r.Overrides.Lookup(q.Name); ok {
		upstreams, ecsClient = ups, netip.Addr{}
	}
	resp := s.forwardAndFix(req, upstreams, udp, ecsClient)

	if isVPN && resp.Rcode == dns.RcodeSuccess && s.opts.Sets != nil {
		if addrs, ttl := aRecords(resp); len(addrs) > 0 {
			s.opts.Sets.Learn(addrs, ttl)
		}
	}
	return resp
}

// forwardAndFix пересылает запрос и готовит ответ клиенту; при отказе
// всех upstream — SERVFAIL.
func (s *Server) forwardAndFix(req *dns.Msg, upstreams []netip.AddrPort, udp bool, ecsClient netip.Addr) *dns.Msg {
	select {
	case s.sem <- struct{}{}:
		defer func() { <-s.sem }()
	default:
		return reply(req, dns.RcodeServerFailure)
	}

	m := req.Copy()
	addedECS := ecsClient.IsValid() && ecsClient.Is4() && !ecsClient.IsLoopback() && setECS(m, ecsClient)

	resp, err := s.exchange(m, upstreams, udp)
	if err != nil {
		s.opts.Log.Warn("upstream DNS не ответил", "запрос", questionString(req), "ошибка", err)
		return reply(req, dns.RcodeServerFailure)
	}
	resp.Id = req.Id
	fixEDNS(req, resp, addedECS)
	if udp {
		size := dns.MinMsgSize
		if opt := req.IsEdns0(); opt != nil && int(opt.UDPSize()) > size {
			size = int(opt.UDPSize())
		}
		resp.Truncate(size)
	}
	return resp
}

// exchange пробует upstream по порядку; ответ UDP с флагом TC повторяется по TCP.
func (s *Server) exchange(m *dns.Msg, upstreams []netip.AddrPort, udp bool) (*dns.Msg, error) {
	var errs []error
	for _, up := range upstreams {
		c := s.tcp
		if udp {
			c = s.udp
		}
		resp, _, err := c.Exchange(m, up.String())
		if err == nil && resp.Truncated && udp {
			resp, _, err = s.tcp.Exchange(m, up.String())
		}
		if err == nil {
			return resp, nil
		}
		errs = append(errs, fmt.Errorf("%s: %w", up, err))
	}
	return nil, errors.Join(errs...)
}

// setECS добавляет EDNS Client Subnet с адресом клиента (/32), заменяя
// присланный клиентом. Возвращает true, если опция добавлена.
func setECS(m *dns.Msg, client netip.Addr) bool {
	opt := m.IsEdns0()
	if opt == nil {
		m.SetEdns0(dns.DefaultMsgSize, false)
		opt = m.IsEdns0()
	}
	kept := opt.Option[:0]
	for _, o := range opt.Option {
		if o.Option() != dns.EDNS0SUBNET {
			kept = append(kept, o)
		}
	}
	opt.Option = append(kept, &dns.EDNS0_SUBNET{
		Code:          dns.EDNS0SUBNET,
		Family:        1,
		SourceNetmask: 32,
		Address:       net.IP(client.AsSlice()),
	})
	return true
}

// fixEDNS приводит EDNS ответа к запросу клиента: клиенту без EDNS — без
// OPT; если ECS добавили мы, он не должен вернуться клиенту.
func fixEDNS(req, resp *dns.Msg, addedECS bool) {
	if req.IsEdns0() == nil {
		extra := resp.Extra[:0]
		for _, rr := range resp.Extra {
			if rr.Header().Rrtype != dns.TypeOPT {
				extra = append(extra, rr)
			}
		}
		resp.Extra = extra
		return
	}
	if !addedECS || hasECS(req) {
		return
	}
	if opt := resp.IsEdns0(); opt != nil {
		kept := opt.Option[:0]
		for _, o := range opt.Option {
			if o.Option() != dns.EDNS0SUBNET {
				kept = append(kept, o)
			}
		}
		opt.Option = kept
	}
}

func hasECS(m *dns.Msg) bool {
	if opt := m.IsEdns0(); opt != nil {
		for _, o := range opt.Option {
			if o.Option() == dns.EDNS0SUBNET {
				return true
			}
		}
	}
	return false
}

// aRecords — IPv4-адреса из ответа и минимальный TTL среди них.
func aRecords(resp *dns.Msg) ([]netip.Addr, time.Duration) {
	var addrs []netip.Addr
	var minTTL uint32
	for _, rr := range resp.Answer {
		a, ok := rr.(*dns.A)
		if !ok {
			continue
		}
		if addr, ok := netip.AddrFromSlice(a.A.To4()); ok {
			addrs = append(addrs, addr)
			if len(addrs) == 1 || a.Hdr.Ttl < minTTL {
				minTTL = a.Hdr.Ttl
			}
		}
	}
	return addrs, time.Duration(minTTL) * time.Second
}

// localAnswer отвечает на запросы в локальную зону (имя.lan) и на PTR
// адресов из аренд. ok=false — запрос не относится к зоне.
func localAnswer(req *dns.Msg, q dns.Question, z LocalZone) (*dns.Msg, bool) {
	name := domain.Normalize(q.Name)
	zone := z.Domain()

	if q.Qtype == dns.TypePTR {
		a, ok := reverseAddr(name)
		if !ok {
			return nil, false
		}
		host, ok := z.LookupAddr(a)
		if !ok {
			return nil, false // дальше — bogus-priv или upstream
		}
		m := authoritative(req, dns.RcodeSuccess)
		m.Answer = append(m.Answer, &dns.PTR{
			Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypePTR, Class: dns.ClassINET, Ttl: localTTL},
			Ptr: dns.Fqdn(host + "." + zone),
		})
		return m, true
	}

	if name != zone && !strings.HasSuffix(name, "."+zone) {
		return nil, false
	}
	label := strings.TrimSuffix(strings.TrimSuffix(name, zone), ".")
	if label == "" {
		return authoritative(req, dns.RcodeSuccess), true
	}
	a, ok := z.LookupName(label)
	if !ok || strings.Contains(label, ".") {
		return authoritative(req, dns.RcodeNameError), true
	}
	m := authoritative(req, dns.RcodeSuccess)
	if q.Qtype == dns.TypeA || q.Qtype == dns.TypeANY {
		m.Answer = append(m.Answer, &dns.A{
			Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: localTTL},
			A:   net.IP(a.AsSlice()),
		})
	}
	return m, true
}

func authoritative(req *dns.Msg, rcode int) *dns.Msg {
	m := reply(req, rcode)
	m.Authoritative = true
	return m
}

// reverseAddr — IPv4-адрес из имени d.c.b.a.in-addr.arpa.
func reverseAddr(name string) (netip.Addr, bool) {
	rest, ok := strings.CutSuffix(name, ".in-addr.arpa")
	if !ok {
		return netip.Addr{}, false
	}
	parts := strings.Split(rest, ".")
	if len(parts) != 4 {
		return netip.Addr{}, false
	}
	slices.Reverse(parts)
	a, err := netip.ParseAddr(strings.Join(parts, "."))
	return a, err == nil && a.Is4()
}

func reply(req *dns.Msg, rcode int) *dns.Msg {
	m := new(dns.Msg)
	m.SetRcode(req, rcode)
	m.RecursionAvailable = true
	return m
}

// privateReverse — обратные зоны частных и служебных сетей (RFC 6303),
// которые не отправляются наружу (как bogus-priv в dnsmasq).
var privateReverse = func() *domain.Matcher[struct{}] {
	m := domain.NewMatcher[struct{}]()
	zones := []string{
		"10.in-addr.arpa", "168.192.in-addr.arpa", "254.169.in-addr.arpa",
		"127.in-addr.arpa", "0.in-addr.arpa",
		"2.0.192.in-addr.arpa", "100.51.198.in-addr.arpa", "113.0.203.in-addr.arpa",
		"255.255.255.255.in-addr.arpa",
		"d.f.ip6.arpa", "8.e.f.ip6.arpa", "9.e.f.ip6.arpa", "a.e.f.ip6.arpa", "b.e.f.ip6.arpa",
	}
	for i := 16; i <= 31; i++ {
		zones = append(zones, fmt.Sprintf("%d.172.in-addr.arpa", i))
	}
	for i := 64; i <= 127; i++ { // 100.64.0.0/10 (RFC 6598)
		zones = append(zones, fmt.Sprintf("%d.100.in-addr.arpa", i))
	}
	for _, z := range zones {
		m.Set(z, struct{}{})
	}
	return m
}()

func bogusPriv(name string) bool {
	_, _, ok := privateReverse.Lookup(name)
	return ok
}

func isUDP(a net.Addr) bool {
	_, ok := a.(*net.UDPAddr)
	return ok
}

func addrOf(a net.Addr) netip.Addr {
	var ip net.IP
	switch v := a.(type) {
	case *net.UDPAddr:
		ip = v.IP
	case *net.TCPAddr:
		ip = v.IP
	}
	addr, _ := netip.AddrFromSlice(ip)
	return addr.Unmap()
}

func questionString(m *dns.Msg) string {
	if len(m.Question) == 0 {
		return "(без вопроса)"
	}
	q := m.Question[0]
	return strings.TrimSuffix(q.Name, ".") + " " + dns.TypeToString[q.Qtype]
}
