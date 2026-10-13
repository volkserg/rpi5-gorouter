package dnsproxy

import (
	"fmt"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/volkserg/rpi5-gorouter/internal/domain"
)

// upstream — поддельный DNS-сервер (UDP и TCP на одном порту).
type upstream struct {
	addr netip.AddrPort
	mu   sync.Mutex
	reqs []*dns.Msg
	nets []string
}

func (u *upstream) requests() []*dns.Msg {
	u.mu.Lock()
	defer u.mu.Unlock()
	return append([]*dns.Msg(nil), u.reqs...)
}

// startUpstream поднимает сервер; answer строит ответ на запрос (net — "udp"/"tcp").
func startUpstream(t *testing.T, answer func(req *dns.Msg, network string) *dns.Msg) *upstream {
	t.Helper()
	u := &upstream{}
	for attempt := 0; ; attempt++ {
		pc, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		ln, err := net.Listen("tcp", pc.LocalAddr().String())
		if err != nil {
			pc.Close()
			if attempt < 5 {
				continue
			}
			t.Fatal(err)
		}
		u.addr = netip.MustParseAddrPort(pc.LocalAddr().String())
		h := func(network string) dns.HandlerFunc {
			return func(w dns.ResponseWriter, r *dns.Msg) {
				u.mu.Lock()
				u.reqs = append(u.reqs, r.Copy())
				u.nets = append(u.nets, network)
				u.mu.Unlock()
				_ = w.WriteMsg(answer(r, network))
			}
		}
		for _, srv := range []*dns.Server{
			{PacketConn: pc, Handler: h("udp")},
			{Listener: ln, Handler: h("tcp")},
		} {
			go func() { _ = srv.ActivateAndServe() }()
			t.Cleanup(func() { _ = srv.Shutdown() })
		}
		return u
	}
}

// answerA отвечает на A записями addrs с TTL ttl (по порядку), на прочее — пусто.
func answerA(ttls []uint32, addrs ...string) func(*dns.Msg, string) *dns.Msg {
	return func(req *dns.Msg, _ string) *dns.Msg {
		m := new(dns.Msg)
		m.SetReply(req)
		q := req.Question[0]
		if q.Qtype == dns.TypeA {
			for i, a := range addrs {
				m.Answer = append(m.Answer, &dns.A{
					Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: ttls[i%len(ttls)]},
					A:   net.ParseIP(a),
				})
			}
		}
		if q.Qtype == dns.TypeAAAA {
			m.Answer = append(m.Answer, &dns.AAAA{
				Hdr:  dns.RR_Header{Name: q.Name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 60},
				AAAA: net.ParseIP("2001:db8::1"),
			})
		}
		if opt := req.IsEdns0(); opt != nil {
			// Как настоящие серверы: отражаем OPT, включая ECS.
			m.SetEdns0(opt.UDPSize(), false)
			m.IsEdns0().Option = append(m.IsEdns0().Option, opt.Option...)
		}
		return m
	}
}

type learned struct {
	addrs []netip.Addr
	ttl   time.Duration
}

type fakeSets struct {
	mu  sync.Mutex
	got []learned
}

func (f *fakeSets) Learn(addrs []netip.Addr, ttl time.Duration) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.got = append(f.got, learned{addrs, ttl})
}

// writer — поддельный ResponseWriter с адресом клиента.
type writer struct {
	dns.ResponseWriter
	remote net.Addr
}

func (w writer) RemoteAddr() net.Addr { return w.remote }

var (
	lanUDP = &net.UDPAddr{IP: net.ParseIP("192.168.3.50"), Port: 40000}
	lanTCP = &net.TCPAddr{IP: net.ParseIP("192.168.3.50"), Port: 40000}
	loUDP  = &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 40000}
)

func matcher[V any](v V, names ...string) *domain.Matcher[V] {
	m := domain.NewMatcher[V]()
	for _, n := range names {
		m.Set(n, v)
	}
	return m
}

func newProxy(up *upstream, sets SetUpdater, mod func(*Rules)) *Server {
	r := Rules{
		Upstream:   up.addr,
		VPN:        matcher(struct{}{}, "vpn.test"),
		FilterAAAA: FilterAAAAVPN,
		ECS:        true,
	}
	if mod != nil {
		mod(&r)
	}
	return New(Options{Rules: r, Sets: sets, UpstreamTimeout: time.Second})
}

func query(name string, qtype uint16, edns bool) *dns.Msg {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), qtype)
	if edns {
		m.SetEdns0(1232, false)
	}
	return m
}

func ecsOf(m *dns.Msg) (netip.Prefix, bool) {
	if opt := m.IsEdns0(); opt != nil {
		for _, o := range opt.Option {
			if s, ok := o.(*dns.EDNS0_SUBNET); ok {
				a, _ := netip.AddrFromSlice(s.Address.To4())
				return netip.PrefixFrom(a, int(s.SourceNetmask)), true
			}
		}
	}
	return netip.Prefix{}, false
}

func TestForwardPlainDomain(t *testing.T) {
	up := startUpstream(t, answerA([]uint32{300}, "203.0.113.10"))
	sets := &fakeSets{}
	p := newProxy(up, sets, nil)

	req := query("direct.test", dns.TypeA, false)
	resp := p.handle(writer{remote: lanUDP}, req)
	if resp.Rcode != dns.RcodeSuccess || len(resp.Answer) != 1 || resp.Id != req.Id {
		t.Fatalf("resp: %v", resp)
	}
	if len(sets.got) != 0 {
		t.Errorf("обычный домен не должен попадать в set: %v", sets.got)
	}
}

func TestVPNDomainLearnsAddresses(t *testing.T) {
	up := startUpstream(t, answerA([]uint32{300, 60}, "203.0.113.20", "203.0.113.21"))
	sets := &fakeSets{}
	p := newProxy(up, sets, nil)

	for _, name := range []string{"vpn.test", "cdn.VPN.test"} {
		p.handle(writer{remote: lanUDP}, query(name, dns.TypeA, false))
	}
	if len(sets.got) != 2 {
		t.Fatalf("ожидалось два обучения (домен и поддомен): %v", sets.got)
	}
	l := sets.got[0]
	if len(l.addrs) != 2 || l.addrs[0].String() != "203.0.113.20" || l.ttl != 60*time.Second {
		t.Errorf("learned = %+v, ожидались оба адреса и минимальный TTL 60s", l)
	}
}

func TestFilterAAAA(t *testing.T) {
	up := startUpstream(t, answerA([]uint32{60}, "203.0.113.20"))
	for _, tc := range []struct {
		mode            string
		vpnEmpty, else_ bool // пустой ответ для vpn.test / для других
	}{
		{FilterAAAAVPN, true, false},
		{FilterAAAAAll, true, true},
		{FilterAAAANone, false, false},
	} {
		p := newProxy(up, nil, func(r *Rules) { r.FilterAAAA = tc.mode })
		for name, wantEmpty := range map[string]bool{"vpn.test": tc.vpnEmpty, "direct.test": tc.else_} {
			resp := p.handle(writer{remote: lanUDP}, query(name, dns.TypeAAAA, false))
			if resp.Rcode != dns.RcodeSuccess || (len(resp.Answer) == 0) != wantEmpty {
				t.Errorf("FILTER_AAAA=%s %s: rcode=%d answers=%d", tc.mode, name, resp.Rcode, len(resp.Answer))
			}
		}
	}
}

func TestOverrideAndECS(t *testing.T) {
	main := startUpstream(t, answerA([]uint32{60}, "203.0.113.10"))
	corp := startUpstream(t, answerA([]uint32{60}, "10.20.0.5"))
	p := newProxy(main, nil, func(r *Rules) {
		r.Overrides = matcher([]netip.AddrPort{corp.addr}, "corp.test")
	})

	resp := p.handle(writer{remote: lanUDP}, query("git.corp.test", dns.TypeA, false))
	if len(resp.Answer) != 1 || resp.Answer[0].(*dns.A).A.String() != "10.20.0.5" {
		t.Fatalf("override: %v", resp)
	}
	if reqs := corp.requests(); len(reqs) != 1 {
		t.Fatalf("override-upstream получил %d запросов", len(reqs))
	} else if _, ok := ecsOf(reqs[0]); ok {
		t.Error("адрес клиента не должен уходить в override-upstream")
	}

	p.handle(writer{remote: lanUDP}, query("direct.test", dns.TypeA, false))
	reqs := main.requests()
	if len(reqs) != 1 {
		t.Fatalf("основной upstream получил %d запросов", len(reqs))
	}
	if ecs, ok := ecsOf(reqs[0]); !ok || ecs.String() != "192.168.3.50/32" {
		t.Errorf("ECS = %v %v, want 192.168.3.50/32", ecs, ok)
	}

	// Запросы самой RPi (GOST через 127.0.0.1) — без ECS.
	p.handle(writer{remote: loUDP}, query("direct.test", dns.TypeA, false))
	if _, ok := ecsOf(main.requests()[1]); ok {
		t.Error("для loopback-клиента ECS не нужен")
	}
	// DNS_ECS=no.
	p2 := newProxy(main, nil, func(r *Rules) { r.ECS = false })
	p2.handle(writer{remote: lanUDP}, query("direct.test", dns.TypeA, false))
	if _, ok := ecsOf(main.requests()[2]); ok {
		t.Error("DNS_ECS=no, но ECS отправлен")
	}
}

func TestEDNSHygiene(t *testing.T) {
	up := startUpstream(t, answerA([]uint32{60}, "203.0.113.10"))
	p := newProxy(up, nil, nil)

	// Клиент без EDNS: в ответе не должно быть OPT, хотя upstream его вернул.
	resp := p.handle(writer{remote: lanUDP}, query("direct.test", dns.TypeA, false))
	if resp.IsEdns0() != nil {
		t.Error("клиенту без EDNS вернулся OPT")
	}
	// Клиент с EDNS без ECS: OPT есть, но без нашего ECS.
	resp = p.handle(writer{remote: lanUDP}, query("direct.test", dns.TypeA, true))
	if resp.IsEdns0() == nil {
		t.Fatal("клиенту с EDNS нужен OPT")
	}
	if _, ok := ecsOf(resp); ok {
		t.Error("добавленный нами ECS вернулся клиенту")
	}
}

func TestBogusPriv(t *testing.T) {
	up := startUpstream(t, answerA([]uint32{60}))
	p := newProxy(up, nil, nil)
	for _, name := range []string{"50.3.168.192.in-addr.arpa", "1.0.0.10.in-addr.arpa", "1.0.20.172.in-addr.arpa", "1.0.64.100.in-addr.arpa"} {
		if resp := p.handle(writer{remote: lanUDP}, query(name, dns.TypePTR, false)); resp.Rcode != dns.RcodeNameError {
			t.Errorf("%s: rcode=%d, want NXDOMAIN", name, resp.Rcode)
		}
	}
	if n := len(up.requests()); n != 0 {
		t.Errorf("частные PTR не должны уходить в upstream: %d", n)
	}
	p.handle(writer{remote: lanUDP}, query("8.8.8.8.in-addr.arpa", dns.TypePTR, false))
	if n := len(up.requests()); n != 1 {
		t.Errorf("публичный PTR должен уйти в upstream: %d", n)
	}
}

func TestTruncation(t *testing.T) {
	var many []string
	for i := 1; i <= 60; i++ {
		many = append(many, fmt.Sprintf("203.0.113.%d", i))
	}
	full := answerA([]uint32{60}, many...)
	up := startUpstream(t, func(req *dns.Msg, network string) *dns.Msg {
		m := full(req, network)
		if network == "udp" {
			// Как настоящий сервер: по UDP не влезло — TC без ответов.
			m.Answer, m.Truncated = nil, true
		}
		return m
	})
	p := newProxy(up, nil, nil)

	// По TCP клиент получает всё (прокси сам повторил запрос по TCP).
	resp := p.handle(writer{remote: lanTCP}, query("direct.test", dns.TypeA, false))
	if len(resp.Answer) != 60 || resp.Truncated {
		t.Errorf("TCP: answers=%d tc=%v", len(resp.Answer), resp.Truncated)
	}
	// UDP-клиент без EDNS: ответ урезан до 512 байт с флагом TC.
	resp = p.handle(writer{remote: lanUDP}, query("direct.test", dns.TypeA, false))
	if !resp.Truncated || resp.Len() > dns.MinMsgSize {
		t.Errorf("UDP: tc=%v len=%d", resp.Truncated, resp.Len())
	}
	up.mu.Lock()
	nets := append([]string(nil), up.nets...)
	up.mu.Unlock()
	// TCP-клиент → TCP; UDP-клиент → UDP (TC) и повтор по TCP.
	if fmt.Sprint(nets) != "[tcp udp tcp]" {
		t.Errorf("запросы к upstream: %v, want [tcp udp tcp]", nets)
	}
}

func TestUpstreamDown(t *testing.T) {
	up := &upstream{addr: netip.MustParseAddrPort("127.0.0.1:1")}
	p := newProxy(up, nil, nil)
	if resp := p.handle(writer{remote: lanUDP}, query("direct.test", dns.TypeA, false)); resp.Rcode != dns.RcodeServerFailure {
		t.Errorf("rcode=%d, want SERVFAIL", resp.Rcode)
	}
}

func TestStartServeShutdown(t *testing.T) {
	up := startUpstream(t, answerA([]uint32{60}, "203.0.113.20"))
	sets := &fakeSets{}
	// Свободный порт для прокси.
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := netip.MustParseAddrPort(pc.LocalAddr().String())
	pc.Close()

	p := New(Options{
		Listen: []netip.AddrPort{addr},
		Rules:  Rules{Upstream: up.addr, VPN: matcher(struct{}{}, "vpn.test"), FilterAAAA: FilterAAAAVPN},
		Sets:   sets,
	})
	if err := p.Start(); err != nil {
		t.Fatal(err)
	}
	defer p.Shutdown()

	for _, network := range []string{"udp", "tcp"} {
		c := &dns.Client{Net: network, Timeout: 2 * time.Second}
		resp, _, err := c.Exchange(query("vpn.test", dns.TypeA, false), addr.String())
		if err != nil || len(resp.Answer) != 1 {
			t.Fatalf("%s: %v %v", network, resp, err)
		}
	}
	if len(sets.got) != 2 {
		t.Errorf("learned: %v", sets.got)
	}

	// Горячая замена правил: vpn.test больше не в списке.
	p.SetRules(Rules{Upstream: up.addr, FilterAAAA: FilterAAAANone})
	c := &dns.Client{Net: "udp", Timeout: 2 * time.Second}
	if _, _, err := c.Exchange(query("vpn.test", dns.TypeA, false), addr.String()); err != nil {
		t.Fatal(err)
	}
	if len(sets.got) != 2 {
		t.Error("после SetRules домен не должен попадать в set")
	}
}

type fakeZone map[string]netip.Addr

func (z fakeZone) Domain() string { return "lan" }
func (z fakeZone) LookupName(l string) (netip.Addr, bool) {
	a, ok := z[l]
	return a, ok
}
func (z fakeZone) LookupAddr(a netip.Addr) (string, bool) {
	for n, x := range z {
		if x == a {
			return n, true
		}
	}
	return "", false
}

func TestLocalZone(t *testing.T) {
	up := startUpstream(t, answerA([]uint32{60}, "203.0.113.10"))
	p := newProxy(up, nil, func(r *Rules) {
		r.Local = fakeZone{"laptop": netip.MustParseAddr("192.168.3.100")}
	})

	resp := p.handle(writer{remote: lanUDP}, query("Laptop.LAN", dns.TypeA, false))
	if resp.Rcode != dns.RcodeSuccess || len(resp.Answer) != 1 || resp.Answer[0].(*dns.A).A.String() != "192.168.3.100" || !resp.Authoritative {
		t.Fatalf("A laptop.lan: %v", resp)
	}
	if resp := p.handle(writer{remote: lanUDP}, query("laptop.lan", dns.TypeAAAA, false)); resp.Rcode != dns.RcodeSuccess || len(resp.Answer) != 0 {
		t.Errorf("AAAA laptop.lan: пустой NOERROR, got %v", resp)
	}
	if resp := p.handle(writer{remote: lanUDP}, query("nobody.lan", dns.TypeA, false)); resp.Rcode != dns.RcodeNameError {
		t.Errorf("nobody.lan: NXDOMAIN, got %d", resp.Rcode)
	}
	resp = p.handle(writer{remote: lanUDP}, query("100.3.168.192.in-addr.arpa", dns.TypePTR, false))
	if len(resp.Answer) != 1 || resp.Answer[0].(*dns.PTR).Ptr != "laptop.lan." {
		t.Errorf("PTR: %v", resp)
	}
	// PTR адреса без аренды — как раньше, bogus-priv.
	if resp := p.handle(writer{remote: lanUDP}, query("99.3.168.192.in-addr.arpa", dns.TypePTR, false)); resp.Rcode != dns.RcodeNameError {
		t.Errorf("PTR без аренды: %d", resp.Rcode)
	}
	if n := len(up.requests()); n != 0 {
		t.Errorf("локальная зона не должна уходить в upstream: %d запросов", n)
	}
	// Остальное — как обычно.
	p.handle(writer{remote: lanUDP}, query("direct.example", dns.TypeA, false))
	if n := len(up.requests()); n != 1 {
		t.Errorf("обычный домен должен уйти в upstream: %d", n)
	}
}
