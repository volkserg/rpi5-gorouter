// Package dhcp — DHCP-сервер routerd: пул адресов с арендами,
// «терпимый authoritative» режим, сохранение аренд в JSON, имена клиентов
// для локальной DNS-зоны (*.lan).
package dhcp

import (
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"time"
)

// State — состояние аренды.
type State string

const (
	StateOffered  State = "offered"  // адрес предложен (DHCPOFFER), ждём REQUEST
	StateBound    State = "bound"    // аренда выдана (DHCPACK)
	StateReleased State = "released" // клиент освободил адрес; привязка помнится
)

// Lease — аренда. После истечения запись остаётся: тот же клиент получит
// тот же адрес обратно, пока адрес не понадобится другому.
type Lease struct {
	IP       netip.Addr `json:"ip"`
	MAC      string     `json:"mac"`
	ClientID string     `json:"client_id,omitempty"` // hex опции 61
	Hostname string     `json:"hostname,omitempty"`  // как прислал клиент (опция 12)
	Name     string     `json:"name,omitempty"`      // уникальное имя в локальной зоне
	State    State      `json:"state"`
	Expires  time.Time  `json:"expires"`
}

// Active — аренда действует (предложена или выдана и не истекла).
func (l *Lease) Active(now time.Time) bool {
	return (l.State == StateBound || l.State == StateOffered) && l.Expires.After(now)
}

func (l *Lease) key() string { return clientKey(l.ClientID, l.MAC) }

// Client — кто просит адрес.
type Client struct {
	MAC      string
	ClientID string
	Hostname string
}

func (c Client) key() string { return clientKey(c.ClientID, c.MAC) }

func clientKey(id, mac string) string {
	if id != "" {
		return "id:" + id
	}
	return "mac:" + strings.ToLower(mac)
}

// Prober сообщает, какое устройство сейчас использует адрес (по таблице
// соседей ядра): RPi — шлюз, поэтому видит все живые устройства LAN.
type Prober interface {
	Owner(ip netip.Addr) (mac string, ok bool)
}

// PoolConfig — параметры пула.
type PoolConfig struct {
	Subnet    netip.Prefix
	Start     netip.Addr
	End       netip.Addr
	Reserved  []netip.Addr // адреса, которые нельзя выдавать (RPi, роутер)
	LeaseTime time.Duration
	OfferTime time.Duration // сколько держится предложенный адрес
}

// Ошибки решений пула.
var (
	ErrExhausted = errors.New("пул адресов исчерпан")
	errForeign   = errors.New("адрес не из подсети LAN")
	errOutside   = errors.New("адрес вне пула")
	errTaken     = errors.New("адрес занят другим клиентом")
	errConflict  = errors.New("адрес используется устройством вне DHCP")
)

const conflictHold = 10 * time.Minute

// conflict — адрес занят устройством вне DHCP (mac) или отклонён клиентом
// (DHCPDECLINE, mac пустой — блокируется для всех).
type conflict struct {
	until time.Time
	mac   string
}

// Pool — пул адресов и аренды. Безопасен для параллельного использования.
type Pool struct {
	mu        sync.Mutex
	cfg       PoolConfig
	byIP      map[netip.Addr]*Lease
	byClient  map[string]*Lease
	conflicts map[netip.Addr]conflict
	probe     Prober
	now       func() time.Time
	onChange  func([]Lease)
}

// NewPool создаёт пул с ранее сохранёнными арендами; аренды вне пула
// (например, после смены LAN_POOL_*) отбрасываются.
func NewPool(cfg PoolConfig, leases []Lease, probe Prober) *Pool {
	p := &Pool{
		byIP:      map[netip.Addr]*Lease{},
		byClient:  map[string]*Lease{},
		conflicts: map[netip.Addr]conflict{},
		probe:     probe,
		now:       time.Now,
	}
	p.cfg = cfg
	for i := range leases {
		l := leases[i]
		if p.inPool(l.IP) && l.State != StateOffered {
			p.byIP[l.IP] = &l
			p.byClient[l.key()] = &l
		}
	}
	return p
}

// OnChange задаёт функцию, вызываемую со снимком аренд после изменений
// (для сохранения на диск).
func (p *Pool) OnChange(f func([]Lease)) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.onChange = f
}

// Reconfigure меняет параметры пула (SIGHUP); аренды вне нового пула
// отбрасываются.
func (p *Pool) Reconfigure(cfg PoolConfig) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.cfg = cfg
	for ip, l := range p.byIP {
		if !p.inPool(ip) {
			p.forget(l)
		}
	}
	p.changed()
}

// Offer выбирает адрес для DHCPDISCOVER: прежний адрес клиента, затем
// запрошенный, затем первый никогда не выданный, затем давно истёкший.
func (p *Pool) Offer(c Client, requested netip.Addr) (netip.Addr, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	now := p.now()
	key := c.key()

	candidates := make([]netip.Addr, 0, 2)
	if l := p.byClient[key]; l != nil {
		candidates = append(candidates, l.IP)
	}
	if requested.IsValid() {
		candidates = append(candidates, requested)
	}
	for _, ip := range candidates {
		if p.inPool(ip) && p.usable(ip, c, now) == nil {
			p.assign(ip, c, StateOffered, p.cfg.OfferTime, now)
			return ip, nil
		}
	}

	var oldest netip.Addr
	var oldestExp time.Time
	for ip := p.cfg.Start; ip.IsValid() && ip.Compare(p.cfg.End) <= 0; ip = ip.Next() {
		if !p.inPool(ip) || p.usable(ip, c, now) != nil {
			continue
		}
		l := p.byIP[ip]
		if l == nil {
			p.assign(ip, c, StateOffered, p.cfg.OfferTime, now)
			return ip, nil
		}
		if !oldest.IsValid() || l.Expires.Before(oldestExp) {
			oldest, oldestExp = ip, l.Expires
		}
	}
	if oldest.IsValid() {
		p.assign(oldest, c, StateOffered, p.cfg.OfferTime, now)
		return oldest, nil
	}
	return netip.Addr{}, ErrExhausted
}

// Request решает DHCPREQUEST в «терпимом authoritative» режиме: адрес не из
// LAN, вне пула или занятый — NAK (клиент сразу уйдёт в DISCOVER); свободный
// адрес из пула — ACK, даже если аренды нет (восстановление после потери базы).
func (p *Pool) Request(c Client, ip netip.Addr) (*Lease, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	now := p.now()
	switch {
	case !ip.IsValid() || !p.cfg.Subnet.Contains(ip):
		return nil, errForeign
	case !p.inPool(ip):
		return nil, errOutside
	}
	if err := p.usable(ip, c, now); err != nil {
		return nil, err
	}
	l := p.assign(ip, c, StateBound, p.cfg.LeaseTime, now)
	cp := *l
	p.changed()
	return &cp, nil
}

// CancelOffer — клиент выбрал другой DHCP-сервер.
func (p *Pool) CancelOffer(c Client) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if l := p.byClient[c.key()]; l != nil && l.State == StateOffered {
		p.forget(l)
	}
}

// Release — клиент освобождает адрес (DHCPRELEASE); привязка помнится.
func (p *Pool) Release(c Client, ip netip.Addr) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if l := p.byIP[ip]; l != nil && l.key() == c.key() {
		l.State, l.Expires = StateReleased, p.now()
		p.changed()
	}
}

// Decline — клиент обнаружил, что адрес занят (DHCPDECLINE).
func (p *Pool) Decline(c Client, ip netip.Addr) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if l := p.byIP[ip]; l != nil && l.key() == c.key() {
		p.forget(l)
	}
	p.conflicts[ip] = conflict{until: p.now().Add(conflictHold)}
	p.changed()
}

// Leases — снимок аренд, по адресу.
func (p *Pool) Leases() []Lease {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.snapshot()
}

// --- внутреннее (под p.mu) ---

func (p *Pool) inPool(ip netip.Addr) bool {
	return ip.IsValid() && ip.Compare(p.cfg.Start) >= 0 && ip.Compare(p.cfg.End) <= 0 &&
		!slices.Contains(p.cfg.Reserved, ip)
}

// usable — можно ли отдать адрес клиенту c.
func (p *Pool) usable(ip netip.Addr, c Client, now time.Time) error {
	if cf, ok := p.conflicts[ip]; ok {
		switch {
		case !cf.until.After(now):
			delete(p.conflicts, ip)
		case cf.mac == "" || !strings.EqualFold(cf.mac, c.MAC):
			return errConflict
		}
	}
	if l := p.byIP[ip]; l != nil && l.key() != c.key() && l.Active(now) {
		return errTaken
	}
	if p.probe != nil {
		if mac, ok := p.probe.Owner(ip); ok && !strings.EqualFold(mac, c.MAC) {
			p.conflicts[ip] = conflict{until: now.Add(conflictHold), mac: mac}
			return errConflict
		}
	}
	return nil
}

// assign привязывает адрес к клиенту, снимая прежние привязки обоих.
func (p *Pool) assign(ip netip.Addr, c Client, st State, d time.Duration, now time.Time) *Lease {
	key := c.key()
	if old := p.byClient[key]; old != nil && old.IP != ip {
		p.forget(old)
	}
	if old := p.byIP[ip]; old != nil && old.key() != key {
		p.forget(old)
	}
	l := p.byIP[ip]
	if l == nil {
		l = &Lease{IP: ip}
		p.byIP[ip] = l
	}
	l.MAC, l.ClientID, l.State, l.Expires = strings.ToLower(c.MAC), c.ClientID, st, now.Add(d)
	if c.Hostname != "" || st == StateBound {
		l.Hostname = c.Hostname
		l.Name = p.uniqueName(sanitizeName(c.Hostname), key, now)
	}
	p.byClient[key] = l
	return l
}

func (p *Pool) forget(l *Lease) {
	delete(p.byIP, l.IP)
	if p.byClient[l.key()] == l {
		delete(p.byClient, l.key())
	}
}

// uniqueName — имя в локальной зоне: base, base-2, base-3… Имя закреплено за
// клиентом, пока его запись свежая (истекла не раньше, чем срок аренды назад):
// освобождение или краткое отключение не отдаёт имя другому устройству.
func (p *Pool) uniqueName(base, key string, now time.Time) string {
	if base == "" {
		return ""
	}
	fresh := now.Add(-p.cfg.LeaseTime)
	taken := func(n string) bool {
		for _, l := range p.byIP {
			if l.Name == n && l.key() != key && l.Expires.After(fresh) {
				return true
			}
		}
		return false
	}
	name := base
	for i := 2; taken(name); i++ {
		suffix := fmt.Sprintf("-%d", i)
		name = strings.TrimRight(base[:min(len(base), 63-len(suffix))], "-") + suffix
	}
	return name
}

func (p *Pool) snapshot() []Lease {
	out := make([]Lease, 0, len(p.byIP))
	for _, l := range p.byIP {
		out = append(out, *l)
	}
	slices.SortFunc(out, func(a, b Lease) int { return a.IP.Compare(b.IP) })
	return out
}

func (p *Pool) changed() {
	if p.onChange != nil {
		p.onChange(p.snapshot())
	}
}

// sanitizeName превращает hostname клиента в метку DNS: нижний регистр,
// [a-z0-9-], до 63 символов; домен после первой точки отбрасывается.
func sanitizeName(h string) string {
	h, _, _ = strings.Cut(strings.ToLower(strings.TrimSpace(h)), ".")
	var b strings.Builder
	dash := false
	for _, r := range h {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
			dash = false
		default:
			if !dash && b.Len() > 0 {
				b.WriteByte('-')
				dash = true
			}
		}
	}
	s := strings.Trim(b.String(), "-")
	if len(s) > 63 {
		s = strings.TrimRight(s[:63], "-")
	}
	return s
}
