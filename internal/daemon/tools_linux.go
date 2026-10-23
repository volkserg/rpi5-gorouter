//go:build linux

package daemon

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/miekg/dns"
	"golang.org/x/sys/unix"

	"github.com/volkserg/rpi5-gorouter/internal/access"
	"github.com/volkserg/rpi5-gorouter/internal/api"
	"github.com/volkserg/rpi5-gorouter/internal/domain"
	"github.com/volkserg/rpi5-gorouter/internal/firewall"
	"github.com/volkserg/rpi5-gorouter/internal/probe"
	"github.com/volkserg/rpi5-gorouter/internal/services"
)

// tunnelCheckMin — не чаще: повторный запрос раньше вернёт прошлый результат.
const tunnelCheckMin = 5 * time.Second

type tunnelChecks struct {
	mu   sync.Mutex
	last api.TunnelCheck
}

// probeDial — соединение самого routerd: напрямую или (tunnel) с меткой
// firewall.ProbeMark, по которой правила routerd отправляют его в туннель.
func probeDial(tunnel bool) probe.Dial {
	return func(ctx context.Context, ap netip.AddrPort) (net.Conn, error) {
		var d net.Dialer
		if tunnel {
			d.Control = func(_, _ string, c syscall.RawConn) error {
				var serr error
				if err := c.Control(func(fd uintptr) {
					serr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_MARK, firewall.ProbeMark)
				}); err != nil {
					return err
				}
				return serr
			}
		}
		return d.DialContext(ctx, "tcp4", ap.String())
	}
}

// tunnelUsable — туннель доступен и перехват не снят.
func (d *daemon) tunnelUsable() bool {
	st := d.Status()
	return st.TunnelUp && !st.Bypass
}

var errNoTunnel = probe.Path{Kind: "other", Error: "туннель недоступен"}

// Check — доступен ли ресурс напрямую и через туннель (api.Tools).
func (d *daemon) Check(ctx context.Context, req api.CheckRequest) (api.CheckResult, error) {
	v := d.view.Load()
	if v == nil {
		return api.CheckResult{}, errors.New("routerd ещё не готов")
	}
	target, port := strings.ToLower(req.Target), req.Port
	// Можно вставить адрес из браузера: https://host:port/путь.
	if strings.Contains(target, "://") {
		u, err := url.Parse(target)
		if err != nil || u.Hostname() == "" {
			return api.CheckResult{}, fmt.Errorf("%q: не разобран адрес", req.Target)
		}
		target = u.Hostname()
		if p, err := strconv.ParseUint(u.Port(), 10, 16); err == nil && p > 0 {
			port = uint16(p)
		} else if u.Scheme == "http" {
			port = 80
		}
	}
	target = strings.TrimSuffix(target, ".")
	res := api.CheckResult{Target: target, Port: port, Addrs: []string{}}
	var addrs []netip.Addr
	if a, err := netip.ParseAddr(target); err == nil && a.Is4() {
		addrs = []netip.Addr{a}
		res.Suggest = []string{a.String()}
	} else {
		if err := domain.Validate(target); err != nil || !strings.Contains(target, ".") {
			return res, fmt.Errorf("%q: ожидается домен или IPv4-адрес", req.Target)
		}
		res.Name = target
		res.Suggest = access.Suggest(target)
		var err error
		if addrs, err = d.resolve(ctx, target); err != nil {
			return res, err
		}
	}
	for _, a := range addrs {
		res.Addrs = append(res.Addrs, a.String())
	}
	ip := addrs[0]
	ap := netip.AddrPortFrom(ip, port)
	res.Addr = ip.String()
	res.ListEntry, res.InList = d.inList(res.Name, ip)
	res.Route = d.routeOf(access.ProtoTCP, ip, port).String()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() { defer wg.Done(); res.Direct = probe.Resource(ctx, probeDial(false), res.Name, ap) }()
	if d.tunnelUsable() {
		res.Tunnel = probe.Resource(ctx, probeDial(true), res.Name, ap)
	} else {
		res.Tunnel = errNoTunnel
	}
	wg.Wait()
	return res, nil
}

// resolve — A-записи через DNS routerd (с его правилами: override, список).
func (d *daemon) resolve(ctx context.Context, name string) ([]netip.Addr, error) {
	c := &dns.Client{Timeout: 4 * time.Second}
	q := new(dns.Msg)
	q.SetQuestion(dns.Fqdn(name), dns.TypeA)
	resp, _, err := c.ExchangeContext(ctx, q, "127.0.0.1:53")
	if err != nil {
		return nil, fmt.Errorf("%s: DNS не ответил: %v", name, err)
	}
	if resp.Rcode != dns.RcodeSuccess {
		return nil, fmt.Errorf("%s: DNS ответил %s", name, dns.RcodeToString[resp.Rcode])
	}
	var out []netip.Addr
	for _, rr := range resp.Answer {
		if a, ok := rr.(*dns.A); ok {
			if ip, ok := netip.AddrFromSlice(a.A.To4()); ok {
				out = append(out, ip)
			}
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("%s: нет адресов IPv4", name)
	}
	return out, nil
}

// TunnelCheck — внешний IP RPi и выхода туннеля (api.Tools).
func (d *daemon) TunnelCheck(ctx context.Context, run bool) api.TunnelCheck {
	v := d.view.Load()
	d.tunCheck.mu.Lock()
	defer d.tunCheck.mu.Unlock()
	if v == nil || v.cfg.TunnelCheckURL == "" {
		return api.TunnelCheck{}
	}
	last := d.tunCheck.last
	if !run || time.Since(last.CheckedAt) < tunnelCheckMin {
		last.Enabled, last.URL = true, v.cfg.TunnelCheckURL
		return last
	}
	res := api.TunnelCheck{Enabled: true, URL: v.cfg.TunnelCheckURL, CheckedAt: time.Now()}
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		res.DirectIP, res.Direct = probe.ExitIP(ctx, probeDial(false), v.cfg.TunnelCheckURL)
	}()
	if d.tunnelUsable() {
		res.TunnelIP, res.Tunnel = probe.ExitIP(ctx, probeDial(true), v.cfg.TunnelCheckURL)
	} else {
		res.Tunnel = errNoTunnel
	}
	wg.Wait()
	d.tunCheck.last = res
	return res
}

// Services — состояние юнитов стека (api.Tools).
func (d *daemon) Services(ctx context.Context) ([]api.Unit, error) {
	v := d.view.Load()
	if v == nil || d.Options.Services == nil {
		return nil, errors.New("routerd ещё не готов")
	}
	type unit struct{ name, label string }
	units := []unit{
		{services.UnitRouterd, "routerd"},
		{v.cfg.VPNService, "клиент туннеля"},
		{services.UnitPihole, "Pi-hole"},
		{services.UnitDNSCrypt, "dnscrypt-proxy"},
	}
	if v.cfg.WebUI {
		units = append(units, unit{services.UnitWeb, "веб-интерфейс"})
	}
	for _, l := range v.cfg.LocalClients {
		units = append(units, unit{services.LocalUnit(l.Name), "сеть сервиса " + l.Name})
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	m, err := d.Options.Services(ctx)
	if err != nil {
		return nil, err
	}
	defer m.Close()
	names := make([]string, len(units))
	for i, u := range units {
		names[i] = u.name
	}
	sts, err := m.States(ctx, names...)
	if err != nil {
		return nil, err
	}
	out := make([]api.Unit, 0, len(units))
	for i, u := range units {
		r := api.Unit{Unit: u.name, Label: u.label}
		if i < len(sts) {
			r.Installed, r.Active, r.Sub = sts[i].Installed(), sts[i].Active, sts[i].Sub
		}
		out = append(out, r)
	}
	return out, nil
}

// Devices — аренды DHCP, локальные сервисы и адреса из обращений (api.Tools).
func (d *daemon) Devices() []api.DeviceRow {
	v := d.view.Load()
	if v == nil {
		return []api.DeviceRow{}
	}
	stats := map[string]access.DeviceInfo{}
	if t := d.tracker.Load(); t != nil {
		for _, di := range t.Query(access.Query{Since: 24 * time.Hour, Limit: 1}).Devices {
			stats[di.Key] = di
		}
	}
	out := []api.DeviceRow{}
	seen := map[string]bool{}
	add := func(r api.DeviceRow) {
		if st, ok := stats[r.Key]; ok {
			r.Connections, r.Problems, r.Last = st.Connections, st.Problems, st.Last
		}
		if n := d.names.Get(r.Key); n != "" {
			r.LeaseName, r.Name = r.Name, n
		}
		seen[r.Key] = true
		out = append(out, r)
	}
	for _, l := range v.locals {
		add(api.DeviceRow{Key: "local:" + l.Name, Name: l.Name + " (сервис RPi)", IP: l.ClientIP().String(), Kind: "local", Active: true})
	}
	if v.pool != nil {
		now := time.Now()
		for _, l := range v.pool.Leases() {
			if l.MAC == "" {
				continue
			}
			mac := strings.ToLower(l.MAC)
			name := l.Name
			if name == "" {
				name = l.Hostname
			}
			if name == "" {
				name = l.IP.String()
			}
			add(api.DeviceRow{Key: "mac:" + mac, Name: name, Hostname: l.Hostname, IP: l.IP.String(), MAC: mac,
				Kind: "lease", Active: l.Active(now), Expires: l.Expires})
		}
	}
	for k, st := range stats {
		if !seen[k] {
			add(api.DeviceRow{Key: k, Name: st.Name, IP: st.IP, MAC: st.MAC, Kind: "seen", Active: true})
		}
	}
	return out
}

// SetDeviceName — имя устройства из веб-интерфейса (api.Tools).
func (d *daemon) SetDeviceName(key, name string) error {
	if d.names == nil {
		return errors.New("имена устройств недоступны")
	}
	if err := d.names.Set(key, name); err != nil {
		return err
	}
	d.Log.Info("имя устройства", "устройство", key, "имя", strings.TrimSpace(name))
	return nil
}

// piholeLog — журнал FTL: Pi-hole пишет его в файл, в journald почти пусто.
const piholeLog = "/var/log/pihole/FTL.log"

// journalUnits — какие журналы можно читать из веб-интерфейса.
func (d *daemon) journalUnit(id string) (string, bool) {
	v := d.view.Load()
	switch id {
	case "", "routerd":
		return services.UnitRouterd, true
	case "web":
		return services.UnitWeb, true
	case "tunnel":
		if v != nil {
			return v.cfg.VPNService, true
		}
		return services.DefaultUnitGost, true
	case "pihole":
		return services.UnitPihole, true
	case "dnscrypt":
		return services.UnitDNSCrypt, true
	}
	return "", false
}

// Journal — записи журнала юнита через journalctl (согласованное
// исключение: своего читателя журнала без cgo нет) (api.Tools).
func (d *daemon) Journal(ctx context.Context, id, cursor string, lines int) (api.Journal, error) {
	unit, ok := d.journalUnit(id)
	if !ok {
		return api.Journal{}, fmt.Errorf("журнал %q не поддерживается", id)
	}
	if id == "pihole" {
		if j, err := api.TailLog(piholeLog, cursor, lines, time.Local); err == nil {
			return j, nil
		}
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	// Все поля записи и --all: --output-fields и поля длиннее 4 КБ (null без
	// --all) в разных версиях systemd ведут себя по-разному — текст терялся.
	args := []string{"-u", unit, "-o", "json", "--all", "--no-pager", "-n", strconv.Itoa(lines)}
	if cursor != "" {
		args = append(args, "--after-cursor="+cursor)
	}
	out, err := exec.CommandContext(ctx, "journalctl", args...).Output()
	if err != nil {
		return api.Journal{}, fmt.Errorf("journalctl: %w", err)
	}
	return api.ParseJournal(unit, cursor, out), nil
}
