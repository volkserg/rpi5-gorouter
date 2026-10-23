package main

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"net/netip"
	"strings"
	"time"

	"github.com/volkserg/rpi5-gorouter/internal/access"
	"github.com/volkserg/rpi5-gorouter/internal/api"
	"github.com/volkserg/rpi5-gorouter/internal/ipinfo"
	"github.com/volkserg/rpi5-gorouter/internal/iplabels"
	"github.com/volkserg/rpi5-gorouter/internal/probe"
)

// Проверки, устройства и журнал демо — правдоподобные ответы без сети.

func (f *fake) Services(context.Context) ([]api.Unit, error) {
	up := f.Status().TunnelUp
	tunnel := api.Unit{Unit: "gost-run.service", Label: "клиент туннеля", Installed: true, Active: "active", Sub: "running"}
	if !up {
		tunnel.Active, tunnel.Sub = "activating", "auto-restart"
	}
	return []api.Unit{
		{Unit: "routerd.service", Label: "routerd", Installed: true, Active: "active", Sub: "running"},
		tunnel,
		{Unit: "pihole-FTL.service", Label: "Pi-hole", Installed: true, Active: "active", Sub: "running"},
		{Unit: "dnscrypt-proxy.service", Label: "dnscrypt-proxy", Installed: true, Active: "active", Sub: "running"},
		{Unit: "routerd-web.service", Label: "веб-интерфейс", Installed: true, Active: "active", Sub: "running"},
		{Unit: "routerd-local@app.service", Label: "сеть сервиса app", Installed: true, Active: "active", Sub: "exited"},
	}, nil
}

func ok(connect, total int64, detail string) probe.Path {
	return probe.Path{OK: true, Connect: connect, Total: total, Detail: detail}
}

func (f *fake) Check(_ context.Context, req api.CheckRequest) (api.CheckResult, error) {
	t := strings.ToLower(strings.TrimSpace(req.Target))
	if i := strings.Index(t, "://"); i >= 0 {
		t = strings.SplitN(t[i+3:], "/", 2)[0]
	}
	if t == "" || !strings.Contains(t, ".") {
		return api.CheckResult{}, errors.New("ожидается домен или IPv4-адрес")
	}
	time.Sleep(time.Duration(400+rand.IntN(600)) * time.Millisecond)
	res := api.CheckResult{Target: t, Port: req.Port, Route: "direct", Suggest: access.Suggest(t)}
	ip := netip.MustParseAddr("198.51.100.30")
	for _, s := range demoSites {
		if s.name == t {
			ip = s.ip
		}
	}
	if a, err := netip.ParseAddr(t); err == nil {
		ip = a
	} else {
		res.Name = t
	}
	res.Addr, res.Addrs = ip.String(), []string{ip.String()}
	if e := vpnChecker(f.vpnEntries)(t); e != "" {
		res.InList, res.ListEntry, res.Route = true, e, "tunnel"
	}
	tls := "TLS 1.3, HTTP 200"
	if req.Port != 443 {
		tls = "HTTP 200"
	}
	res.Tunnel = ok(int64(60+rand.IntN(40)), int64(180+rand.IntN(120)), tls)
	switch {
	case strings.Contains(t, "storage") || strings.Contains(t, "partner"):
		res.Direct = probe.Path{Kind: "timeout", Error: "соединение: нет ответа (таймаут)", Total: 6000}
	case strings.Contains(t, "geo"):
		res.Direct = probe.Path{Kind: "http", Status: 403, Error: "сервер отказал в доступе (HTTP 403)",
			Detail: "TLS 1.3, HTTP 403", Connect: 18, Total: 74}
	case strings.Contains(t, "bot"):
		res.Direct = probe.Path{Kind: "http", Status: 403, Error: "сервер отказал в доступе (HTTP 403)",
			Detail: "TLS 1.3, HTTP 403", Connect: 18, Total: 74}
		res.Tunnel = probe.Path{Kind: "http", Status: 403, Error: "сервер отказал в доступе (HTTP 403)",
			Detail: "TLS 1.3, HTTP 403", Connect: 70, Total: 230}
	case strings.Contains(t, "blocked"):
		res.Direct = probe.Path{Kind: "reset", Error: "TLS: соединение сброшено", Connect: 21, Total: 45}
	default:
		res.Direct = ok(int64(15+rand.IntN(20)), int64(60+rand.IntN(60)), tls)
	}
	if !f.Status().TunnelUp {
		res.Tunnel = probe.Path{Kind: "other", Error: "туннель недоступен"}
	}
	res.Owner = f.owner(ip, res.Name)
	var cert *probe.Cert
	if req.Port == 443 {
		cert = demoCert(res.Name, ip)
		if res.Direct.Kind != "timeout" {
			res.Direct.Cert = cert
		}
		if res.Tunnel.OK || res.Tunnel.Kind == "http" {
			res.Tunnel.Cert = cert
		}
	}
	if res.Name == "" {
		var names []string
		var subj, ptr, as string
		if cert != nil {
			names, subj = cert.Names, cert.Subject
		}
		if res.Owner != nil {
			ptr, as = res.Owner.PTR, res.Owner.ASName
		}
		if name, src := iplabels.Guess(names, subj, ptr, as); name != "" {
			if l, err := f.labels.Auto(ip, name, src); err == nil {
				res.Label = &l
			}
		}
	}
	return res, nil
}

func (f *fake) SetIPLabel(ip netip.Addr, name string) error { return f.labels.Set(ip, name) }
func (f *fake) ResetIPLabels() (int, error)                 { return f.labels.Reset() }

// demoCert — сертификат сервера: на имя ресурса, по IP — на имя из TLS
// или общий сертификат оператора.
func demoCert(name string, ip netip.Addr) *probe.Cert {
	if name == "" {
		for _, s := range demoSites {
			if s.ip == ip {
				name = s.sni
			}
		}
	}
	if name == "" {
		return &probe.Cert{Subject: "*.edge.example-hosting.example", Org: "Example Hosting B.V.",
			Names: []string{"*.edge.example-hosting.example", "edge.example-hosting.example"}, Issuer: "Example Trust CA"}
	}
	parent := name
	if i := strings.Index(name, "."); i > 0 && strings.Count(name, ".") > 1 {
		parent = name[i+1:]
	}
	return &probe.Cert{Subject: "*." + parent, Names: []string{"*." + parent, parent}, Issuer: "Example Trust CA"}
}

// demoNets — операторы сетей демо (номера AS из диапазона для документации).
var demoNets = map[[3]byte]struct {
	asn  uint32
	name string
	cc   string
}{
	{203, 0, 113}:  {64500, "EXAMPLE-HOSTING", "NL"},
	{198, 51, 100}: {64501, "EXAMPLE-CDN", "US"},
	{192, 0, 2}:    {64502, "EXAMPLE-STORAGE", "DE"},
}

func (f *fake) owner(ip netip.Addr, name string) *ipinfo.Info {
	var info ipinfo.Info
	for _, n := range f.tracker.NamesOf(ip) {
		if n != name {
			info.Names = append(info.Names, n)
		}
	}
	b := ip.As16()
	if n, ok := demoNets[[3]byte{b[12], b[13], b[14]}]; ok && ip.Is4() {
		info.ASN, info.ASName, info.Country = n.asn, n.name, n.cc
		info.Prefix = netip.PrefixFrom(ip, 24).Masked().String()
		info.PTR = fmt.Sprintf("host-%d.%s.example", b[15], strings.ToLower(n.name))
	}
	if info.Empty() {
		return nil
	}
	return &info
}

func (f *fake) TunnelCheck(_ context.Context, run bool) api.TunnelCheck {
	f.mu.Lock()
	defer f.mu.Unlock()
	if run {
		time.Sleep(700 * time.Millisecond)
		f.tunnel = api.TunnelCheck{Enabled: true, URL: "https://api.ipify.org", CheckedAt: time.Now(),
			DirectIP: "198.51.100.2", Direct: ok(int64(20+rand.IntN(20)), int64(90+rand.IntN(40)), "200 OK")}
		if f.phase%3 == 0 {
			f.tunnel.TunnelIP = "203.0.113.77"
			f.tunnel.Tunnel = ok(int64(70+rand.IntN(40)), int64(240+rand.IntN(120)), "200 OK")
		} else {
			f.tunnel.Tunnel = probe.Path{Kind: "other", Error: "туннель недоступен"}
		}
	}
	t := f.tunnel
	t.Enabled, t.URL = true, "https://api.ipify.org"
	return t
}

func (f *fake) SetDeviceName(key, name string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.names == nil {
		f.names = map[string]string{}
	}
	if name = strings.TrimSpace(name); name == "" {
		delete(f.names, key)
	} else {
		f.names[key] = name
	}
	return nil
}

func (f *fake) Devices() []api.DeviceRow {
	rows := f.devices()
	f.mu.Lock()
	defer f.mu.Unlock()
	for i := range rows {
		if n := f.names[rows[i].Key]; n != "" {
			rows[i].LeaseName, rows[i].Name = rows[i].Name, n
		}
	}
	return rows
}

func (f *fake) devices() []api.DeviceRow {
	stats := map[string]access.DeviceInfo{}
	for _, d := range f.tracker.Query(access.Query{Since: 24 * time.Hour, Limit: 1}).Devices {
		stats[d.Key] = d
	}
	out := []api.DeviceRow{{Key: "local:app", Name: "app (сервис RPi)", IP: "10.99.0.2", Kind: "local", Active: true}}
	for _, d := range demoDevices {
		r := api.DeviceRow{Key: "mac:" + d.mac, Name: d.name, Hostname: d.name, IP: d.ip.String(), MAC: d.mac,
			Kind: "lease", Active: true, Expires: time.Now().Add(17 * time.Hour)}
		if st, ok := stats[r.Key]; ok {
			r.Connections, r.Problems, r.Last = st.Connections, st.Problems, st.Last
		}
		out = append(out, r)
	}
	out = append(out, api.DeviceRow{Key: "mac:02:00:00:00:00:20", Name: "printer", IP: "192.168.3.130",
		MAC: "02:00:00:00:00:20", Kind: "lease", Expires: time.Now().Add(-5 * time.Hour)})
	return out
}

var demoLog = []string{
	`level=INFO msg="routerd запущен" состояние="работает: доменов 5, IP/подсетей 3, DNS-override 3, режим tproxy, туннель доступен"`,
	`level=INFO msg="учёт обращений запущен" история=168h0m0s`,
	`level=INFO msg="изменение из веб-интерфейса" пользователь=demo изменение="добавлено в список VPN: example.com"`,
	`level=INFO msg="конфигурация перезагружена" состояние="работает: доменов 6, IP/подсетей 3, DNS-override 3, режим tproxy, туннель доступен"`,
	`level=INFO msg="список применён к недавним DNS-ответам" "имён добавлено"=2 "адресов убрано"=0`,
	`level=WARN msg="туннель недоступен"`,
	`level=INFO msg="туннель доступен"`,
	`level=WARN msg="запись пропущена" файл=vpn_domains.txt строка=12 ошибка="\"bad entry\": недопустимые символы"`,
}

func (f *fake) Journal(_ context.Context, unit, cursor string, lines int) (api.Journal, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	now := time.Now()
	// Курсор — номер последней выданной записи; каждые несколько секунд — новая.
	total := 20 + int(now.Sub(f.started.Add(26*time.Hour))/(4*time.Second))
	from := max(0, total-lines)
	if n, err := parseInt(cursor); err == nil {
		from = n
	}
	j := api.Journal{Unit: "routerd.service", Entries: []api.JournalEntry{}, Cursor: itoa(total)}
	for i := from; i < total; i++ {
		msg := demoLog[i%len(demoLog)]
		prio := 6
		if strings.HasPrefix(msg, "level=WARN") {
			prio = 4
		}
		j.Entries = append(j.Entries, api.JournalEntry{Time: now.Add(-time.Duration(total-i) * 4 * time.Second).UnixMilli(), Priority: prio, Message: msg})
	}
	return j, nil
}
