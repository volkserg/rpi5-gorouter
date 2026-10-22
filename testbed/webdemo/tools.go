package main

import (
	"context"
	"errors"
	"math/rand/v2"
	"net/netip"
	"strings"
	"time"

	"github.com/volkserg/rpi5-gorouter/internal/access"
	"github.com/volkserg/rpi5-gorouter/internal/api"
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
	return res, nil
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

func (f *fake) Devices() []api.DeviceRow {
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
