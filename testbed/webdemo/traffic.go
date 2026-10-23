package main

import (
	"math/rand/v2"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/volkserg/rpi5-gorouter/internal/access"
)

// Синтетический трафик демо: устройства LAN обращаются к ресурсам, часть
// ресурсов напрямую не отвечает (таймауты), часть идёт через туннель. Исходы
// определяет настоящий access.Tracker по снимкам «conntrack».

type demoDevice struct {
	ip   netip.Addr
	name string
	mac  string
}

type demoSite struct {
	name   string
	ip     netip.Addr
	port   uint16
	udp    bool
	tunnel bool // в списке VPN
	// fail: "" — отвечает; timeout — напрямую не отвечает; refused — RST;
	// nodata — через туннель без данных.
	fail   string
	weight int
	// sni — имя в TLS при обращении по IP (name пусто: устройство не
	// спрашивало DNS routerd).
	sni string
}

var (
	demoDevices = []demoDevice{
		{netip.MustParseAddr("192.168.3.100"), "laptop", "02:00:00:00:00:10"},
		{netip.MustParseAddr("192.168.3.101"), "phone", "02:00:00:00:00:11"},
		{netip.MustParseAddr("192.168.3.102"), "tablet", "02:00:00:00:00:12"},
		{netip.MustParseAddr("192.168.3.120"), "tv", "02:00:00:00:00:13"},
	}
	demoSites = []demoSite{
		{name: "intranet.example.com", ip: netip.MustParseAddr("10.20.1.10"), port: 443, tunnel: true, weight: 6},
		{name: "git.example.com", ip: netip.MustParseAddr("10.20.1.20"), port: 443, tunnel: true, weight: 4},
		{name: "wiki.example.org", ip: netip.MustParseAddr("203.0.113.40"), port: 443, tunnel: true, weight: 2},
		{name: "build.example.org", ip: netip.MustParseAddr("203.0.113.41"), port: 443, tunnel: true, fail: "nodata", weight: 1},
		{name: "news.example.net", ip: netip.MustParseAddr("198.51.100.30"), port: 443, weight: 8},
		{name: "cdn.example.net", ip: netip.MustParseAddr("198.51.100.31"), port: 443, weight: 10},
		{name: "video.example.net", ip: netip.MustParseAddr("198.51.100.32"), port: 443, udp: true, weight: 5},
		{name: "files.storage.example.com", ip: netip.MustParseAddr("192.0.2.50"), port: 443, fail: "timeout", weight: 3},
		{name: "api.partner.example", ip: netip.MustParseAddr("192.0.2.60"), port: 8443, fail: "timeout", weight: 2},
		// Ещё ресурсы без ответа напрямую: кандидатов больше пяти — видно сворачивание.
		{name: "docs.vendor.example", ip: netip.MustParseAddr("192.0.2.61"), port: 443, fail: "timeout", weight: 2},
		{name: "cdn.vendor.example", ip: netip.MustParseAddr("192.0.2.62"), port: 443, fail: "timeout", weight: 2},
		{name: "status.service.example", ip: netip.MustParseAddr("192.0.2.63"), port: 443, fail: "timeout", weight: 1},
		{name: "login.service.example", ip: netip.MustParseAddr("192.0.2.64"), port: 443, fail: "timeout", weight: 1},
		{name: "media.service.example", ip: netip.MustParseAddr("192.0.2.65"), port: 443, fail: "timeout", weight: 1},
		{name: "mail.example.net", ip: netip.MustParseAddr("198.51.100.33"), port: 993, weight: 3},
		{name: "", ip: netip.MustParseAddr("198.51.100.90"), port: 8080, fail: "refused", weight: 1},
		{name: "time.example.net", ip: netip.MustParseAddr("198.51.100.35"), port: 123, udp: true, weight: 2},
		// Обращения по IP без DNS: приложение со своим резолвером или зашитыми адресами.
		{ip: netip.MustParseAddr("198.51.100.91"), port: 443, sni: "push.example.net", weight: 4},
		{ip: netip.MustParseAddr("203.0.113.77"), port: 443, sni: "api.messenger.example", weight: 3},
		{ip: netip.MustParseAddr("192.0.2.71"), port: 5222, fail: "timeout", weight: 2},
	}
)

type demoFlow struct {
	f    access.Flow
	site demoSite
	born time.Time
	life time.Duration
}

type traffic struct {
	mu     sync.Mutex
	t      *access.Tracker
	vpnHas func(string) string
	flows  []*demoFlow
	port   uint16
}

func newTracker(vpnHas func(string) string) *access.Tracker {
	byIP := map[netip.Addr]demoDevice{}
	for _, d := range demoDevices {
		byIP[d.ip] = d
	}
	sites := map[netip.Addr]demoSite{}
	for _, s := range demoSites {
		sites[s.ip] = s
	}
	return access.New(access.Options{
		Retention: 7 * 24 * time.Hour,
		Watch:     func(src, _ netip.Addr) bool { _, ok := byIP[src]; return ok },
		Device: func(a netip.Addr) access.Device {
			d := byIP[a]
			return access.Device{Key: "mac:" + d.mac, Name: d.name, IP: a.String(), MAC: d.mac}
		},
		Route: func(_ uint8, dst netip.Addr, _ uint16) access.Route {
			if s := sites[dst]; s.tunnel || (s.name != "" && vpnHas(s.name) != "") {
				return access.Tunnel
			}
			return access.Direct
		},
		InList: func(name string, ip netip.Addr) (string, bool) {
			if name != "" {
				e := vpnHas(name)
				return e, e != ""
			}
			return "", sites[ip].tunnel
		},
	})
}

// run — каждые 2 с новые соединения и снимок «таблицы».
func (tr *traffic) run() {
	tr.t.Observe(nil, true)
	total := 0
	for _, s := range demoSites {
		total += s.weight
	}
	for range time.Tick(2 * time.Second) {
		tr.step(total)
	}
}

func (tr *traffic) step(total int) {
	tr.mu.Lock()
	defer tr.mu.Unlock()
	now := time.Now()
	for i := 0; i < 1+rand.IntN(4); i++ {
		n := rand.IntN(total)
		var s demoSite
		for _, c := range demoSites {
			if n -= c.weight; n < 0 {
				s = c
				break
			}
		}
		// Добавленный в список ресурс начинает отвечать — через туннель.
		if s.fail == "timeout" && tr.vpnHas(s.name) != "" {
			s.fail = ""
		}
		d := demoDevices[rand.IntN(len(demoDevices))]
		if s.name != "" {
			tr.t.Answer(d.ip, s.name, []netip.Addr{s.ip}, 5*time.Minute)
		}
		if s.sni != "" {
			tr.t.SNI(d.ip, s.ip, s.sni)
		}
		tr.port++
		f := access.Flow{Proto: access.ProtoTCP, Src: d.ip, Dst: s.ip, SPort: 40000 + tr.port%20000, DPort: s.port,
			OrigPkts: 1, OrigBytes: 60}
		if s.udp {
			f.Proto = access.ProtoUDP
		}
		tr.flows = append(tr.flows, &demoFlow{f: f, site: s, born: now, life: time.Duration(3+rand.IntN(20)) * time.Second})
	}
	snap := make([]access.Flow, 0, len(tr.flows))
	keep := tr.flows[:0]
	for _, df := range tr.flows {
		age := now.Sub(df.born)
		f := &df.f
		switch df.site.fail {
		case "timeout":
			f.TCPState = 1 // SYN_SENT, только SYN
			if age > 20*time.Second {
				continue
			}
		case "refused":
			// RST в ответ на SYN: запись удаляется сразу — только событие.
			f.TCPState, f.ReplyPkts, f.ReplyBytes = 8, 1, 40
			tr.t.Gone(*f)
			continue
		case "nodata":
			f.TCPState, f.ReplyPkts, f.ReplyBytes = 3, 2, 120
			f.OrigPkts, f.OrigBytes = 3, 700
			if age > df.life {
				f.TCPState = 7
			}
			if age > df.life+4*time.Second {
				continue
			}
		default:
			f.TCPState = 3
			f.OrigPkts, f.OrigBytes = 3, 700
			f.ReplyPkts = uint64(2 + age/time.Second)
			f.ReplyBytes = f.ReplyPkts * 1200
			if age > df.life {
				f.TCPState = 7
			}
			if age > df.life+4*time.Second {
				continue
			}
		}
		snap = append(snap, *f)
		keep = append(keep, df)
	}
	tr.flows = keep
	tr.t.Observe(snap, true)
}

// vpnChecker — запись файла списка демо, покрывающая имя (сам домен или
// родительский), пусто — нет.
func vpnChecker(read func() []string) func(string) string {
	return func(name string) string {
		for _, e := range read() {
			if name == e || strings.HasSuffix(name, "."+e) {
				return e
			}
		}
		return ""
	}
}
