//go:build linux

package daemon

import (
	"context"
	"net/netip"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/vishvananda/netlink"

	"github.com/volkserg/rpi5-gorouter/internal/access"
	"github.com/volkserg/rpi5-gorouter/internal/config"
	"github.com/volkserg/rpi5-gorouter/internal/dhcp"
	"github.com/volkserg/rpi5-gorouter/internal/domain"
	"github.com/volkserg/rpi5-gorouter/internal/firewall"
	"github.com/volkserg/rpi5-gorouter/internal/sysctl"
)

const (
	// accessPoll — интервал опроса conntrack (записи живут дольше, см. access).
	accessPoll = 3 * time.Second
	// accessDir — каталог истории обращений в StateDir.
	accessDir = "history"
)

// netView — то, что учёт обращений читает из других горутин: обновляется
// целиком в основном цикле (updateSnapshot).
type netView struct {
	lan    netip.Prefix
	rpi    netip.Addr
	locals []config.LocalClient
	mode   firewall.Mode
	bypass bool
	static []netip.Prefix
	vpn    *domain.Matcher[struct{}]
	pool   *dhcp.Pool
	// cfg — router.conf последнего применения (не меняется после публикации).
	cfg *config.Config
}

// syncAccess включает или выключает учёт обращений по router.conf.
func (d *daemon) syncAccess(cfg *config.Config) {
	if !cfg.AccessTracking() {
		d.stopAccess()
		return
	}
	// Счётчики пакетов и байтов в conntrack: без них не отличить UDP без
	// ответа и соединение через туннель без данных.
	if _, err := sysctl.Apply(d.ProcRoot, []sysctl.Setting{{Key: "net.netfilter.nf_conntrack_acct", Value: "1"}}); err != nil {
		d.Log.Warn("учёт обращений: счётчики conntrack не включены", "ошибка", err)
	}
	if t := d.tracker.Load(); t != nil {
		t.SetRetention(cfg.AccessHistory)
		return
	}
	h, err := netlink.NewHandle()
	if err != nil {
		d.Log.Error("учёт обращений не запущен", "ошибка", err)
		return
	}
	t := access.New(access.Options{
		Dir:       filepath.Join(d.StateDir, accessDir),
		Retention: cfg.AccessHistory,
		Watch:     d.watchFlow,
		Device:    d.deviceOf,
		Route:     d.routeOf,
		InList:    d.inList,
		Log:       d.Log,
	})
	ctx, cancel := context.WithCancel(context.Background())
	if err := access.ListenDestroy(ctx, t.Gone, func(err error) {
		d.Log.Warn("учёт обращений: события conntrack", "ошибка", err)
	}); err != nil {
		// Без событий учёт работает по опросу, но не видит соединений
		// короче интервала опроса (например, отказов).
		d.Log.Warn("учёт обращений: события conntrack недоступны", "ошибка", err)
	}
	done := make(chan struct{})
	d.accessStop = func() { cancel(); <-done }
	d.tracker.Store(t)
	go func() {
		defer close(done)
		defer h.Close()
		poll := time.NewTicker(accessPoll)
		defer poll.Stop()
		minute := time.NewTicker(time.Minute)
		defer minute.Stop()
		var failing bool
		for {
			select {
			case <-ctx.Done():
				t.Close()
				return
			case <-minute.C:
				t.Tick()
			case <-poll.C:
				flows, acct, err := access.Snapshot(h)
				if err != nil {
					if !failing {
						d.Log.Warn("учёт обращений: таблица conntrack не прочитана", "ошибка", err)
					}
					failing = true
					continue
				}
				failing = false
				t.Observe(flows, acct)
			}
		}
	}()
	d.Log.Info("учёт обращений запущен", "история", cfg.AccessHistory.String())
}

func (d *daemon) stopAccess() {
	if d.accessStop != nil {
		d.accessStop()
		d.accessStop = nil
		d.tracker.Store(nil)
		d.Log.Info("учёт обращений остановлен")
	}
}

// watchFlow — соединение устройства LAN (или локального сервиса) с внешним адресом.
func (d *daemon) watchFlow(src, dst netip.Addr) bool {
	v := d.view.Load()
	if v == nil || !dst.IsGlobalUnicast() || dst == v.rpi || v.lan.Contains(dst) {
		return false
	}
	for _, l := range v.locals {
		if l.Net.Contains(dst) {
			return false
		}
		if src == l.ClientIP() {
			return true
		}
	}
	return v.lan.Contains(src) && src != v.rpi
}

// deviceOf — устройство по адресу: локальный сервис, аренда DHCP (ключ —
// MAC, переживает смену адреса) или просто адрес.
func (d *daemon) deviceOf(a netip.Addr) access.Device {
	v := d.view.Load()
	if v != nil {
		for _, l := range v.locals {
			if l.ClientIP() == a {
				return access.Device{Key: "local:" + l.Name, Name: l.Name + " (сервис RPi)", IP: a.String()}
			}
		}
		if v.pool != nil {
			for _, l := range v.pool.Leases() {
				if l.IP != a || l.MAC == "" {
					continue
				}
				name := l.Name
				if name == "" {
					name = l.Hostname
				}
				if name == "" {
					name = a.String()
				}
				return access.Device{Key: "mac:" + strings.ToLower(l.MAC), Name: name, IP: a.String(), MAC: strings.ToLower(l.MAC)}
			}
		}
	}
	return access.Device{Key: "ip:" + a.String(), Name: a.String(), IP: a.String()}
}

// inVPN — адрес сейчас в vpn_static или vpn_dynamic.
func (d *daemon) inVPN(v *netView, a netip.Addr) bool {
	return slices.ContainsFunc(v.static, func(p netip.Prefix) bool { return p.Contains(a) }) || d.dyn.Has(a)
}

// routeOf — пойдёт ли соединение через туннель (как правила nftables режима).
func (d *daemon) routeOf(proto uint8, dst netip.Addr, _ uint16) access.Route {
	v := d.view.Load()
	if v == nil || v.bypass || !d.inVPN(v, dst) {
		return access.Direct
	}
	switch {
	case v.mode == firewall.ModeRoute,
		proto == access.ProtoTCP,
		proto == access.ProtoUDP && v.mode == firewall.ModeTProxy:
		return access.Tunnel
	}
	return access.Direct
}

// inList — ресурс в списке VPN и запись, которая его покрывает: домен из
// списка над именем, статическая подсеть с адресом; для ресурса без имени
// адрес в vpn_dynamic — в списке, но запись неизвестна.
func (d *daemon) inList(name string, ip netip.Addr) (string, bool) {
	v := d.view.Load()
	if v == nil {
		return "", false
	}
	if name != "" && v.vpn != nil {
		if _, dom, ok := v.vpn.Lookup(name); ok {
			return dom, true
		}
	}
	if !ip.IsValid() {
		return "", false
	}
	for _, p := range v.static {
		if p.Contains(ip) {
			if p.Bits() == 32 {
				return p.Addr().String(), true
			}
			return p.String(), true
		}
	}
	return "", name == "" && d.dyn.Has(ip)
}
