//go:build linux

// Package daemon — долгоживущий процесс routerd (routerd run): применяет
// sysctl, правила nftables и policy routing, обслуживает DNS на :53,
// перечитывает конфиги по SIGHUP и убирает за собой правила при остановке.
package daemon

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"slices"
	"strconv"
	"syscall"
	"time"

	sddaemon "github.com/coreos/go-systemd/v22/daemon"
	"github.com/google/nftables"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"github.com/volkserg/rpi5-gorouter/internal/config"
	"github.com/volkserg/rpi5-gorouter/internal/dnsproxy"
	"github.com/volkserg/rpi5-gorouter/internal/domain"
	"github.com/volkserg/rpi5-gorouter/internal/firewall"
	"github.com/volkserg/rpi5-gorouter/internal/lists"
	"github.com/volkserg/rpi5-gorouter/internal/routing"
	"github.com/volkserg/rpi5-gorouter/internal/sysctl"
	"github.com/volkserg/rpi5-gorouter/internal/sysinfo"
)

// healthInterval — как часто проверяется доступность туннеля.
const healthInterval = 2 * time.Second

// Options — параметры демона.
type Options struct {
	ConfigDir string
	ProcRoot  string
	Log       *slog.Logger
}

type daemon struct {
	Options
	nft *nftables.Conn
	nl  *netlink.Handle
	dyn *firewall.Dynamic
	dns *dnsproxy.Server
	// listen — адреса, на которых сейчас слушает dns.
	listen []netip.AddrPort

	// Состояние после последнего успешного apply.
	cfg     *config.Config
	spec    firewall.Spec
	summary string
	healthy bool
	tunUp   bool
}

// Run работает до SIGTERM/SIGINT. Ошибка первого применения конфигурации
// фатальна (systemd увидит отказ запуска); ошибки перезагрузки — нет:
// остаются прежние правила, а причина видна в status и журнале.
func Run(ctx context.Context, o Options) error {
	nft, err := nftables.New()
	if err != nil {
		return fmt.Errorf("netlink nftables: %w", err)
	}
	nl, err := netlink.NewHandle()
	if err != nil {
		return fmt.Errorf("netlink: %w", err)
	}
	defer nl.Close()
	dyn, err := firewall.NewDynamic(24*time.Hour, o.Log)
	if err != nil {
		return fmt.Errorf("netlink nftables: %w", err)
	}
	d := &daemon{Options: o, nft: nft, nl: nl, dyn: dyn}

	sigs := make(chan os.Signal, 4)
	signal.Notify(sigs, syscall.SIGHUP, syscall.SIGTERM, syscall.SIGINT)
	defer signal.Stop(sigs)

	if err := d.apply(); err != nil {
		d.cleanup()
		return err
	}
	d.Log.Info("routerd запущен", "состояние", d.status())
	notify("READY=1", "STATUS="+d.status())

	ticker := time.NewTicker(healthInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			d.cleanup()
			return nil
		case <-ticker.C:
			d.tick()
		case sig := <-sigs:
			if sig != syscall.SIGHUP {
				d.Log.Info("остановка по сигналу", "сигнал", sig.String())
				notify("STOPPING=1")
				d.cleanup()
				return nil
			}
			notify("RELOADING=1", "MONOTONIC_USEC="+monotonicUsec())
			if err := d.apply(); err != nil {
				d.Log.Error("перезагрузка не удалась, действуют прежние правила", "ошибка", err)
				notify("READY=1", "STATUS=ошибка перезагрузки: "+err.Error())
				continue
			}
			d.Log.Info("конфигурация перезагружена", "состояние", d.status())
			notify("READY=1", "STATUS="+d.status())
		}
	}
}

// apply читает конфиги и приводит систему к ним.
func (d *daemon) apply() error {
	cfg, warns, err := config.Load(config.Path(d.ConfigDir))
	for _, w := range warns {
		d.Log.Warn(string(w))
	}
	if err != nil {
		return err
	}
	vpn, _, err := lists.ReadVPN(filepath.Join(d.ConfigDir, lists.VPNFileName))
	if err != nil {
		return err
	}
	for _, ln := range vpn.Invalid() {
		d.Log.Warn("запись пропущена", "файл", lists.VPNFileName, "строка", ln.Num, "ошибка", ln.Err)
	}
	overrides, bad, err := lists.ReadOverrides(filepath.Join(d.ConfigDir, lists.OverrideFileName))
	if err != nil {
		return err
	}
	for _, b := range bad {
		d.Log.Warn("правило пропущено", "файл", lists.OverrideFileName, "строка", b.Line, "ошибка", b.Err)
	}

	changed, err := sysctl.Apply(d.ProcRoot, sysctl.Router(cfg.Iface))
	if len(changed) > 0 {
		d.Log.Info("sysctl изменены", "параметры", changed)
	}
	if err != nil {
		// Не фатально: например, в контейнере /proc/sys только для чтения.
		d.Log.Warn("sysctl", "ошибка", err)
	}

	entries := vpn.Entries()
	var static []netip.Prefix
	var domains int
	for _, e := range entries {
		if e.Kind == lists.KindNet {
			static = append(static, e.Prefix)
		} else {
			domains++
		}
	}
	healthy := d.tunnelHealthy(cfg)
	spec := firewall.Spec{
		Iface:          cfg.Iface,
		LAN:            cfg.LANSubnet,
		RedirectPort:   cfg.VPNPort,
		QUICReject:     cfg.QUICReject,
		DynamicTimeout: cfg.VPNDynamicTimeout,
		Static:         static,
		Mode:           firewall.Mode(cfg.VPNMode),
		Tun:            cfg.VPNTun,
		Bypass:         cfg.VPNFailoverOpen && !healthy,
	}
	recreated, err := firewall.Apply(d.nft, spec)
	if err != nil {
		return err
	}
	if recreated {
		d.Log.Warn("таблица nftables пересоздана: адреса, узнанные из DNS, сброшены")
	}
	tunUp, err := d.applyRouting(spec)
	if err != nil {
		return err
	}

	if err := d.syncDNS(cfg, entries, overrides, recreated); err != nil {
		return err
	}
	d.cfg, d.spec, d.healthy, d.tunUp = cfg, spec, healthy, tunUp
	d.summary = fmt.Sprintf("доменов %d, IP/подсетей %d, DNS-override %d, режим %s",
		domains, len(static), len(overrides), cfg.VPNMode)
	return nil
}

// applyRouting применяет policy routing; в режиме route для поднятого
// интерфейса туннеля включает нестрогий rp_filter (ответы приходят через tun,
// а обратный маршрут в основной таблице ведёт в LAN).
func (d *daemon) applyRouting(spec firewall.Spec) (tunUp bool, err error) {
	tunUp, err = routing.Apply(d.nl, routing.Policy{Mode: spec.Mode, Tun: spec.Tun, Bypass: spec.Bypass})
	if err != nil {
		return false, err
	}
	if tunUp {
		key := "net.ipv4.conf." + spec.Tun + ".rp_filter"
		if _, err := sysctl.Apply(d.ProcRoot, []sysctl.Setting{{Key: key, Value: "2"}}); err != nil {
			d.Log.Warn("sysctl", "ошибка", err)
		}
	}
	return tunUp, nil
}

// tunnelHealthy — признак доступности туннеля: для redirect/tproxy слушает
// ли локальный порт GOST, для route — поднят ли интерфейс туннеля. Проверяется
// только локальная часть; связь с удалённым узлом routerd не проверяет.
func (d *daemon) tunnelHealthy(cfg *config.Config) bool {
	if cfg.VPNMode == config.ModeRoute {
		_, ok := routing.TunLink(d.nl, cfg.VPNTun)
		return ok
	}
	ports, err := sysinfo.ListeningPorts(d.ProcRoot)
	return err == nil && ports.TCP[cfg.VPNPort]
}

// tick реагирует на изменение состояния туннеля: снимает или возвращает
// перехват (VPN_FAILOVER=open) и в режиме route переставляет маршрут в tun.
func (d *daemon) tick() {
	if d.cfg == nil {
		return
	}
	healthy := d.tunnelHealthy(d.cfg)
	bypass := d.cfg.VPNFailoverOpen && !healthy
	_, tunUp := routing.TunLink(d.nl, d.spec.Tun)
	tunChanged := d.spec.Mode == firewall.ModeRoute && tunUp != d.tunUp
	if healthy == d.healthy && bypass == d.spec.Bypass && !tunChanged {
		return
	}

	spec := d.spec
	spec.Bypass = bypass
	if bypass != d.spec.Bypass {
		if _, err := firewall.Apply(d.nft, spec); err != nil {
			d.Log.Error("переключение перехвата", "ошибка", err)
			return
		}
	}
	up, err := d.applyRouting(spec)
	if err != nil {
		d.Log.Error("маршрутизация", "ошибка", err)
		return
	}
	if healthy != d.healthy {
		if healthy {
			d.Log.Info("туннель доступен")
		} else {
			d.Log.Warn("туннель недоступен")
		}
	}
	if bypass != d.spec.Bypass {
		if bypass {
			d.Log.Warn("перехват снят: трафик к адресам из списков идёт напрямую (VPN_FAILOVER=open)")
		} else {
			d.Log.Info("перехват восстановлен")
		}
	}
	d.spec, d.healthy, d.tunUp = spec, healthy, up
	notify("STATUS=" + d.status())
}

// status — текст для StatusText юнита и журнала.
func (d *daemon) status() string {
	tunnel := "доступен"
	if !d.healthy {
		tunnel = "недоступен"
	}
	s := "работает: " + d.summary + ", туннель " + tunnel
	if d.spec.Bypass {
		s += ", перехват снят (VPN_FAILOVER=open)"
	}
	return s
}

// syncDNS приводит DNS-прокси к конфигу: правила меняются на лету,
// слушатели пересоздаются, только если сменились адреса (RPI5_IP).
func (d *daemon) syncDNS(cfg *config.Config, entries []lists.Entry, overrides []lists.Override, recreated bool) error {
	d.dyn.SetFloor(cfg.VPNDynamicTimeout)
	if recreated {
		d.dyn.Reset()
	}
	vpn := domain.NewMatcher[struct{}]()
	for _, e := range entries {
		if e.Kind == lists.KindDomain {
			vpn.Set(e.Domain, struct{}{})
		}
	}
	ovr := domain.NewMatcher[[]netip.AddrPort]()
	for _, o := range overrides {
		ups, _ := ovr.Get(o.Domain)
		ovr.Set(o.Domain, append(ups, o.Upstream))
	}
	rules := dnsproxy.Rules{
		Upstream:   cfg.DNSUpstream,
		Overrides:  ovr,
		VPN:        vpn,
		FilterAAAA: cfg.FilterAAAA,
		ECS:        cfg.DNSECS,
	}

	// Как dnsmasq с interface=eth0: адрес LAN и loopback (на нём резолвит GOST).
	listen := []netip.AddrPort{
		netip.AddrPortFrom(cfg.RPi5IP, 53),
		netip.AddrPortFrom(netip.AddrFrom4([4]byte{127, 0, 0, 1}), 53),
	}
	if d.dns != nil && slices.Equal(listen, d.listen) {
		d.dns.SetRules(rules)
		return nil
	}
	if d.dns != nil {
		d.dns.Shutdown()
		d.dns = nil
	}
	srv := dnsproxy.New(dnsproxy.Options{Listen: listen, Rules: rules, Sets: d.dyn, Log: d.Log})
	if err := srv.Start(); err != nil {
		return err
	}
	d.dns, d.listen = srv, listen
	return nil
}

// cleanup останавливает DNS и убирает правила routerd (как stop в bash-версии).
func (d *daemon) cleanup() {
	if d.dns != nil {
		d.dns.Shutdown()
	}
	if err := firewall.Remove(d.nft); err != nil {
		d.Log.Error("удаление таблицы nftables", "ошибка", err)
	}
	if err := routing.Remove(d.nl); err != nil {
		d.Log.Error("удаление policy routing", "ошибка", err)
	}
}

func notify(state ...string) {
	var b bytes.Buffer
	for _, s := range state {
		b.WriteString(s)
		b.WriteByte('\n')
	}
	_, _ = sddaemon.SdNotify(false, b.String())
}

// monotonicUsec — CLOCK_MONOTONIC в микросекундах: systemd требует его
// вместе с RELOADING=1 для Type=notify-reload.
func monotonicUsec() string {
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts); err != nil {
		return "0"
	}
	return strconv.FormatInt(ts.Nano()/1000, 10)
}
