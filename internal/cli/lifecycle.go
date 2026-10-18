package cli

import (
	"context"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/volkserg/rpi5-gorouter/internal/config"
	"github.com/volkserg/rpi5-gorouter/internal/dhcp"
	"github.com/volkserg/rpi5-gorouter/internal/lists"
	"github.com/volkserg/rpi5-gorouter/internal/localclient"
	"github.com/volkserg/rpi5-gorouter/internal/pihole"
	"github.com/volkserg/rpi5-gorouter/internal/services"
	"github.com/volkserg/rpi5-gorouter/internal/sysinfo"
)

func (x *ctx) stackLogger() services.Logger {
	return func(warn bool, format string, a ...any) {
		if warn {
			x.notef(format, a...)
		} else {
			x.okf(format, a...)
		}
	}
}

func cmdStart(x *ctx, _ []string) int {
	if !x.requireRoot() {
		return 1
	}
	x.okf("Запуск router_service...")
	return x.withManager(func(ctx context.Context, m services.Manager) int {
		if err := services.StartStack(ctx, m, x.gostUnit(), x.stackLogger()); err != nil {
			x.errf("Ошибка запуска: %v", err)
			return 1
		}
		x.okf("router_service запущен.")
		return 0
	})
}

func cmdStop(x *ctx, _ []string) int {
	if !x.requireRoot() {
		return 1
	}
	x.out("%sОстановка router_service...%s", x.c.Red, x.c.NC)
	return x.withManager(func(ctx context.Context, m services.Manager) int {
		if err := services.StopStack(ctx, m, x.gostUnit()); err != nil {
			x.errf("Ошибка остановки: %v", err)
			return 1
		}
		x.out("%srouter_service остановлен.%s", x.c.Red, x.c.NC)
		return 0
	})
}

// cmdRestart запускает стек и после неудачной остановки: иначе routerd мог
// бы остаться выключенным (нет DHCP и DNS в LAN).
func cmdRestart(x *ctx, a []string) int {
	rcStop := cmdStop(x, a)
	if rcStart := cmdStart(x, a); rcStart != 0 {
		return rcStart
	}
	return rcStop
}

// dnscryptSocket сверяет адрес dnscrypt-proxy.socket с DNSCRYPT_ADDR —
// конфиг dnscrypt-proxy ведёт пользователь, routerd его только проверяет.
func (x *ctx) dnscryptSocket(ctx context.Context, cfg *config.Config) {
	m, err := x.Services(ctx)
	if err != nil {
		return
	}
	defer m.Close()
	want := cfg.DNSCryptAddr.String()
	addrs, err := m.SocketListen(ctx, services.UnitDNSCryptSocket)
	switch {
	case err != nil:
		x.out("  dnscrypt-proxy.socket: %s?%s %v", x.c.Yellow, x.c.NC, err)
	case slices.Contains(addrs, want):
		x.out("  dnscrypt-proxy.socket: %s✓%s %s", x.c.Green, x.c.NC, want)
	default:
		x.out("  dnscrypt-proxy.socket: %s✗%s слушает %v, ожидается %s (DNSCRYPT_ADDR)", x.c.Red, x.c.NC, addrs, want)
	}
}

// piholeConfig показывает, в порядке ли ключи цепочки в pihole.toml.
func (x *ctx) piholeConfig(cfg *config.Config) {
	if !cfg.PiholeManage {
		return
	}
	if _, err := os.Stat(cfg.PiholeTOML); err != nil {
		return
	}
	want := pihole.Desired{
		Port:      int(cfg.DNSUpstream.Port()),
		Upstreams: []string{fmt.Sprintf("%s#%d", cfg.DNSCryptAddr.Addr(), cfg.DNSCryptAddr.Port())},
		ECS:       cfg.DNSECS,
		LAN:       cfg.LANSubnet,
	}
	if cfg.DHCPEnabled {
		want.RevServer = pihole.RevServerEntry(cfg.LANSubnet, netip.MustParseAddrPort("127.0.0.1:53"), cfg.LocalDomain)
	}
	drifts, err := pihole.Check(cfg.PiholeTOML, want)
	switch {
	case err != nil:
		x.out("  pihole.toml: %s?%s %v", x.c.Yellow, x.c.NC, err)
	case len(drifts) == 0:
		x.out("  pihole.toml: %s✓%s ключи цепочки в порядке", x.c.Green, x.c.NC)
	default:
		x.out("  pihole.toml: %s✗%s расхождения (routerd исправит при reload):", x.c.Red, x.c.NC)
		for _, d := range drifts {
			x.out("    %s", d)
		}
	}
}

// logUnits — юниты, чьи журналы показывает logs.
func (x *ctx) logUnits() []string {
	return []string{services.UnitRouterd, x.gostUnit(), services.UnitDNSCrypt, services.UnitPihole}
}

// gostUnit — юнит клиента туннеля из router.conf (VPN_SERVICE). Если конфиг
// не читается — значение по умолчанию: stop, status и logs работают всегда.
func (x *ctx) gostUnit() string {
	if cfg, _, err := config.Load(x.routerConf()); err == nil {
		return cfg.VPNService
	}
	return services.DefaultUnitGost
}

func cmdLogs(x *ctx, _ []string) int {
	x.out("%sЛоги router_service:%s", x.c.Cyan, x.c.NC)
	ctx, cancel := context.WithTimeout(context.Background(), opTimeout)
	defer cancel()
	for i, u := range x.logUnits() {
		if i > 0 {
			x.out("")
		}
		x.out("--- systemd (%s) ---", strings.TrimSuffix(u, ".service"))
		if err := x.Journal(ctx, x.Stdout, u, 30); err != nil {
			x.out("Нет логов (%v)", err)
		}
	}
	return 0
}

func cmdStatus(x *ctx, _ []string) int {
	x.header("Состояние router_service")

	x.out("%sSystemd-сервисы:%s", x.c.Yellow, x.c.NC)
	ctx, cancel := context.WithTimeout(context.Background(), opTimeout)
	defer cancel()
	if m, err := x.Services(ctx); err != nil {
		x.out("  %s?%s systemd недоступен: %v", x.c.Yellow, x.c.NC, err)
	} else {
		sts, err := m.States(ctx, services.StatusUnits(x.gostUnit())...)
		if err != nil {
			x.out("  %s?%s ошибка запроса состояния: %v", x.c.Yellow, x.c.NC, err)
		}
		for _, st := range sts {
			x.unitLine(st)
			if st.Name == services.UnitRouterd && st.Running() {
				if text, err := m.StatusText(ctx, st.Name); err == nil && text != "" {
					x.out("      %s", text)
				}
			}
		}
		m.Close()
	}
	x.out("")

	ports, perr := sysinfo.ListeningPorts(x.ProcRoot)
	listen := func(tcp, udp bool, port uint16) string {
		if perr != nil {
			return x.c.Yellow + "?" + x.c.NC + " N/A"
		}
		if (tcp && ports.TCP[port]) || (udp && ports.UDP[port]) {
			return x.c.Green + "●" + x.c.NC + " слушается"
		}
		return x.c.Red + "○" + x.c.NC + " не слушается"
	}

	x.out("%sСеть:%s", x.c.Yellow, x.c.NC)
	fwd, err := sysinfo.Sysctl(x.ProcRoot, "net.ipv4.ip_forward")
	if err != nil {
		fwd = "N/A"
	}
	x.out("  IP forwarding: %s", fwd)
	x.out("")

	x.out("%sDNS:%s", x.c.Yellow, x.c.NC)
	x.out("  Цепочка: Клиент → routerd (:53) → Pi-hole (:5353) → dnscrypt-proxy (:5053) → DoH")
	x.out("  :53    routerd        %s", listen(true, true, 53))
	x.out("  :5353  Pi-hole        %s", listen(true, true, 5353))
	x.out("  :5053  dnscrypt-proxy %s", listen(true, true, 5053))
	if cfg, _, err := config.Load(x.routerConf()); err == nil {
		x.dnscryptSocket(ctx, cfg)
		x.piholeConfig(cfg)
	}
	x.out("")

	x.out("%sVPN:%s", x.c.Yellow, x.c.NC)
	port := uint16(config.RedirectPort)
	if cfg, _, err := config.Load(x.routerConf()); err == nil {
		port = cfg.VPNPort
	}
	x.out("  :%-5d GOST           %s", port, listen(true, false, port))
	if l, exists, err := lists.ReadVPN(x.vpnFile()); err == nil && exists {
		var doms, nets int
		for _, e := range l.Entries() {
			if e.Kind == lists.KindDomain {
				doms++
			} else {
				nets++
			}
		}
		x.out("  В списке: доменов %d, IP/подсетей %d", doms, nets)
	} else {
		x.out("  Список %s не найден", x.vpnFile())
	}
	x.out("")

	x.out("%sDHCP:%s", x.c.Yellow, x.c.NC)
	x.out("  :67    routerd        %s", listen(false, true, 67))
	x.leases()

	if cfg, _, err := config.Load(x.routerConf()); err == nil && len(cfg.LocalClients) > 0 {
		x.out("")
		x.localClients(ctx, cfg)
	}
	return 0
}

// localClients печатает состояние локальных сервисов: юнит их сети и
// namespace. Сами сервисы — юниты пользователя, их состояние здесь не видно.
func (x *ctx) localClients(ctx context.Context, cfg *config.Config) {
	x.out("%sЛокальные сервисы (LOCAL_CLIENTS):%s", x.c.Yellow, x.c.NC)
	var units []string
	for _, l := range cfg.LocalClients {
		units = append(units, services.LocalUnit(l.Name))
	}
	var sts []services.State
	if m, err := x.Services(ctx); err == nil {
		sts, _ = m.States(ctx, units...)
		m.Close()
	}
	for i, l := range cfg.LocalClients {
		if i < len(sts) {
			x.unitLine(sts[i])
		} else {
			x.out("  %s?%s %s — состояние неизвестно", x.c.Yellow, x.c.NC, strings.TrimSuffix(units[i], ".service"))
		}
		netns := "нет"
		if _, err := os.Stat(localclient.NetnsPath(l.Name)); err == nil {
			netns = "есть"
		}
		x.out("      %s/%d, шлюз %s (%s), %s: %s", l.ClientIP(), l.Net.Bits(), l.HostIP(), l.Iface(), localclient.NetnsPath(l.Name), netns)
	}
}

// leases печатает действующие аренды DHCP.
func (x *ctx) leases() {
	path := filepath.Join(x.StateDir, dhcp.LeaseFile)
	all, err := dhcp.LoadLeases(path)
	if err != nil {
		x.out("  Аренды: ошибка чтения %s: %v", path, err)
		return
	}
	now := time.Now()
	var active []dhcp.Lease
	for _, l := range all {
		if l.State == dhcp.StateBound && l.Expires.After(now) {
			active = append(active, l)
		}
	}
	x.out("  Активные аренды: %d", len(active))
	for _, l := range active {
		name := l.Name
		if name == "" {
			name = "-"
		}
		x.out("    %-15s %-17s %-20s до %s", l.IP, l.MAC, name, l.Expires.Local().Format("02.01 15:04"))
	}
}

func (x *ctx) unitLine(st services.State) {
	name := strings.TrimSuffix(st.Name, ".service")
	switch {
	case !st.Installed():
		x.out("  %s?%s %s — не установлен", x.c.Yellow, x.c.NC, name)
	case st.Running():
		x.out("  %s●%s %s — запущен (%s)", x.c.Green, x.c.NC, name, st.Sub)
	case st.Active == "failed":
		x.out("  %s✗%s %s — ошибка", x.c.Red, x.c.NC, name)
	case st.Active == "activating" || st.Active == "reloading":
		x.out("  %s?%s %s — %s", x.c.Yellow, x.c.NC, name, st.Active)
	default:
		x.out("  %s○%s %s — остановлен", x.c.Red, x.c.NC, name)
	}
}
