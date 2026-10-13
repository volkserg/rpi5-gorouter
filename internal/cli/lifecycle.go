package cli

import (
	"context"
	"strings"

	"github.com/volkserg/rpi5-gorouter/internal/config"
	"github.com/volkserg/rpi5-gorouter/internal/lists"
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
		if err := services.StartStack(ctx, m, x.stackLogger()); err != nil {
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
		if err := services.StopStack(ctx, m); err != nil {
			x.errf("Ошибка остановки: %v", err)
			return 1
		}
		x.out("%srouter_service остановлен.%s", x.c.Red, x.c.NC)
		return 0
	})
}

func cmdRestart(x *ctx, a []string) int {
	if rc := cmdStop(x, a); rc != 0 {
		return rc
	}
	return cmdStart(x, a)
}

// logUnits — юниты, чьи журналы показывает logs.
var logUnits = []string{services.UnitRouterd, services.UnitGost, services.UnitDNSCrypt, services.UnitPihole}

func cmdLogs(x *ctx, _ []string) int {
	x.out("%sЛоги router_service:%s", x.c.Cyan, x.c.NC)
	ctx, cancel := context.WithTimeout(context.Background(), opTimeout)
	defer cancel()
	for i, u := range logUnits {
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
		sts, err := m.States(ctx, services.StatusUnits...)
		m.Close()
		if err != nil {
			x.out("  %s?%s ошибка запроса состояния: %v", x.c.Yellow, x.c.NC, err)
		}
		for _, st := range sts {
			x.unitLine(st)
		}
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
	x.out("")

	x.out("%sVPN:%s", x.c.Yellow, x.c.NC)
	x.out("  :%d  GOST           %s", config.RedirectPort, listen(true, false, config.RedirectPort))
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
	return 0
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
