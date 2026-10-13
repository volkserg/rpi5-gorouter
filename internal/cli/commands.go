package cli

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/volkserg/rpi5-gorouter/internal/config"
	"github.com/volkserg/rpi5-gorouter/internal/lists"
)

func (x *ctx) header(title string) {
	x.out("%s========================================%s", x.c.Cyan, x.c.NC)
	x.out("%s  %s%s", x.c.Cyan, title, x.c.NC)
	x.out("%s========================================%s", x.c.Cyan, x.c.NC)
	x.out("")
}

func cmdInfo(x *ctx, _ []string) int {
	cfg, ok := x.loadConfig()
	if !ok {
		return 1
	}
	x.header("Конфигурация router_service")

	dns := make([]string, len(cfg.DNS))
	for i, a := range cfg.DNS {
		dns[i] = a.String()
	}
	x.out("%sТекущая конфигурация (%s):%s", x.c.Yellow, x.routerConf(), x.c.NC)
	x.out("  Файл конфигов:      %s", x.ConfigDir)
	x.out("  Интерфейс LAN:      %s", cfg.Iface)
	x.out("  Подключение NM:     %s", cfg.NMConn)
	x.out("  IP RPi5 (шлюз/DNS): %s", cfg.RPi5IP)
	x.out("  IP роутера:         %s", cfg.RouterIP)
	x.out("  Подсеть LAN:        %s", cfg.LANSubnet)
	x.out("  Маска / broadcast:  %s / %s", cfg.Netmask(), cfg.Broadcast())
	dhcpState := "выключен (DHCP_ENABLED=no)"
	if cfg.DHCPEnabled {
		dhcpState = fmt.Sprintf("аренда %s, домен %s", shortDuration(cfg.DHCPLeaseTime), cfg.LocalDomain)
	}
	x.out("  Пул DHCP:           %s - %s, %s", cfg.PoolStart, cfg.PoolEnd, dhcpState)
	x.out("  Upstream DNS:       %s", strings.Join(dns, ", "))
	x.out("  DNS-upstream:       %s (Pi-hole), ECS: %s", cfg.DNSUpstream, yesNo(cfg.DNSECS))
	x.out("  Фильтр AAAA:        %s", cfg.FilterAAAA)
	failover := "closed"
	if cfg.VPNFailoverOpen {
		failover = "open"
	}
	x.out("  Туннель:            режим %s, порт %d, tun %s, VPN_FAILOVER=%s", cfg.VPNMode, cfg.VPNPort, cfg.VPNTun, failover)
	x.out("  QUIC reject:        %s", yesNo(cfg.QUICReject))
	x.out("  vpn_dynamic:        таймаут %s", shortDuration(cfg.VPNDynamicTimeout))
	x.out("")

	x.out("%sСписки:%s", x.c.Yellow, x.c.NC)
	if l, exists, err := lists.ReadVPN(x.vpnFile()); err != nil {
		x.out("  %s%s%s — ошибка чтения: %v", x.c.Cyan, lists.VPNFileName, x.c.NC, err)
	} else if !exists {
		x.out("  %s%s%s — файл не найден", x.c.Cyan, lists.VPNFileName, x.c.NC)
	} else {
		var doms, nets int
		for _, e := range l.Entries() {
			if e.Kind == lists.KindDomain {
				doms++
			} else {
				nets++
			}
		}
		x.out("  %s%s%s — доменов: %d, IP/подсетей: %d%s", x.c.Cyan, lists.VPNFileName, x.c.NC, doms, nets, badSuffix(len(l.Invalid())))
	}
	if ovs, bad, err := lists.ReadOverrides(x.overrideFile()); err != nil {
		x.out("  %s%s%s — ошибка чтения: %v", x.c.Cyan, lists.OverrideFileName, x.c.NC, err)
	} else {
		x.out("  %s%s%s — правил: %d%s", x.c.Cyan, lists.OverrideFileName, x.c.NC, len(ovs), badSuffix(len(bad)))
	}
	return 0
}

func badSuffix(n int) string {
	if n == 0 {
		return ""
	}
	return ", с ошибками: " + strconv.Itoa(n) + " (см. check-config)"
}

func cmdListVPN(x *ctx, _ []string) int {
	x.out("%sСписок VPN-записей (%s):%s", x.c.Cyan, x.vpnFile(), x.c.NC)
	l, exists, err := lists.ReadVPN(x.vpnFile())
	switch {
	case err != nil:
		x.errf("Ошибка чтения: %v", err)
		return 1
	case !exists:
		x.out("%sФайл не найден.%s", x.c.Yellow, x.c.NC)
		return 0
	}
	empty := true
	for _, ln := range l.Lines {
		switch {
		case ln.Err != nil:
			x.out("  %sОШИБКА (строка %d):%s %v", x.c.Yellow, ln.Num, x.c.NC, ln.Err)
		case ln.Entry == nil:
			continue
		case ln.Entry.Kind == lists.KindNet:
			x.out("  %sIP:%s %s", x.c.Cyan, x.c.NC, ln.Entry)
		default:
			x.out("  %sDOMAIN:%s %s", x.c.Green, x.c.NC, ln.Entry)
		}
		empty = false
	}
	if empty {
		x.out("  (список пуст)")
	}
	return 0
}

// cmdCheckConfig — новая команда: проверка всех конфигов без применения.
func cmdCheckConfig(x *ctx, _ []string) int {
	failed := false
	report := func(name string, errs []string) {
		if len(errs) == 0 {
			x.out("  %s✓%s %s", x.c.Green, x.c.NC, name)
			return
		}
		failed = true
		x.out("  %s✗%s %s", x.c.Red, x.c.NC, name)
		for _, e := range errs {
			x.out("      %s", e)
		}
	}

	x.out("%sПроверка конфигов в %s:%s", x.c.Yellow, x.ConfigDir, x.c.NC)

	_, warns, err := config.Load(x.routerConf())
	var errs []string
	if err != nil {
		errs = strings.Split(err.Error(), "\n")
	}
	report(config.FileName, errs)
	for _, w := range warns {
		x.out("      %sпредупреждение:%s %s", x.c.Yellow, x.c.NC, w)
	}

	errs = nil
	if l, _, err := lists.ReadVPN(x.vpnFile()); err != nil {
		errs = append(errs, err.Error())
	} else {
		for _, ln := range l.Invalid() {
			errs = append(errs, "строка "+strconv.Itoa(ln.Num)+": "+ln.Err.Error())
		}
	}
	report(lists.VPNFileName, errs)

	errs = nil
	if _, bad, err := lists.ReadOverrides(x.overrideFile()); err != nil {
		errs = append(errs, err.Error())
	} else {
		for _, b := range bad {
			errs = append(errs, b.Error())
		}
	}
	report(lists.OverrideFileName, errs)

	if failed {
		return 1
	}
	return 0
}

// shortDuration — 24h вместо 24h0m0s.
func shortDuration(d time.Duration) string {
	switch {
	case d%time.Hour == 0:
		return fmt.Sprintf("%dh", d/time.Hour)
	case d%time.Minute == 0:
		return fmt.Sprintf("%dm", d/time.Minute)
	}
	return d.String()
}

func yesNo(b bool) string {
	if b {
		return "да"
	}
	return "нет"
}
