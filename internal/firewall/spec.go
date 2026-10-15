// Package firewall — правила nftables routerd: NAT, отправка трафика к адресам
// из списков в туннель (redirect / tproxy / route), отклонение QUIC.
// Работает через netlink (google/nftables), без вызова nft/iptables/ipset.
//
// Всё живёт в собственной таблице `ip router_service`; таблицы других
// программ не трогаются. Применение правил — только Linux
// (firewall_linux.go); Spec и подготовка диапазонов собираются везде.
package firewall

import (
	"errors"
	"fmt"
	"net/netip"
	"time"
)

// Имена объектов nftables.
const (
	TableName       = "router_service"
	SetStatic       = "vpn_static"  // IP и подсети из списка (interval)
	SetDynamic      = "vpn_dynamic" // адреса из DNS-ответов (timeout)
	chainPrerouting = "prerouting_nat"
	chainPostroute  = "postrouting_nat"
	chainForward    = "forward_filter"
	chainMangle     = "prerouting_mangle"

	// Mark — fwmark пакетов, идущих в туннель (режимы tproxy и route);
	// по нему policy routing выбирает таблицу RouteTable.
	Mark = 0x52
	// RouteTable — таблица маршрутизации routerd.
	RouteTable = 152
)

// Mode — способ отправки трафика к адресам из списков в туннель.
type Mode string

const (
	// ModeRedirect — nat REDIRECT TCP на локальный слушатель (GOST red://).
	ModeRedirect Mode = "redirect"
	// ModeTProxy — TPROXY TCP и UDP на локальный слушатель (GOST red/redu с tproxy).
	ModeTProxy Mode = "tproxy"
	// ModeRoute — пометка и policy routing в интерфейс туннеля (L3, GOST tun://).
	ModeRoute Mode = "route"
)

// Spec — желаемое состояние правил.
type Spec struct {
	Iface        string       // интерфейс LAN (eth0)
	LAN          netip.Prefix // подсеть LAN
	RedirectPort uint16       // порт слушателя туннеля (redirect)
	QUICReject   bool         // отклонять UDP/443 к адресам из списков
	// DynamicTimeout — время жизни адреса в vpn_dynamic по умолчанию.
	DynamicTimeout time.Duration
	// Static — IP/подсети из vpn_domains.txt.
	Static []netip.Prefix

	Mode Mode
	// Tun — интерфейс туннеля для ModeRoute.
	Tun string
	// Bypass — перехват снят: туннель недоступен при VPN_FAILOVER=open,
	// трафик к адресам из списков идёт напрямую. Set'ы и NAT остаются.
	Bypass bool
}

// Validate проверяет Spec до обращения к ядру.
func (s Spec) Validate() error {
	var errs []error
	if s.Iface == "" || len(s.Iface) > 15 {
		errs = append(errs, fmt.Errorf("недопустимое имя интерфейса %q", s.Iface))
	}
	if !s.LAN.IsValid() || !s.LAN.Addr().Is4() {
		errs = append(errs, fmt.Errorf("недопустимая подсеть LAN %v", s.LAN))
	}
	if s.RedirectPort == 0 {
		errs = append(errs, errors.New("порт перенаправления не задан"))
	}
	switch s.Mode {
	case ModeRedirect, ModeTProxy:
	case ModeRoute:
		if s.Tun == "" || len(s.Tun) > 15 {
			errs = append(errs, fmt.Errorf("недопустимое имя интерфейса туннеля %q", s.Tun))
		}
	default:
		errs = append(errs, fmt.Errorf("неизвестный режим %q", s.Mode))
	}
	if s.DynamicTimeout < time.Second {
		errs = append(errs, fmt.Errorf("слишком короткий таймаут vpn_dynamic: %v", s.DynamicTimeout))
	}
	return errors.Join(errs...)
}
