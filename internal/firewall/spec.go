// Package firewall — правила nftables routerd: NAT, перенаправление трафика
// к адресам из списков на локальный слушатель туннеля, отклонение QUIC.
// Работает через netlink (google/nftables), без вызова nft/iptables/ipset.
//
// Всё живёт в собственной таблице `ip router_service`; чужие таблицы
// (iptables-nft, Docker, …) не трогаются. Применение правил — только Linux
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
	if s.DynamicTimeout < time.Second {
		errs = append(errs, fmt.Errorf("слишком короткий таймаут vpn_dynamic: %v", s.DynamicTimeout))
	}
	return errors.Join(errs...)
}
