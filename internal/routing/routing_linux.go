//go:build linux

// Package routing — policy routing routerd через netlink (вместо ip rule /
// ip route): пакеты с меткой firewall.Mark уходят в таблицу
// firewall.RouteTable, содержимое которой зависит от режима.
//
//	tproxy: local 0.0.0.0/0 dev lo          — доставка перехваченного слушателю
//	route:  default dev <tun>               — когда интерфейс туннеля поднят
//	        unreachable default metric 4096 — туннеля нет: не утекать напрямую
package routing

import (
	"errors"
	"fmt"
	"net"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"github.com/volkserg/rpi5-gorouter/internal/firewall"
)

// RulePriority — приоритет ip rule routerd (раньше main = 32766).
const RulePriority = 1520

// killSwitchMetric — метрика запасного unreachable-маршрута в режиме route.
const killSwitchMetric = 4096

// Policy — желаемое состояние маршрутизации.
type Policy struct {
	Mode   firewall.Mode
	Tun    string
	Bypass bool
}

var defaultDst = &net.IPNet{IP: net.IPv4zero.To4(), Mask: net.CIDRMask(0, 32)}

// Apply приводит ip rule и таблицу routerd к Policy. Возвращает, поднят ли
// интерфейс туннеля (имеет смысл для режима route).
func Apply(h *netlink.Handle, p Policy) (tunUp bool, err error) {
	wantRule := (p.Mode == firewall.ModeTProxy || p.Mode == firewall.ModeRoute) && !p.Bypass
	if err := ensureRule(h, wantRule); err != nil {
		return false, err
	}

	var want []*netlink.Route
	switch {
	case !wantRule:
	case p.Mode == firewall.ModeTProxy:
		lo, err := h.LinkByName("lo")
		if err != nil {
			return false, fmt.Errorf("интерфейс lo: %w", err)
		}
		want = append(want, &netlink.Route{Family: netlink.FAMILY_V4, Table: firewall.RouteTable,
			Type: unix.RTN_LOCAL, Dst: defaultDst, LinkIndex: lo.Attrs().Index, Scope: netlink.SCOPE_HOST})
	case p.Mode == firewall.ModeRoute:
		want = append(want, &netlink.Route{Family: netlink.FAMILY_V4, Table: firewall.RouteTable,
			Type: unix.RTN_UNREACHABLE, Dst: defaultDst, Priority: killSwitchMetric})
		if link, ok := TunLink(h, p.Tun); ok {
			tunUp = true
			want = append(want, &netlink.Route{Family: netlink.FAMILY_V4, Table: firewall.RouteTable,
				Type: unix.RTN_UNICAST, Dst: defaultDst, LinkIndex: link.Attrs().Index, Scope: netlink.SCOPE_LINK})
		}
	}
	return tunUp, syncTable(h, want)
}

// Remove убирает ip rule и маршруты routerd.
func Remove(h *netlink.Handle) error {
	return errors.Join(ensureRule(h, false), syncTable(h, nil))
}

// TunLink возвращает интерфейс туннеля, если он существует и поднят.
func TunLink(h *netlink.Handle, name string) (netlink.Link, bool) {
	if name == "" {
		return nil, false
	}
	link, err := h.LinkByName(name)
	if err != nil || link.Attrs().Flags&net.FlagUp == 0 {
		return nil, false
	}
	return link, true
}

func ourRule() *netlink.Rule {
	r := netlink.NewRule()
	r.Family = netlink.FAMILY_V4
	r.Priority = RulePriority
	r.Mark = firewall.Mark
	r.Table = firewall.RouteTable
	return r
}

func ensureRule(h *netlink.Handle, want bool) error {
	rules, err := h.RuleList(netlink.FAMILY_V4)
	if err != nil {
		return fmt.Errorf("список ip rule: %w", err)
	}
	found := false
	for _, r := range rules {
		if r.Table == firewall.RouteTable && r.Mark == firewall.Mark {
			found = true
			break
		}
	}
	switch {
	case want && !found:
		if err := h.RuleAdd(ourRule()); err != nil {
			return fmt.Errorf("ip rule fwmark %#x lookup %d: %w", firewall.Mark, firewall.RouteTable, err)
		}
	case !want && found:
		if err := h.RuleDel(ourRule()); err != nil {
			return fmt.Errorf("удаление ip rule: %w", err)
		}
	}
	return nil
}

// syncTable приводит таблицу routerd к списку want: нужные маршруты
// заменяются на месте (без окна, когда таблица пуста), лишние удаляются.
func syncTable(h *netlink.Handle, want []*netlink.Route) error {
	var errs []error
	for _, r := range want {
		if err := h.RouteReplace(r); err != nil {
			errs = append(errs, fmt.Errorf("маршрут %s в таблице %d: %w", describe(r), firewall.RouteTable, err))
		}
	}
	have, err := h.RouteListFiltered(netlink.FAMILY_V4,
		&netlink.Route{Table: firewall.RouteTable}, netlink.RT_FILTER_TABLE)
	if err != nil {
		return errors.Join(append(errs, err)...)
	}
	for i := range have {
		r := &have[i]
		if !wanted(r, want) {
			if err := h.RouteDel(r); err != nil {
				errs = append(errs, fmt.Errorf("удаление маршрута %s: %w", describe(r), err))
			}
		}
	}
	return errors.Join(errs...)
}

func wanted(r *netlink.Route, want []*netlink.Route) bool {
	for _, w := range want {
		if r.Type == w.Type && r.Priority == w.Priority && r.LinkIndex == w.LinkIndex {
			return true
		}
	}
	return false
}

func describe(r *netlink.Route) string {
	switch r.Type {
	case unix.RTN_LOCAL:
		return "local default"
	case unix.RTN_UNREACHABLE:
		return "unreachable default"
	}
	return fmt.Sprintf("default dev #%d", r.LinkIndex)
}
