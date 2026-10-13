//go:build linux

package dhcp

import (
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"sync/atomic"

	"github.com/insomniacslk/dhcp/dhcpv4"
	"github.com/insomniacslk/dhcp/dhcpv4/server4"
	"github.com/vishvananda/netlink"
)

// Server — UDP :67 на интерфейсе LAN (SO_BINDTODEVICE) с Handler.
type Server struct {
	srv     *server4.Server
	handler atomic.Pointer[Handler]
}

// Listen открывает сокет и начинает обслуживать запросы.
func Listen(iface string, h *Handler, log *slog.Logger) (*Server, error) {
	conn, err := server4.NewIPv4UDPConn(iface, &net.UDPAddr{IP: net.IPv4zero, Port: dhcpv4.ServerPort})
	if err != nil {
		return nil, fmt.Errorf("DHCP :67 на %s: %w", iface, err)
	}
	s := &Server{}
	s.handler.Store(h)
	srv, err := server4.NewServer(iface, nil, func(c net.PacketConn, _ net.Addr, m *dhcpv4.DHCPv4) {
		resp, dst := s.handler.Load().Handle(m)
		if resp == nil || dst == nil {
			return
		}
		if _, err := c.WriteTo(resp.ToBytes(), dst); err != nil {
			log.Warn("отправка ответа DHCP", "куда", dst, "ошибка", err)
		}
	}, server4.WithConn(conn))
	if err != nil {
		conn.Close()
		return nil, err
	}
	s.srv = srv
	go func() {
		if err := srv.Serve(); err != nil {
			log.Debug("DHCP-сервер остановлен", "ошибка", err)
		}
	}()
	return s, nil
}

// SetHandler заменяет обработчик (после перезагрузки конфигурации).
func (s *Server) SetHandler(h *Handler) { s.handler.Store(h) }

// Close закрывает сокет.
func (s *Server) Close() error { return s.srv.Close() }

// NeighProber — Prober по таблице соседей ядра (ARP) интерфейса LAN.
type NeighProber struct {
	H     *netlink.Handle
	Iface string
}

// Owner возвращает MAC устройства, которое ядро видит на адресе ip.
func (p NeighProber) Owner(ip netip.Addr) (string, bool) {
	link, err := p.H.LinkByName(p.Iface)
	if err != nil {
		return "", false
	}
	neighs, err := p.H.NeighList(link.Attrs().Index, netlink.FAMILY_V4)
	if err != nil {
		return "", false
	}
	const alive = netlink.NUD_REACHABLE | netlink.NUD_STALE | netlink.NUD_DELAY | netlink.NUD_PROBE | netlink.NUD_PERMANENT
	for _, n := range neighs {
		if a, ok := netip.AddrFromSlice(n.IP.To4()); ok && a == ip && n.State&alive != 0 && len(n.HardwareAddr) > 0 {
			return n.HardwareAddr.String(), true
		}
	}
	return "", false
}
