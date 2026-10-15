package dhcp

import (
	"encoding/hex"
	"log/slog"
	"net"
	"net/netip"
	"time"

	"github.com/insomniacslk/dhcp/dhcpv4"
)

// Options — параметры, которые сервер сообщает клиентам.
type Options struct {
	ServerIP  netip.Addr // RPi: идентификатор сервера, шлюз и DNS для клиентов
	Netmask   netip.Addr
	Broadcast netip.Addr
	Domain    string // опция 15 (lan)
	LeaseTime time.Duration
}

// Handler отвечает на DHCP-сообщения клиентов.
type Handler struct {
	Pool *Pool
	Opts Options
	Log  *slog.Logger
}

var bcast = &net.UDPAddr{IP: net.IPv4bcast, Port: dhcpv4.ClientPort}

// Handle возвращает ответ и адрес, куда его отправить (nil — не отвечать).
// Ответы клиентам без адреса уходят broadcast'ом: так не нужен raw-сокет
// (CAP_NET_RAW) для unicast на ещё не настроенный адрес.
func (h *Handler) Handle(req *dhcpv4.DHCPv4) (*dhcpv4.DHCPv4, *net.UDPAddr) {
	if req.OpCode != dhcpv4.OpcodeBootRequest || addrOf(req.GatewayIPAddr).IsValid() {
		return nil, nil // relay-агенты не поддерживаются: сервер в той же L2-сети
	}
	c := Client{MAC: req.ClientHWAddr.String(), Hostname: req.HostName()}
	if id := req.GetOneOption(dhcpv4.OptionClientIdentifier); len(id) > 0 {
		c.ClientID = hex.EncodeToString(id)
	}
	requested := addrOf(req.RequestedIPAddress())

	switch req.MessageType() {
	case dhcpv4.MessageTypeDiscover:
		ip, err := h.Pool.Offer(c, requested)
		if err != nil {
			h.Log.Warn("DHCPDISCOVER без ответа", "mac", c.MAC, "ошибка", err)
			return nil, nil
		}
		h.Log.Info("DHCPOFFER", "ip", ip, "mac", c.MAC, "hostname", c.Hostname)
		return h.reply(req, dhcpv4.MessageTypeOffer, ip, true), bcast

	case dhcpv4.MessageTypeRequest:
		if sid := addrOf(req.ServerIdentifier()); sid.IsValid() && sid != h.Opts.ServerIP {
			h.Pool.CancelOffer(c) // клиент выбрал другой сервер
			return nil, nil
		}
		ip := requested
		if !ip.IsValid() {
			ip = addrOf(req.ClientIPAddr) // RENEWING / REBINDING
		}
		lease, err := h.Pool.Request(c, ip)
		if err != nil {
			h.Log.Info("DHCPNAK", "ip", ip, "mac", c.MAC, "причина", err)
			return h.nak(req), bcast
		}
		h.Log.Info("DHCPACK", "ip", lease.IP, "mac", c.MAC, "name", lease.Name)
		return h.reply(req, dhcpv4.MessageTypeAck, lease.IP, true), h.dest(req)

	case dhcpv4.MessageTypeRelease:
		h.Pool.Release(c, addrOf(req.ClientIPAddr))
		h.Log.Info("DHCPRELEASE", "ip", addrOf(req.ClientIPAddr), "mac", c.MAC)
		return nil, nil

	case dhcpv4.MessageTypeDecline:
		h.Pool.Decline(c, requested)
		h.Log.Warn("DHCPDECLINE: адрес занят", "ip", requested, "mac", c.MAC)
		return nil, nil

	case dhcpv4.MessageTypeInform:
		// Адрес у клиента уже есть — только параметры сети.
		return h.reply(req, dhcpv4.MessageTypeAck, netip.Addr{}, false), h.dest(req)
	}
	return nil, nil
}

func (h *Handler) reply(req *dhcpv4.DHCPv4, mt dhcpv4.MessageType, yiaddr netip.Addr, lease bool) *dhcpv4.DHCPv4 {
	o := h.Opts
	mods := []dhcpv4.Modifier{
		dhcpv4.WithMessageType(mt),
		dhcpv4.WithOption(dhcpv4.OptServerIdentifier(ip(o.ServerIP))),
		dhcpv4.WithOption(dhcpv4.OptSubnetMask(net.IPMask(ip(o.Netmask)))),
		dhcpv4.WithOption(dhcpv4.OptRouter(ip(o.ServerIP))),
		dhcpv4.WithOption(dhcpv4.OptDNS(ip(o.ServerIP))),
		dhcpv4.WithOption(dhcpv4.OptBroadcastAddress(ip(o.Broadcast))),
	}
	if o.Domain != "" {
		mods = append(mods, dhcpv4.WithOption(dhcpv4.OptDomainName(o.Domain)))
	}
	if lease {
		// T1/T2 — 1/2 и 7/8 срока аренды (рекомендация RFC 2131).
		mods = append(mods,
			dhcpv4.WithYourIP(ip(yiaddr)),
			dhcpv4.WithOption(dhcpv4.OptIPAddressLeaseTime(o.LeaseTime)),
			dhcpv4.WithOption(dhcpv4.OptRenewTimeValue(o.LeaseTime/2)),
			dhcpv4.WithOption(dhcpv4.OptRebindingTimeValue(o.LeaseTime*7/8)),
		)
	}
	resp, err := dhcpv4.NewReplyFromRequest(req, mods...)
	if err != nil {
		h.Log.Error("сборка ответа DHCP", "ошибка", err)
		return nil
	}
	return resp
}

func (h *Handler) nak(req *dhcpv4.DHCPv4) *dhcpv4.DHCPv4 {
	resp, err := dhcpv4.NewReplyFromRequest(req,
		dhcpv4.WithMessageType(dhcpv4.MessageTypeNak),
		dhcpv4.WithOption(dhcpv4.OptServerIdentifier(ip(h.Opts.ServerIP))),
	)
	if err != nil {
		return nil
	}
	return resp
}

// dest — unicast на адрес клиента, если он у клиента уже есть (RENEWING,
// INFORM), иначе broadcast.
func (h *Handler) dest(req *dhcpv4.DHCPv4) *net.UDPAddr {
	if ci := addrOf(req.ClientIPAddr); ci.IsValid() && !ci.IsUnspecified() {
		return &net.UDPAddr{IP: ip(ci), Port: dhcpv4.ClientPort}
	}
	return bcast
}

func addrOf(b net.IP) netip.Addr {
	if b4 := b.To4(); b4 != nil && !b4.IsUnspecified() {
		a, _ := netip.AddrFromSlice(b4)
		return a
	}
	return netip.Addr{}
}

func ip(a netip.Addr) net.IP {
	if !a.IsValid() {
		return net.IPv4zero.To4()
	}
	return net.IP(a.AsSlice())
}
