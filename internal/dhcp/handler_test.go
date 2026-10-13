package dhcp

import (
	"io"
	"log/slog"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/insomniacslk/dhcp/dhcpv4"
)

func testHandler() *Handler {
	p, _ := testPool(nil)
	return &Handler{
		Pool: p,
		Opts: Options{
			ServerIP: a("192.168.3.2"), Netmask: a("255.255.255.0"), Broadcast: a("192.168.3.255"),
			Domain: "lan", LeaseTime: 24 * time.Hour,
		},
		Log: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
}

func msg(t *testing.T, mt dhcpv4.MessageType, mac string, mods ...dhcpv4.Modifier) *dhcpv4.DHCPv4 {
	t.Helper()
	hw, _ := net.ParseMAC(mac)
	m, err := dhcpv4.New(append([]dhcpv4.Modifier{
		dhcpv4.WithMessageType(mt), dhcpv4.WithHwAddr(hw), dhcpv4.WithOption(dhcpv4.OptHostName("alice")),
	}, mods...)...)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func TestHandleDORA(t *testing.T) {
	h := testHandler()
	offer, dst := h.Handle(msg(t, dhcpv4.MessageTypeDiscover, alice.MAC))
	if offer == nil || offer.MessageType() != dhcpv4.MessageTypeOffer || !dst.IP.Equal(net.IPv4bcast) {
		t.Fatalf("offer: %v → %v", offer, dst)
	}
	if offer.YourIPAddr.String() != "192.168.3.100" ||
		offer.Router()[0].String() != "192.168.3.2" || offer.DNS()[0].String() != "192.168.3.2" ||
		offer.ServerIdentifier().String() != "192.168.3.2" || net.IP(offer.SubnetMask()).String() != "255.255.255.0" ||
		offer.DomainName() != "lan" || offer.IPAddressLeaseTime(0) != 24*time.Hour ||
		offer.IPAddressRenewalTime(0) != 12*time.Hour || offer.IPAddressRebindingTime(0) != 21*time.Hour {
		t.Errorf("опции OFFER: %s", offer.Summary())
	}
	if bc := offer.GetOneOption(dhcpv4.OptionBroadcastAddress); net.IP(bc).String() != "192.168.3.255" {
		t.Errorf("broadcast: %v", net.IP(bc))
	}

	ack, dst := h.Handle(msg(t, dhcpv4.MessageTypeRequest, alice.MAC,
		dhcpv4.WithOption(dhcpv4.OptRequestedIPAddress(offer.YourIPAddr)),
		dhcpv4.WithOption(dhcpv4.OptServerIdentifier(net.ParseIP("192.168.3.2")))))
	if ack == nil || ack.MessageType() != dhcpv4.MessageTypeAck || ack.YourIPAddr.String() != "192.168.3.100" || !dst.IP.Equal(net.IPv4bcast) {
		t.Fatalf("ack: %v → %v", ack, dst)
	}

	// Продление (RENEWING): ciaddr, unicast на адрес клиента.
	renew, dst := h.Handle(msg(t, dhcpv4.MessageTypeRequest, alice.MAC,
		dhcpv4.WithClientIP(net.ParseIP("192.168.3.100"))))
	if renew.MessageType() != dhcpv4.MessageTypeAck || dst.IP.String() != "192.168.3.100" {
		t.Errorf("renew: %v → %v", renew.MessageType(), dst)
	}
}

func TestHandleNAKAndOtherServer(t *testing.T) {
	h := testHandler()
	nak, dst := h.Handle(msg(t, dhcpv4.MessageTypeRequest, alice.MAC,
		dhcpv4.WithOption(dhcpv4.OptRequestedIPAddress(net.ParseIP("10.0.0.5")))))
	if nak == nil || nak.MessageType() != dhcpv4.MessageTypeNak || !dst.IP.Equal(net.IPv4bcast) {
		t.Errorf("NAK: %v → %v", nak, dst)
	}
	// Клиент выбрал другой сервер — молчим и снимаем предложение.
	h.Handle(msg(t, dhcpv4.MessageTypeDiscover, alice.MAC))
	resp, _ := h.Handle(msg(t, dhcpv4.MessageTypeRequest, alice.MAC,
		dhcpv4.WithOption(dhcpv4.OptRequestedIPAddress(net.ParseIP("192.168.3.100"))),
		dhcpv4.WithOption(dhcpv4.OptServerIdentifier(net.ParseIP("192.168.3.1")))))
	if resp != nil {
		t.Errorf("ответ на REQUEST другому серверу: %v", resp)
	}
	if len(h.Pool.Leases()) != 0 {
		t.Errorf("предложение должно сняться: %+v", h.Pool.Leases())
	}
}

func TestHandleReleaseInformRelay(t *testing.T) {
	h := testHandler()
	h.Handle(msg(t, dhcpv4.MessageTypeDiscover, alice.MAC))
	h.Handle(msg(t, dhcpv4.MessageTypeRequest, alice.MAC,
		dhcpv4.WithOption(dhcpv4.OptRequestedIPAddress(net.ParseIP("192.168.3.100")))))
	h.Handle(msg(t, dhcpv4.MessageTypeRelease, alice.MAC, dhcpv4.WithClientIP(net.ParseIP("192.168.3.100"))))
	if l := h.Pool.Leases(); len(l) != 1 || l[0].State != StateReleased {
		t.Errorf("release: %+v", l)
	}

	inf, dst := h.Handle(msg(t, dhcpv4.MessageTypeInform, carol.MAC, dhcpv4.WithClientIP(net.ParseIP("192.168.3.40"))))
	if inf.MessageType() != dhcpv4.MessageTypeAck || !inf.YourIPAddr.IsUnspecified() || dst.IP.String() != "192.168.3.40" {
		t.Errorf("inform: %s → %v", inf.Summary(), dst)
	}

	relayed := msg(t, dhcpv4.MessageTypeDiscover, carol.MAC, dhcpv4.WithGatewayIP(net.ParseIP("10.1.1.1")))
	if resp, _ := h.Handle(relayed); resp != nil {
		t.Error("через relay-агент не отвечаем")
	}
	_ = netip.Addr{}
}
