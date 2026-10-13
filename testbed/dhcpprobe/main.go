// Command dhcpprobe — DHCP-пробник стенда: отправляет отдельные сообщения,
// которые обычный клиент (busybox udhcpc) не умеет отправить по запросу.
// Client-id — 01+MAC, как у udhcpc, чтобы сервер видел того же клиента.
//
//	dhcpprobe -iface eth0 -request 10.9.9.9          # REQUEST (INIT-REBOOT), печатает ответ
//	dhcpprobe -iface eth0 -release 192.168.3.100 -server 192.168.3.2
package main

import (
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"time"

	"github.com/insomniacslk/dhcp/dhcpv4"
	"github.com/insomniacslk/dhcp/dhcpv4/server4"
)

func main() {
	iface := flag.String("iface", "eth0", "интерфейс")
	request := flag.String("request", "", "запросить адрес (DHCPREQUEST в состоянии INIT-REBOOT)")
	release := flag.String("release", "", "освободить адрес (DHCPRELEASE)")
	server := flag.String("server", "", "для -release: адрес DHCP-сервера")
	flag.Parse()

	ifi, err := net.InterfaceByName(*iface)
	if err != nil {
		log.Fatal(err)
	}
	conn, err := server4.NewIPv4UDPConn(*iface, &net.UDPAddr{IP: net.IPv4zero, Port: dhcpv4.ClientPort})
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()

	base := []dhcpv4.Modifier{
		dhcpv4.WithHwAddr(ifi.HardwareAddr),
		dhcpv4.WithOption(dhcpv4.OptClientIdentifier(append([]byte{1}, ifi.HardwareAddr...))),
	}
	switch {
	case *request != "":
		m, err := dhcpv4.New(append(base,
			dhcpv4.WithMessageType(dhcpv4.MessageTypeRequest),
			dhcpv4.WithBroadcast(true),
			dhcpv4.WithOption(dhcpv4.OptRequestedIPAddress(net.ParseIP(*request))))...)
		if err != nil {
			log.Fatal(err)
		}
		if _, err := conn.WriteTo(m.ToBytes(), &net.UDPAddr{IP: net.IPv4bcast, Port: dhcpv4.ServerPort}); err != nil {
			log.Fatal(err)
		}
		resp, err := waitReply(conn, m.TransactionID)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println(resp.MessageType(), resp.YourIPAddr)
	case *release != "":
		m, err := dhcpv4.New(append(base,
			dhcpv4.WithMessageType(dhcpv4.MessageTypeRelease),
			dhcpv4.WithClientIP(net.ParseIP(*release)),
			dhcpv4.WithOption(dhcpv4.OptServerIdentifier(net.ParseIP(*server))))...)
		if err != nil {
			log.Fatal(err)
		}
		if _, err := conn.WriteTo(m.ToBytes(), &net.UDPAddr{IP: net.ParseIP(*server), Port: dhcpv4.ServerPort}); err != nil {
			log.Fatal(err)
		}
		fmt.Println("RELEASE отправлен")
	default:
		flag.Usage()
		os.Exit(2)
	}
}

func waitReply(conn net.PacketConn, xid dhcpv4.TransactionID) (*dhcpv4.DHCPv4, error) {
	deadline := time.Now().Add(3 * time.Second)
	buf := make([]byte, 1500)
	for time.Now().Before(deadline) {
		_ = conn.SetReadDeadline(deadline)
		n, _, err := conn.ReadFrom(buf)
		if err != nil {
			return nil, err
		}
		m, err := dhcpv4.FromBytes(buf[:n])
		if err == nil && m.OpCode == dhcpv4.OpcodeBootReply && m.TransactionID == xid {
			return m, nil
		}
	}
	return nil, errors.New("нет ответа")
}
