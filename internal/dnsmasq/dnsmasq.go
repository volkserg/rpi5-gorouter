// Package dnsmasq генерирует конфиг временного DNS-фильтра на dnsmasq:
// домены из списка наполняют nft-set vpn_dynamic (nftset=), override-домены
// уходят на свои upstream (server=). Пакет живёт до этапа 3, где его
// заменит DNS-прокси routerd.
package dnsmasq

import (
	"bytes"
	"fmt"
	"net/netip"

	"github.com/volkserg/rpi5-gorouter/internal/config"
	"github.com/volkserg/rpi5-gorouter/internal/firewall"
	"github.com/volkserg/rpi5-gorouter/internal/lists"
)

// Unit — systemd-юнит, в котором работает dnsmasq (PartOf=routerd.service).
const Unit = "routerd-dnsmasq.service"

// Render строит конфиг. Параметры совпадают с запуском dnsmasq в bash-версии:
// порт 53 на интерфейсе LAN (и loopback — его dnsmasq добавляет сам, на нём
// резолвит GOST), без resolv.conf и без кэша (кэширует Pi-hole).
func Render(cfg *config.Config, entries []lists.Entry, overrides []lists.Override) []byte {
	var b bytes.Buffer
	b.WriteString("# Сгенерировано routerd — не редактировать, изменения будут перезаписаны.\n")
	fmt.Fprintf(&b, "port=53\ninterface=%s\nbind-interfaces\n", cfg.Iface)
	b.WriteString("no-resolv\ncache-size=0\ndns-forward-max=300\nbogus-priv\n")
	fmt.Fprintf(&b, "server=%s\n", upstream(cfg.DNSUpstream))

	for _, e := range entries {
		if e.Kind == lists.KindDomain {
			fmt.Fprintf(&b, "nftset=/%s/4#ip#%s#%s\n", e.Domain, firewall.TableName, firewall.SetDynamic)
		}
	}
	for _, o := range overrides {
		fmt.Fprintf(&b, "server=/%s/%s\n", o.Domain, upstream(o.Upstream))
	}
	return b.Bytes()
}

// upstream — адрес в синтаксисе dnsmasq: порт через '#'.
func upstream(ap netip.AddrPort) string {
	return fmt.Sprintf("%s#%d", ap.Addr(), ap.Port())
}
