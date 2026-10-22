//go:build linux

package access

import (
	"net/netip"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// Snapshot читает таблицу conntrack (IPv4). acct — в записях есть
// счётчики пакетов (nf_conntrack_acct=1).
func Snapshot(h *netlink.Handle) (flows []Flow, acct bool, err error) {
	list, err := h.ConntrackTableList(netlink.ConntrackTable, netlink.InetFamily(unix.AF_INET))
	if err != nil {
		return nil, false, err
	}
	flows = make([]Flow, 0, len(list))
	for _, c := range list {
		src, ok1 := netip.AddrFromSlice(c.Forward.SrcIP.To4())
		dst, ok2 := netip.AddrFromSlice(c.Forward.DstIP.To4())
		if !ok1 || !ok2 {
			continue
		}
		f := Flow{
			Proto: c.Forward.Protocol, Src: src, Dst: dst,
			SPort: c.Forward.SrcPort, DPort: c.Forward.DstPort,
			OrigPkts: c.Forward.Packets, OrigBytes: c.Forward.Bytes,
			ReplyPkts: c.Reverse.Packets, ReplyBytes: c.Reverse.Bytes,
		}
		if tcp, ok := c.ProtoInfo.(*netlink.ProtoInfoTCP); ok {
			f.TCPState = tcp.State
		}
		if f.OrigPkts > 0 {
			acct = true
		}
		flows = append(flows, f)
	}
	return flows, acct, nil
}
