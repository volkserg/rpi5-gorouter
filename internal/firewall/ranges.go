package firewall

import (
	"net/netip"
	"slices"
)

// ipRange — диапазон IPv4 [first, last] включительно.
type ipRange struct {
	first, last uint32
}

func addrToU32(a netip.Addr) uint32 {
	b := a.As4()
	return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
}

func u32ToAddr(v uint32) netip.Addr {
	return netip.AddrFrom4([4]byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)})
}

// mergePrefixes сливает перекрывающиеся и смежные подсети в непересекающиеся
// диапазоны. Ядро отвергает пересекающиеся элементы interval-set, а nft
// делает это слияние сам (auto-merge) — через netlink его делаем мы.
func mergePrefixes(ps []netip.Prefix) []ipRange {
	rs := make([]ipRange, 0, len(ps))
	for _, p := range ps {
		if !p.Addr().Is4() {
			continue
		}
		p = p.Masked()
		first := addrToU32(p.Addr())
		last := first | (^uint32(0) >> p.Bits())
		if p.Bits() == 0 {
			last = ^uint32(0)
		}
		rs = append(rs, ipRange{first, last})
	}
	slices.SortFunc(rs, func(a, b ipRange) int {
		switch {
		case a.first < b.first:
			return -1
		case a.first > b.first:
			return 1
		}
		return 0
	})
	var out []ipRange
	for _, r := range rs {
		if n := len(out); n > 0 {
			prev := &out[n-1]
			// Перекрытие или смежность (prev.last+1 == r.first без переполнения).
			if r.first <= prev.last || (prev.last != ^uint32(0) && r.first == prev.last+1) {
				if r.last > prev.last {
					prev.last = r.last
				}
				continue
			}
		}
		out = append(out, r)
	}
	return out
}
