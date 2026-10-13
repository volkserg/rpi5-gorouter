//go:build linux

package firewall

import (
	"net/netip"
	"testing"
)

func TestIntervalElements(t *testing.T) {
	els := intervalElements(mergePrefixes([]netip.Prefix{
		netip.MustParsePrefix("10.0.0.0/8"), netip.MustParsePrefix("255.255.255.255/32"),
	}))
	// 0.0.0.0(end) 10.0.0.0 11.0.0.0(end) 255.255.255.255 — без конца: дальше адресов нет.
	want := []struct {
		key string
		end bool
	}{{"0.0.0.0", true}, {"10.0.0.0", false}, {"11.0.0.0", true}, {"255.255.255.255", false}}
	if len(els) != len(want) {
		t.Fatalf("got %d elements: %+v", len(els), els)
	}
	for i, w := range want {
		a, _ := netip.AddrFromSlice(els[i].Key)
		if a.String() != w.key || els[i].IntervalEnd != w.end {
			t.Errorf("элемент %d: %s end=%v, want %s end=%v", i, a, els[i].IntervalEnd, w.key, w.end)
		}
	}
	if intervalElements(nil) != nil {
		t.Error("пустой список — без элементов")
	}
}
