package firewall

import (
	"net/netip"
	"strings"
	"testing"
	"time"
)

func rangesString(rs []ipRange) string {
	var parts []string
	for _, r := range rs {
		parts = append(parts, u32ToAddr(r.first).String()+"-"+u32ToAddr(r.last).String())
	}
	return strings.Join(parts, ",")
}

func prefixes(ss ...string) []netip.Prefix {
	var out []netip.Prefix
	for _, s := range ss {
		out = append(out, netip.MustParsePrefix(s))
	}
	return out
}

func TestMergePrefixes(t *testing.T) {
	for _, tc := range []struct {
		in   []string
		want string
	}{
		{nil, ""},
		{[]string{"192.0.2.1/32"}, "192.0.2.1-192.0.2.1"},
		// Вложенная подсеть поглощается.
		{[]string{"10.0.0.0/8", "10.20.0.0/16", "10.1.2.3/32"}, "10.0.0.0-10.255.255.255"},
		// Смежные сливаются, порядок входа не важен.
		{[]string{"10.0.1.0/24", "10.0.0.0/24"}, "10.0.0.0-10.0.1.255"},
		// Несмежные остаются отдельно и сортируются.
		{[]string{"203.0.113.0/24", "198.51.100.7/32"}, "198.51.100.7-198.51.100.7,203.0.113.0-203.0.113.255"},
		// Ненормализованная подсеть и края адресного пространства.
		{[]string{"10.1.2.3/16"}, "10.1.0.0-10.1.255.255"},
		{[]string{"0.0.0.0/0", "1.2.3.4/32"}, "0.0.0.0-255.255.255.255"},
		{[]string{"255.255.255.0/24", "255.255.254.0/24"}, "255.255.254.0-255.255.255.255"},
	} {
		if got := rangesString(mergePrefixes(prefixes(tc.in...))); got != tc.want {
			t.Errorf("%v: got %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestSpecValidate(t *testing.T) {
	ok := Spec{Iface: "eth0", LAN: netip.MustParsePrefix("192.168.3.0/24"), RedirectPort: 1080, DynamicTimeout: 24 * time.Hour}
	if err := ok.Validate(); err != nil {
		t.Fatal(err)
	}
	bad := ok
	bad.Iface, bad.RedirectPort, bad.DynamicTimeout = "averyveryverylongname", 0, 0
	if err := bad.Validate(); err == nil || strings.Count(err.Error(), "\n") != 2 {
		t.Errorf("ожидались три ошибки: %v", err)
	}
}
