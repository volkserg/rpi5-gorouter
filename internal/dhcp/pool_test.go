package dhcp

import (
	"errors"
	"net/netip"
	"path/filepath"
	"testing"
	"time"
)

type fakeProbe map[netip.Addr]string

func (f fakeProbe) Owner(ip netip.Addr) (string, bool) {
	mac, ok := f[ip]
	return mac, ok
}

var t0 = time.Date(2026, 10, 13, 12, 0, 0, 0, time.UTC)

func a(s string) netip.Addr { return netip.MustParseAddr(s) }

func testPool(probe Prober) (*Pool, *time.Time) {
	now := t0
	p := NewPool(PoolConfig{
		Subnet:    netip.MustParsePrefix("192.168.3.0/24"),
		Start:     a("192.168.3.100"),
		End:       a("192.168.3.103"),
		Reserved:  []netip.Addr{a("192.168.3.101")},
		LeaseTime: 24 * time.Hour,
		OfferTime: time.Minute,
	}, nil, probe)
	p.now = func() time.Time { return now }
	return p, &now
}

var (
	alice = Client{MAC: "02:00:00:00:00:01", Hostname: "Alice-Laptop"}
	bob   = Client{MAC: "02:00:00:00:00:02", Hostname: "alice laptop"}
	carol = Client{MAC: "02:00:00:00:00:03"}
	dave  = Client{MAC: "02:00:00:00:00:04"}
)

func TestOfferRequestRenew(t *testing.T) {
	p, now := testPool(nil)
	ip, err := p.Offer(alice, netip.Addr{})
	if err != nil || ip != a("192.168.3.100") {
		t.Fatalf("offer: %v %v", ip, err)
	}
	l, err := p.Request(alice, ip)
	if err != nil || l.Name != "alice-laptop" || !l.Expires.Equal(t0.Add(24*time.Hour)) {
		t.Fatalf("request: %+v %v", l, err)
	}
	// Повторный DISCOVER того же клиента — тот же адрес.
	if ip2, _ := p.Offer(alice, netip.Addr{}); ip2 != ip {
		t.Errorf("повторное предложение: %v", ip2)
	}
	// Продление через сутки без малого.
	*now = t0.Add(23 * time.Hour)
	if l, err := p.Request(alice, ip); err != nil || !l.Expires.Equal(now.Add(24*time.Hour)) {
		t.Errorf("renew: %+v %v", l, err)
	}
}

func TestReservedAndUniqueNames(t *testing.T) {
	p, _ := testPool(nil)
	ipA, _ := p.Offer(alice, netip.Addr{})
	p.Request(alice, ipA)
	ipB, _ := p.Offer(bob, netip.Addr{})
	if ipB != a("192.168.3.102") {
		t.Errorf("адрес RPi/роутера (.101) зарезервирован: предложен %v", ipB)
	}
	l, _ := p.Request(bob, ipB)
	if l.Name != "alice-laptop-2" {
		t.Errorf("имя второго клиента: %q", l.Name)
	}
}

func TestTolerantAuthoritative(t *testing.T) {
	p, _ := testPool(nil)
	ip, _ := p.Offer(alice, netip.Addr{})
	p.Request(alice, ip)

	for name, tc := range map[string]struct {
		c   Client
		ip  string
		err error
	}{
		"чужая подсеть": {bob, "10.0.0.5", errForeign},
		"вне пула":      {bob, "192.168.3.50", errOutside},
		"RPi":           {bob, "192.168.3.101", errOutside},
		"занят другим":  {bob, "192.168.3.100", errTaken},
	} {
		if _, err := p.Request(tc.c, a(tc.ip)); !errors.Is(err, tc.err) {
			t.Errorf("%s: err=%v, want %v", name, err, tc.err)
		}
	}
	// Свободный адрес из пула без аренды — ACK (восстановление после потери базы).
	if l, err := p.Request(carol, a("192.168.3.103")); err != nil || l.IP != a("192.168.3.103") {
		t.Errorf("свободный адрес: %+v %v", l, err)
	}
}

func TestExpiredReuseAndExhaustion(t *testing.T) {
	p, now := testPool(nil)
	for _, c := range []Client{alice, bob} {
		ip, _ := p.Offer(c, netip.Addr{})
		p.Request(c, ip)
	}
	ipC, _ := p.Offer(carol, netip.Addr{})
	p.Request(carol, ipC)
	if _, err := p.Offer(dave, netip.Addr{}); !errors.Is(err, ErrExhausted) {
		t.Fatalf("пул из трёх адресов исчерпан: %v", err)
	}
	// Аренда alice истекла — её адрес достаётся dave, но только после истечения.
	*now = t0.Add(25 * time.Hour)
	p.Request(bob, a("192.168.3.102"))
	p.Request(carol, ipC)
	ip, err := p.Offer(dave, netip.Addr{})
	if err != nil || ip != a("192.168.3.100") {
		t.Errorf("истёкший адрес: %v %v", ip, err)
	}
}

func TestReleaseKeepsBinding(t *testing.T) {
	p, now := testPool(nil)
	ip, _ := p.Offer(alice, netip.Addr{})
	p.Request(alice, ip)
	p.Release(alice, ip)
	*now = t0.Add(time.Hour)
	// Другой клиент может взять освобождённый адрес…
	if ipB, _ := p.Offer(bob, netip.Addr{}); ipB != a("192.168.3.102") {
		t.Logf("bob: %v (берёт сначала никогда не выданный)", ipB)
	}
	// …а alice, пока адрес свободен, получает его обратно.
	if ipA, _ := p.Offer(alice, netip.Addr{}); ipA != ip {
		t.Errorf("alice после release: %v, want %v", ipA, ip)
	}
}

func TestProbeConflictAndDecline(t *testing.T) {
	probe := fakeProbe{a("192.168.3.100"): "02:aa:00:00:00:99"} // статика вне DHCP
	p, now := testPool(probe)
	ip, _ := p.Offer(alice, netip.Addr{})
	if ip != a("192.168.3.102") {
		t.Errorf("занятый устройством адрес не предлагается: %v", ip)
	}
	if _, err := p.Request(bob, a("192.168.3.100")); !errors.Is(err, errConflict) {
		t.Errorf("REQUEST занятого устройством адреса: %v", err)
	}
	// Тот же MAC — его собственный адрес.
	if _, err := p.Request(Client{MAC: "02:AA:00:00:00:99"}, a("192.168.3.100")); err != nil {
		t.Errorf("устройство с этим MAC: %v", err)
	}

	l, _ := p.Request(alice, ip)
	p.Decline(alice, l.IP)
	if ip2, _ := p.Offer(alice, netip.Addr{}); ip2 == l.IP {
		t.Error("после DECLINE адрес не предлагается")
	}
	*now = t0.Add(conflictHold + time.Minute)
	delete(probe, a("192.168.3.100"))
	if _, err := p.Request(carol, l.IP); err != nil {
		t.Errorf("после истечения конфликта адрес снова доступен: %v", err)
	}
}

func TestClientIDKey(t *testing.T) {
	p, _ := testPool(nil)
	withID := Client{MAC: alice.MAC, ClientID: "01020000000001"}
	ip1, _ := p.Offer(alice, netip.Addr{})
	p.Request(alice, ip1)
	ip2, _ := p.Offer(withID, netip.Addr{})
	if ip2 == ip1 {
		t.Error("клиент с client-id — отдельный клиент")
	}
}

func TestPersistence(t *testing.T) {
	path := filepath.Join(t.TempDir(), LeaseFile)
	p, _ := testPool(nil)
	p.OnChange(func(ls []Lease) {
		if err := SaveLeases(path, ls); err != nil {
			t.Fatal(err)
		}
	})
	ip, _ := p.Offer(alice, netip.Addr{})
	p.Request(alice, ip)

	leases, err := LoadLeases(path)
	if err != nil || len(leases) != 1 || leases[0].Name != "alice-laptop" {
		t.Fatalf("leases=%+v err=%v", leases, err)
	}
	p2 := NewPool(p.cfg, leases, nil)
	p2.now = p.now
	if ip2, _ := p2.Offer(alice, netip.Addr{}); ip2 != ip {
		t.Errorf("после перезапуска: %v, want %v", ip2, ip)
	}
	if _, err := p2.Request(bob, ip); !errors.Is(err, errTaken) {
		t.Errorf("после перезапуска адрес alice занят: %v", err)
	}
	// Смена пула: аренды вне нового пула отбрасываются.
	cfg := p.cfg
	cfg.Start, cfg.End = a("192.168.3.200"), a("192.168.3.210")
	p2.Reconfigure(cfg)
	if len(p2.Leases()) != 0 {
		t.Errorf("аренды вне пула: %+v", p2.Leases())
	}
}

func TestZone(t *testing.T) {
	p, now := testPool(nil)
	p.now = func() time.Time { return *now }
	ip, _ := p.Offer(alice, netip.Addr{})
	z := NewZone(p, "LAN.")
	z.now = p.now
	if _, ok := z.LookupName("alice-laptop"); ok {
		t.Error("предложенный (не выданный) адрес не публикуется")
	}
	p.Request(alice, ip)
	if got, ok := z.LookupName("alice-laptop"); !ok || got != ip || z.Domain() != "lan" {
		t.Errorf("A: %v %v %q", got, ok, z.Domain())
	}
	if name, ok := z.LookupAddr(ip); !ok || name != "alice-laptop" {
		t.Errorf("PTR: %q %v", name, ok)
	}
	*now = t0.Add(48 * time.Hour)
	if _, ok := z.LookupName("alice-laptop"); ok {
		t.Error("истёкшая аренда не публикуется")
	}
}

func TestSanitizeName(t *testing.T) {
	for in, want := range map[string]string{
		"Alice-Laptop":     "alice-laptop",
		"iPhone (Bob)":     "iphone-bob",
		"host.example.com": "host",
		"--x--":            "x",
		"Пётр":             "",
		"":                 "",
	} {
		if got := sanitizeName(in); got != want {
			t.Errorf("%q → %q, want %q", in, got, want)
		}
	}
}

func TestNameStickyAcrossRelease(t *testing.T) {
	p, now := testPool(nil)
	ipA, _ := p.Offer(alice, netip.Addr{})
	p.Request(alice, ipA) // alice-laptop
	p.Release(alice, ipA)
	*now = t0.Add(time.Hour)
	ipB, _ := p.Offer(bob, netip.Addr{}) // тот же hostname «alice laptop»
	if l, _ := p.Request(bob, ipB); l.Name != "alice-laptop-2" {
		t.Errorf("имя освободившего адрес клиента ещё закреплено за ним: %q", l.Name)
	}
	if l, _ := p.Request(alice, ipA); l.Name != "alice-laptop" {
		t.Errorf("alice вернулась со своим именем: %q", l.Name)
	}
	// Через срок аренды после ухода имя освобождается.
	p.Release(alice, ipA)
	*now = now.Add(25 * time.Hour)
	if l, _ := p.Request(bob, ipB); l.Name != "alice-laptop" {
		t.Errorf("давно ушедший клиент не держит имя: %q", l.Name)
	}
}
