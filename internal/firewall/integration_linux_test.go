//go:build linux && integration

// Интеграционные тесты: настоящий nftables в отдельном network namespace.
// Нужны root и утилиты ip/nft (только для подготовки и проверки — сам
// routerd их не вызывает). Запуск на стенде:
//
//	GOOS=linux GOARCH=arm64 go test -c -tags integration -o fw.test ./internal/firewall
//	orb -m routerd-lab sudo ./fw.test -test.v
package firewall

import (
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/google/nftables"
)

// testNS создаёт namespace и возвращает Conn в нём и функцию выполнения команд.
func testNS(t *testing.T) (*nftables.Conn, func(args ...string) string) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("нужен root")
	}
	name := fmt.Sprintf("routerd-it-%d", os.Getpid())
	if out, err := exec.Command("ip", "netns", "add", name).CombinedOutput(); err != nil {
		t.Fatalf("ip netns add: %v: %s", err, out)
	}
	t.Cleanup(func() { _ = exec.Command("ip", "netns", "del", name).Run() })

	f, err := os.Open("/run/netns/" + name)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.Close() })
	c, err := nftables.New(nftables.WithNetNSFd(int(f.Fd())))
	if err != nil {
		t.Fatal(err)
	}
	run := func(args ...string) string {
		t.Helper()
		out, err := exec.Command("ip", append([]string{"netns", "exec", name}, args...)...).CombinedOutput()
		if err != nil {
			t.Fatalf("%v: %v: %s", args, err, out)
		}
		return string(out)
	}
	return c, run
}

func spec(static ...string) Spec {
	s := Spec{
		Iface:          "eth0",
		LAN:            netip.MustParsePrefix("192.168.3.0/24"),
		RedirectPort:   1080,
		QUICReject:     true,
		DynamicTimeout: 24 * time.Hour,
		Mode:           ModeRedirect,
	}
	for _, p := range static {
		s.Static = append(s.Static, netip.MustParsePrefix(p))
	}
	return s
}

func mustContain(t *testing.T, out string, want ...string) {
	t.Helper()
	for _, w := range want {
		if !strings.Contains(out, w) {
			t.Errorf("нет %q в:\n%s", w, out)
		}
	}
}

func TestApplyRedirectMode(t *testing.T) {
	c, run := testNS(t)
	if _, err := Apply(c, spec("10.20.0.0/16", "10.20.5.0/24", "192.0.2.10/32")); err != nil {
		t.Fatal(err)
	}
	out := run("nft", "list", "table", "ip", TableName)
	mustContain(t, out,
		"set vpn_static", "flags interval", "10.20.0.0/16", "192.0.2.10",
		"set vpn_dynamic", "timeout 1d",
		`iifname "eth0" meta l4proto tcp ip daddr @vpn_static counter`,
		`ip daddr @vpn_dynamic counter`, "redirect to :1080",
		"ip saddr 192.168.3.0/24 ip daddr != 192.168.3.0/24 counter", "masquerade",
		`iifname "eth0" udp dport 443 ip daddr @vpn_static counter`,
		`iifname "eth0" udp dport 443 ip daddr @vpn_dynamic counter`,
		"reject",
	)
	if strings.Contains(out, "10.20.5.0/24") {
		t.Error("вложенная подсеть должна слиться с 10.20.0.0/16")
	}
}

func TestReapplyKeepsDynamic(t *testing.T) {
	c, run := testNS(t)
	if _, err := Apply(c, spec("10.20.0.0/16")); err != nil {
		t.Fatal(err)
	}
	run("nft", "add", "element", "ip", TableName, SetDynamic, "{ 198.51.100.77 }")

	recreated, err := Apply(c, spec("172.16.0.0/12"))
	if err != nil || recreated {
		t.Fatalf("recreated=%v err=%v", recreated, err)
	}
	out := run("nft", "list", "table", "ip", TableName)
	mustContain(t, out, "172.16.0.0/12", "198.51.100.77")
	if strings.Contains(out, "10.20.0.0/16") {
		t.Error("старые статические записи должны быть заменены")
	}
	// Правила не дублируются при повторном применении.
	if n := strings.Count(out, "redirect to :1080"); n != 2 {
		t.Errorf("правил redirect: %d, want 2", n)
	}
}

func TestReapplyIncompatibleRecreates(t *testing.T) {
	c, run := testNS(t)
	if _, err := Apply(c, spec()); err != nil {
		t.Fatal(err)
	}
	s := spec()
	s.DynamicTimeout = time.Hour
	recreated, err := Apply(c, s)
	if err != nil {
		t.Fatal(err)
	}
	out := run("nft", "list", "set", "ip", TableName, SetDynamic)
	t.Logf("recreated=%v\n%s", recreated, out)
	if !recreated || !strings.Contains(out, "timeout 1h") {
		t.Error("смена таймаута vpn_dynamic должна пересоздавать таблицу")
	}
}

func TestQUICRejectOff(t *testing.T) {
	c, run := testNS(t)
	s := spec()
	s.QUICReject = false
	if _, err := Apply(c, s); err != nil {
		t.Fatal(err)
	}
	if out := run("nft", "list", "table", "ip", TableName); strings.Contains(out, "reject") {
		t.Errorf("reject при QUICReject=false:\n%s", out)
	}
}

func TestRemove(t *testing.T) {
	c, run := testNS(t)
	if err := Remove(c); err != nil {
		t.Fatalf("удаление несуществующей таблицы: %v", err)
	}
	if _, err := Apply(c, spec()); err != nil {
		t.Fatal(err)
	}
	if err := Remove(c); err != nil {
		t.Fatal(err)
	}
	if out := run("nft", "list", "tables"); strings.Contains(out, TableName) {
		t.Errorf("таблица осталась:\n%s", out)
	}
}

func TestApplyTProxyMode(t *testing.T) {
	c, run := testNS(t)
	s := spec("10.20.0.0/16")
	s.Mode = ModeTProxy
	if _, err := Apply(c, s); err != nil {
		t.Fatal(err)
	}
	out := run("nft", "list", "chain", "ip", TableName, chainMangle)
	mustContain(t, out,
		"type filter hook prerouting priority mangle",
		"meta l4proto tcp socket transparent 1 meta mark set 0x00000052 accept",
		`iifname "eth0" udp dport 443 return`,
		`iifname "eth0" meta l4proto tcp ip daddr @vpn_static counter`,
		`iifname "eth0" meta l4proto udp ip daddr @vpn_dynamic counter`,
		"tproxy to :1080 meta mark set 0x00000052 accept",
		// Запасное правило без tproxy: туннель упал — пакет не уходит напрямую.
		`iifname "eth0" meta l4proto tcp ip daddr @vpn_static meta mark set 0x00000052`,
	)
	if out := run("nft", "list", "chain", "ip", TableName, chainPrerouting); strings.Contains(out, "redirect") {
		t.Errorf("в режиме tproxy redirect не нужен:\n%s", out)
	}
}

func TestApplyRouteMode(t *testing.T) {
	c, run := testNS(t)
	s := spec("10.20.0.0/16")
	s.Mode, s.Tun = ModeRoute, "tun0"
	if _, err := Apply(c, s); err != nil {
		t.Fatal(err)
	}
	out := run("nft", "list", "table", "ip", TableName)
	mustContain(t, out,
		`iifname "eth0" ct state new ip daddr @vpn_static counter`, "ct mark set 0x00000052",
		`iifname "eth0" ct mark 0x00000052 meta mark set 0x00000052`,
		`oifname "tun0" tcp flags syn tcp option maxseg size set rt mtu`,
		`udp dport 443 ip daddr @vpn_dynamic counter`,
	)
	if strings.Contains(out, "redirect") || strings.Contains(out, "tproxy") {
		t.Errorf("в режиме route нет redirect/tproxy:\n%s", out)
	}
}

func TestBypass(t *testing.T) {
	c, run := testNS(t)
	for _, mode := range []Mode{ModeRedirect, ModeTProxy, ModeRoute} {
		s := spec("10.20.0.0/16")
		s.Mode, s.Tun, s.Bypass = mode, "tun0", true
		if _, err := Apply(c, s); err != nil {
			t.Fatal(mode, err)
		}
		out := run("nft", "list", "table", "ip", TableName)
		for _, banned := range []string{"redirect", "tproxy", "ct mark set"} {
			if strings.Contains(out, banned) {
				t.Errorf("%s, перехват снят, но есть %q:\n%s", mode, banned, out)
			}
		}
		// NAT, set'ы и QUIC-reject остаются.
		mustContain(t, out, "masquerade", "10.20.0.0/16", "reject")
	}
}

func TestDynamicLearn(t *testing.T) {
	c, run := testNS(t)
	if _, err := Apply(c, spec()); err != nil {
		t.Fatal(err)
	}
	d := newDynamic(c, 30*time.Second, nil)

	// TTL меньше нижней границы — срок 30s; больше — по TTL.
	d.Learn([]netip.Addr{netip.MustParseAddr("203.0.113.20")}, 5*time.Second)
	d.Learn([]netip.Addr{netip.MustParseAddr("203.0.113.21")}, 2*time.Minute)
	out := run("nft", "list", "set", "ip", TableName, SetDynamic)
	mustContain(t, out, "203.0.113.20 timeout 30s", "203.0.113.21 timeout 2m")

	// Повторный ответ скоро после первого — без изменений (срок не тронут).
	d.Learn([]netip.Addr{netip.MustParseAddr("203.0.113.20")}, 5*time.Second)

	// Срок подходит к концу — продлевается, с новым большим TTL.
	d.now = func() time.Time { return time.Now().Add(20 * time.Second) }
	d.Learn([]netip.Addr{netip.MustParseAddr("203.0.113.20")}, 10*time.Minute)
	out = run("nft", "list", "set", "ip", TableName, SetDynamic)
	mustContain(t, out, "203.0.113.20 timeout 10m")

	// После Reset (таблица пересоздана) адрес добавляется снова.
	if _, err := Apply(c, spec()); err != nil {
		t.Fatal(err)
	}
	run("nft", "flush", "set", "ip", TableName, SetDynamic)
	d.Reset()
	d.Learn([]netip.Addr{netip.MustParseAddr("203.0.113.20")}, time.Minute)
	mustContain(t, run("nft", "list", "set", "ip", TableName, SetDynamic), "203.0.113.20 timeout 1m")
}
