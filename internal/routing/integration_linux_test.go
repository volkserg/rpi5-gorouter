//go:build linux && integration

// Интеграционные тесты policy routing в отдельном network namespace (root).
package routing

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"

	"github.com/volkserg/rpi5-gorouter/internal/firewall"
)

func testNS(t *testing.T) (*netlink.Handle, func(args ...string) string) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("нужен root")
	}
	name := fmt.Sprintf("routerd-rt-%d", os.Getpid())
	if out, err := exec.Command("ip", "netns", "add", name).CombinedOutput(); err != nil {
		t.Fatalf("ip netns add: %v: %s", err, out)
	}
	t.Cleanup(func() { _ = exec.Command("ip", "netns", "del", name).Run() })
	ns, err := netns.GetFromName(name)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ns.Close() })
	h, err := netlink.NewHandleAt(ns)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(h.Close)
	run := func(args ...string) string {
		t.Helper()
		out, err := exec.Command("ip", append([]string{"netns", "exec", name}, args...)...).CombinedOutput()
		if err != nil {
			t.Fatalf("%v: %v: %s", args, err, out)
		}
		return string(out)
	}
	run("ip", "link", "set", "lo", "up")
	return h, run
}

func TestTProxyPolicy(t *testing.T) {
	h, run := testNS(t)
	if _, err := Apply(h, Policy{Mode: firewall.ModeTProxy}); err != nil {
		t.Fatal(err)
	}
	if _, err := Apply(h, Policy{Mode: firewall.ModeTProxy}); err != nil {
		t.Fatalf("повторное применение: %v", err)
	}
	rules := run("ip", "rule")
	if strings.Count(rules, "fwmark 0x52 lookup 152") != 1 {
		t.Errorf("ip rule:\n%s", rules)
	}
	if out := run("ip", "route", "show", "table", "152"); !strings.Contains(out, "local default dev lo") {
		t.Errorf("таблица 152:\n%s", out)
	}
}

func TestRoutePolicyFollowsTun(t *testing.T) {
	h, run := testNS(t)
	up, err := Apply(h, Policy{Mode: firewall.ModeRoute, Tun: "tun0"})
	if err != nil || up {
		t.Fatalf("up=%v err=%v", up, err)
	}
	out := run("ip", "route", "show", "table", "152")
	if !strings.Contains(out, "unreachable default metric 4096") || strings.Contains(out, "dev tun0") {
		t.Errorf("без туннеля — только unreachable:\n%s", out)
	}

	run("ip", "tuntap", "add", "tun0", "mode", "tun")
	run("ip", "link", "set", "tun0", "up")
	if up, err = Apply(h, Policy{Mode: firewall.ModeRoute, Tun: "tun0"}); err != nil || !up {
		t.Fatalf("up=%v err=%v", up, err)
	}
	out = run("ip", "route", "show", "table", "152")
	if !strings.Contains(out, "default dev tun0") || !strings.Contains(out, "unreachable default metric 4096") {
		t.Errorf("с туннелем:\n%s", out)
	}

	// Смена режима на tproxy убирает маршруты route.
	if _, err := Apply(h, Policy{Mode: firewall.ModeTProxy}); err != nil {
		t.Fatal(err)
	}
	if out := run("ip", "route", "show", "table", "152"); strings.Contains(out, "tun0") || strings.Contains(out, "unreachable") {
		t.Errorf("после смены режима:\n%s", out)
	}
}

func TestBypassAndRemove(t *testing.T) {
	h, run := testNS(t)
	if _, err := Apply(h, Policy{Mode: firewall.ModeRoute, Tun: "tun0"}); err != nil {
		t.Fatal(err)
	}
	if _, err := Apply(h, Policy{Mode: firewall.ModeRoute, Tun: "tun0", Bypass: true}); err != nil {
		t.Fatal(err)
	}
	if out := run("ip", "rule"); strings.Contains(out, "lookup 152") {
		t.Errorf("при снятом перехвате правила быть не должно:\n%s", out)
	}
	if _, err := Apply(h, Policy{Mode: firewall.ModeTProxy}); err != nil {
		t.Fatal(err)
	}
	if err := Remove(h); err != nil {
		t.Fatal(err)
	}
	if out := run("ip", "rule"); strings.Contains(out, "lookup 152") {
		t.Errorf("Remove оставил правило:\n%s", out)
	}
	if out := run("ip", "route", "show", "table", "152"); strings.TrimSpace(out) != "" {
		t.Errorf("Remove оставил маршруты:\n%s", out)
	}
}
