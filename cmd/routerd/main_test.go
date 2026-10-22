package main

import (
	"net/netip"
	"testing"

	"github.com/volkserg/rpi5-gorouter/internal/config"
)

// Имя вызова и первое слово выбирают режим: неизвестная команда доходит до
// CLI (код 1, «Неизвестная команда»), а не до справки демона (код 2).
func TestDispatchToCLI(t *testing.T) {
	t.Setenv("ROUTERD_CONFIG_DIR", t.TempDir())
	for _, args := range [][]string{
		{"/usr/local/bin/rsc", "no-such-command"},
		{"/usr/local/bin/router_service_ctl", "no-such-command"},
		{"routerd", "no-such-command"},
		{"routerd", "ctl", "no-such-command"},
	} {
		if rc := run(args); rc != 1 {
			t.Errorf("%v: код %d, ожидался 1 (команда CLI)", args, rc)
		}
	}
	if rc := run([]string{"routerd"}); rc != 2 {
		t.Errorf("routerd без аргументов: код %d, ожидался 2", rc)
	}
	for _, args := range [][]string{{"/usr/local/bin/rsc", "help"}, {"routerd", "help"}, {"routerd", "check-config"}} {
		if rc := run(args); rc != 0 {
			t.Errorf("%v: код %d, ожидался 0", args, rc)
		}
	}
}

func TestAllowWeb(t *testing.T) {
	cfg, err := config.FromValues(map[string]string{"LOCAL_CLIENTS": "app:10.99.0.0/30"})
	if err != nil {
		t.Fatal(err)
	}
	allow := allowWeb(cfg)
	for a, want := range map[string]bool{
		"192.168.3.50": true, "10.99.0.2": true, "127.0.0.1": true,
		"fe80::1": true, "fd12:3456::1": true,
		"203.0.113.5": false, "2001:db8::5": false, "192.168.4.1": false,
	} {
		if got := allow(netip.MustParseAddr(a)); got != want {
			t.Errorf("%s: %v, ожидалось %v", a, got, want)
		}
	}
}
