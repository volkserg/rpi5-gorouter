package main

import "testing"

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
