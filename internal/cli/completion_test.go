package cli

import (
	"bytes"
	"strings"
	"testing"
)

func TestCompletionListsAllCommands(t *testing.T) {
	for _, shell := range []string{"bash", "zsh"} {
		var b bytes.Buffer
		if err := Completion(&b, shell); err != nil {
			t.Fatal(err)
		}
		out := b.String()
		for _, c := range commands {
			if c.name != "" && !strings.Contains(out, c.name) {
				t.Errorf("%s: нет команды %s", shell, c.name)
			}
		}
		for _, want := range []string{"--dry-run", "--confirm", "--rollback", "/usr/local/etc/router_service/vpn_domains.txt"} {
			if !strings.Contains(out, want) {
				t.Errorf("%s: нет %q", shell, want)
			}
		}
		if strings.Contains(out, "%!") {
			t.Errorf("%s: ошибка форматирования:\n%s", shell, out)
		}
	}
	if err := Completion(&bytes.Buffer{}, "fish"); err == nil {
		t.Error("fish: ожидалась ошибка")
	}
}
