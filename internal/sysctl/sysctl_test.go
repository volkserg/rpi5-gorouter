package sysctl

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func setup(t *testing.T, values map[string]string) string {
	t.Helper()
	root := t.TempDir()
	for k, v := range values {
		p := filepath.Join(root, "sys", strings.ReplaceAll(k, ".", "/"))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(v+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func TestApplyWritesOnlyDifferences(t *testing.T) {
	root := setup(t, map[string]string{
		"net.ipv4.ip_forward":                 "0",
		"net.ipv4.conf.all.send_redirects":    "0",
		"net.ipv4.conf.eth0.send_redirects":   "1",
		"net.ipv4.conf.all.proxy_arp":         "0",
		"net.ipv4.conf.all.rp_filter":         "1",
		"net.ipv4.conf.all.accept_redirects":  "1",
		"net.ipv4.conf.eth0.accept_redirects": "0",
	})
	changed, err := Apply(root, Router("eth0"))
	if err != nil {
		t.Fatal(err)
	}
	want := "net.ipv4.ip_forward,net.ipv4.conf.all.accept_redirects,net.ipv4.conf.eth0.send_redirects"
	if strings.Join(changed, ",") != want {
		t.Errorf("changed = %v", changed)
	}
	b, _ := os.ReadFile(filepath.Join(root, "sys/net/ipv4/conf/eth0/send_redirects"))
	if strings.TrimSpace(string(b)) != "0" {
		t.Errorf("eth0.send_redirects = %q", b)
	}
	if changed, _ := Apply(root, Router("eth0")); len(changed) != 0 {
		t.Errorf("повторный Apply ничего не должен менять: %v", changed)
	}
}

func TestApplyReadOnlyButAlreadySet(t *testing.T) {
	root := setup(t, map[string]string{"net.ipv4.ip_forward": "1"})
	p := filepath.Join(root, "sys/net/ipv4/ip_forward")
	if err := os.Chmod(p, 0o444); err != nil {
		t.Fatal(err)
	}
	if _, err := Apply(root, []Setting{{"net.ipv4.ip_forward", "1"}}); err != nil {
		t.Errorf("значение уже нужное — не ошибка: %v", err)
	}
	if _, err := Apply(root, []Setting{{"net.ipv4.conf.missing.x", "1"}}); err == nil {
		t.Error("отсутствующий параметр — ошибка")
	}
}
