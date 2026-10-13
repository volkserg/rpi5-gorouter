package cli

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/volkserg/rpi5-gorouter/internal/services"
	"github.com/volkserg/rpi5-gorouter/internal/services/servicestest"
)

// testEnv — окружение с поддельным systemd; root по умолчанию.
func testEnv(dir string, fake *servicestest.Fake) (Env, *bytes.Buffer, *bytes.Buffer) {
	var o, e bytes.Buffer
	return Env{
		Stdout: &o, Stderr: &e, ConfigDir: dir,
		ProcRoot: filepath.Join(dir, "proc"),
		IsRoot:   func() bool { return true },
		Services: func(context.Context) (services.Manager, error) { return fake, nil },
	}, &o, &e
}

func run(t *testing.T, dir string, args ...string) (stdout, stderr string, code int) {
	t.Helper()
	env, o, e := testEnv(dir, servicestest.New())
	code = Run(env, args)
	return o.String(), e.String(), code
}

func writeFiles(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func TestHelpListsAllReferenceCommands(t *testing.T) {
	out, _, code := run(t, t.TempDir(), "help")
	if code != 0 {
		t.Fatal(code)
	}
	for _, c := range []string{"status", "info", "start", "stop", "restart", "apply-network", "logs",
		"add-vpn-domain", "remove-vpn-domain", "add-vpn-ip", "remove-vpn-ip", "list-vpn-domains",
		"load-vpn-domains", "load-vpn-ips", "reload-vpn-domains"} {
		if !strings.Contains(out, "  "+c+" ") {
			t.Errorf("в справке нет команды %s", c)
		}
	}
	if out2, _, _ := run(t, t.TempDir()); out2 != out {
		t.Error("вызов без аргументов должен печатать справку")
	}
}

func TestUnknownCommand(t *testing.T) {
	_, errOut, code := run(t, t.TempDir(), "frobnicate")
	if code != 1 || !strings.Contains(errOut, "Неизвестная команда: frobnicate") {
		t.Errorf("code=%d stderr=%q", code, errOut)
	}
}

func TestNotYetPorted(t *testing.T) {
	_, errOut, code := run(t, t.TempDir(), "apply-network")
	if code != 1 || !strings.Contains(errOut, "ещё не перенесена") {
		t.Errorf("code=%d stderr=%q", code, errOut)
	}
}

func TestInfo(t *testing.T) {
	dir := writeFiles(t, map[string]string{
		"router.conf":      "LAN_SUBNET=10.0.0.0/23\nROUTER_IP=10.0.0.1\nRPI5_IP=10.0.0.2\nLAN_POOL_START=10.0.1.10\nLAN_POOL_END=10.0.1.200\n",
		"vpn_domains.txt":  "intranet.com\n1.2.3.4\n10.0.0.0/8\nbad entry\n",
		"dns_override.txt": "corp.example.com 10.20.0.53\n",
	})
	out, _, code := run(t, dir, "info")
	if code != 0 {
		t.Fatal(code)
	}
	for _, want := range []string{
		"Подсеть LAN:        10.0.0.0/23",
		"Маска / broadcast:  255.255.254.0 / 10.0.1.255",
		"Пул DHCP:           10.0.1.10 - 10.0.1.200",
		"доменов: 1, IP/подсетей: 2, с ошибками: 1",
		"правил: 1",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("нет %q в выводе:\n%s", want, out)
		}
	}
	if strings.Contains(out, "\033[") {
		t.Error("цвета включены при Color=false")
	}
}

func TestInfoBadConfig(t *testing.T) {
	dir := writeFiles(t, map[string]string{"router.conf": "RPI5_IP=192.168.3.150\n"})
	_, errOut, code := run(t, dir, "info")
	if code != 1 || !strings.Contains(errOut, "попадает в пул") {
		t.Errorf("code=%d stderr=%q", code, errOut)
	}
}

func TestListVPN(t *testing.T) {
	dir := writeFiles(t, map[string]string{"vpn_domains.txt": "# c\nIntranet.com\n1.2.3.4/32\n5.6.7.8/24\n999.1.1.1\n"})
	out, _, code := run(t, dir, "list-vpn-domains")
	if code != 0 {
		t.Fatal(code)
	}
	for _, want := range []string{"DOMAIN: intranet.com", "IP: 1.2.3.4\n", "IP: 5.6.7.0/24", "ОШИБКА (строка 5)"} {
		if !strings.Contains(out, want) {
			t.Errorf("нет %q в выводе:\n%s", want, out)
		}
	}

	out, _, _ = run(t, t.TempDir(), "list-vpn-domains")
	if !strings.Contains(out, "Файл не найден.") {
		t.Errorf("got:\n%s", out)
	}
	out, _, _ = run(t, writeFiles(t, map[string]string{"vpn_domains.txt": "# только комментарий\n"}), "list-vpn-domains")
	if !strings.Contains(out, "(список пуст)") {
		t.Errorf("got:\n%s", out)
	}
}

func TestCheckConfig(t *testing.T) {
	ok := writeFiles(t, map[string]string{"vpn_domains.txt": "intranet.com\n", "dns_override.txt": "a.com 1.1.1.1#5353\n"})
	if out, _, code := run(t, ok, "check-config"); code != 0 {
		t.Errorf("code=%d\n%s", code, out)
	}

	bad := writeFiles(t, map[string]string{
		"router.conf":      "LAN_SUBNET=192.168.3.1/24\n",
		"vpn_domains.txt":  "999.1.1.1\n",
		"dns_override.txt": "a.com dns.google\n",
	})
	out, _, code := run(t, bad, "check-config")
	if code != 1 {
		t.Errorf("code=%d", code)
	}
	if strings.Count(out, "✗") != 3 {
		t.Errorf("ожидались ошибки во всех трёх файлах:\n%s", out)
	}
}
