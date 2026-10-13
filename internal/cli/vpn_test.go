package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/volkserg/rpi5-gorouter/internal/services"
	"github.com/volkserg/rpi5-gorouter/internal/services/servicestest"
)

func readList(t *testing.T, dir string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, "vpn_domains.txt"))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func runFake(dir string, f *servicestest.Fake, args ...string) (string, string, int) {
	env, o, e := testEnv(dir, f)
	code := Run(env, args)
	return o.String(), e.String(), code
}

func TestAddRemoveDomainReloadsRouterd(t *testing.T) {
	dir := writeFiles(t, map[string]string{"vpn_domains.txt": "# список\nintranet.com\n"})
	f := servicestest.New(services.UnitRouterd)
	f.SetActive(services.UnitRouterd)

	out, _, code := runFake(dir, f, "add-vpn-domain", "Partner.com")
	if code != 0 || !strings.Contains(out, "Домен 'partner.com' добавлен в список VPN. (записан как partner.com)") {
		t.Fatalf("code=%d out=%q", code, out)
	}
	if readList(t, dir) != "# список\nintranet.com\npartner.com\n" {
		t.Errorf("файл: %q", readList(t, dir))
	}
	if strings.Join(f.Calls, ",") != "reload routerd.service" {
		t.Errorf("calls: %v", f.Calls)
	}

	out, _, _ = runFake(dir, f, "add-vpn-domain", "partner.com")
	if !strings.Contains(out, "уже в списке") || len(f.Calls) != 1 {
		t.Errorf("повторное добавление: out=%q calls=%v", out, f.Calls)
	}

	out, _, code = runFake(dir, f, "remove-vpn-domain", "intranet.com")
	if code != 0 || !strings.Contains(out, "удалён из списка VPN") || readList(t, dir) != "# список\npartner.com\n" {
		t.Errorf("remove: code=%d out=%q file=%q", code, out, readList(t, dir))
	}

	out, _, _ = runFake(dir, f, "remove-vpn-domain", "intranet.com")
	if !strings.Contains(out, "не найден в списке") {
		t.Errorf("remove absent: %q", out)
	}
}

func TestAddDomainRejectsIP(t *testing.T) {
	dir := t.TempDir()
	_, errOut, code := runFake(dir, servicestest.New(), "add-vpn-domain", "1.2.3.4")
	if code != 1 || !strings.Contains(errOut, "Используйте 'add-vpn-ip'") {
		t.Errorf("code=%d err=%q", code, errOut)
	}
	_, errOut, code = runFake(dir, servicestest.New(), "add-vpn-ip", "intranet.com")
	if code != 1 || !strings.Contains(errOut, "не является валидным IP-адресом или CIDR") {
		t.Errorf("code=%d err=%q", code, errOut)
	}
	out, errOut, code := runFake(dir, servicestest.New(), "add-vpn-domain")
	if code != 1 || !strings.Contains(errOut, "укажите домен") || !strings.Contains(out, "Использование") {
		t.Errorf("без аргумента: code=%d err=%q", code, errOut)
	}
}

func TestAddIPNormalizesAndCreatesFile(t *testing.T) {
	dir := t.TempDir()
	f := servicestest.New(services.UnitRouterd) // routerd остановлен
	out, _, code := runFake(dir, f, "add-vpn-ip", "10.1.2.3/16")
	if code != 0 || !strings.Contains(out, "IP/CIDR '10.1.0.0/16' добавлен") || !strings.Contains(out, "routerd не запущен") {
		t.Errorf("code=%d out=%q", code, out)
	}
	if readList(t, dir) != "10.1.0.0/16\n" {
		t.Errorf("файл: %q", readList(t, dir))
	}
	if len(f.Calls) != 0 {
		t.Errorf("остановленный routerd не перезагружают: %v", f.Calls)
	}
}

func TestMutationRequiresRoot(t *testing.T) {
	dir := writeFiles(t, map[string]string{"vpn_domains.txt": "intranet.com\n"})
	env, _, e := testEnv(dir, servicestest.New())
	env.IsRoot = func() bool { return false }
	for _, args := range [][]string{
		{"add-vpn-domain", "a.com"}, {"remove-vpn-domain", "intranet.com"}, {"add-vpn-ip", "1.1.1.1"},
		{"reload-vpn-domains"}, {"start"}, {"stop"}, {"restart"},
	} {
		e.Reset()
		if code := Run(env, args); code != 1 || !strings.Contains(e.String(), "требуется root") {
			t.Errorf("%v: code=%d err=%q", args, code, e.String())
		}
	}
	if readList(t, dir) != "intranet.com\n" {
		t.Error("без root файл меняться не должен")
	}
}

func TestLoadDomains(t *testing.T) {
	dir := writeFiles(t, map[string]string{
		"vpn_domains.txt": "intranet.com\n",
		"src.txt":         "# импорт\nintranet.com\npartner.com\npartner.com\n1.2.3.4\nbad entry\n",
	})
	f := servicestest.New(services.UnitRouterd)
	f.SetActive(services.UnitRouterd)
	out, _, code := runFake(dir, f, "load-vpn-domains", filepath.Join(dir, "src.txt"))
	for _, want := range []string{
		"Пропущено (IP/CIDR, используйте load-vpn-ips): 1.2.3.4",
		"Пропущено (строка 6)",
		"Обработано доменов: 3", "Добавлено доменов: 1", "Пропущено (уже есть): 2",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("нет %q:\n%s", want, out)
		}
	}
	if code != 0 || readList(t, dir) != "intranet.com\npartner.com\n" || len(f.Calls) != 1 {
		t.Errorf("code=%d file=%q calls=%v", code, readList(t, dir), f.Calls)
	}

	// Повторная загрузка ничего не добавляет и не перезагружает routerd.
	out, _, _ = runFake(dir, f, "load-vpn-domains", filepath.Join(dir, "src.txt"))
	if !strings.Contains(out, "Новых записей нет") || len(f.Calls) != 1 {
		t.Errorf("out=%q calls=%v", out, f.Calls)
	}

	_, errOut, code := runFake(dir, f, "load-vpn-ips", filepath.Join(dir, "missing.txt"))
	if code != 1 || !strings.Contains(errOut, "не найден") {
		t.Errorf("code=%d err=%q", code, errOut)
	}
}

func TestReload(t *testing.T) {
	dir := t.TempDir()
	f := servicestest.New(services.UnitRouterd)
	f.SetActive(services.UnitRouterd)
	out, _, code := runFake(dir, f, "reload-vpn-domains")
	if code != 0 || !strings.Contains(out, "перезагружен") || f.Calls[0] != "reload routerd.service" {
		t.Errorf("code=%d out=%q calls=%v", code, out, f.Calls)
	}

	f.Fail[services.UnitRouterd] = true
	_, errOut, code := runFake(dir, f, "reload-vpn-domains")
	if code != 1 || !strings.Contains(errOut, "Ошибка применения") {
		t.Errorf("code=%d err=%q", code, errOut)
	}
}
