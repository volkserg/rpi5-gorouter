package cli

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/volkserg/rpi5-gorouter/internal/services"
	"github.com/volkserg/rpi5-gorouter/internal/services/servicestest"
)

var stack = []string{
	services.UnitDNSCryptSocket, services.UnitDNSCrypt, services.UnitPihole,
	services.UnitRouterd, services.DefaultUnitGost,
}

func TestStartStopRestart(t *testing.T) {
	f := servicestest.New(stack...)
	out, _, code := runFake(t.TempDir(), f, "start")
	if code != 0 || !strings.Contains(out, "router_service запущен.") {
		t.Fatalf("code=%d out=%q", code, out)
	}
	for _, u := range stack {
		if !f.Units[u].Running() {
			t.Errorf("%s не запущен", u)
		}
	}

	f.Calls = nil
	out, _, code = runFake(t.TempDir(), f, "restart")
	calls := strings.Join(f.Calls, ",")
	if code != 0 || !strings.HasPrefix(calls, "stop gost-run.service,stop routerd.service,start ") {
		t.Errorf("code=%d calls=%s out=%q", code, calls, out)
	}
}

func TestStartFailsWhenRouterdFails(t *testing.T) {
	f := servicestest.New(stack...)
	f.Fail[services.UnitRouterd] = true
	_, errOut, code := runFake(t.TempDir(), f, "start")
	if code != 1 || !strings.Contains(errOut, "routerd.service") {
		t.Errorf("code=%d err=%q", code, errOut)
	}
}

func TestStatus(t *testing.T) {
	dir := writeFiles(t, map[string]string{"vpn_domains.txt": "intranet.com\n1.2.3.4\n"})
	proc := filepath.Join(dir, "proc")
	must := func(err error) {
		if err != nil {
			t.Fatal(err)
		}
	}
	must(os.MkdirAll(filepath.Join(proc, "net"), 0o755))
	must(os.MkdirAll(filepath.Join(proc, "sys", "net", "ipv4"), 0o755))
	must(os.WriteFile(filepath.Join(proc, "sys", "net", "ipv4", "ip_forward"), []byte("1\n"), 0o644))
	// Слушают :53 (0x35) и :1080 (0x438) по TCP.
	must(os.WriteFile(filepath.Join(proc, "net", "tcp"), []byte(
		"  sl local_address rem_address st\n"+
			"   0: 0203A8C0:0035 00000000:0000 0A\n"+
			"   1: 00000000:0438 00000000:0000 0A\n"), 0o644))

	f := servicestest.New(services.UnitRouterd, services.UnitPihole)
	f.SetActive(services.UnitRouterd)
	f.Status[services.UnitRouterd] = "работает: режим tproxy, туннель доступен"
	out, _, code := runFake(dir, f, "status")
	if code != 0 {
		t.Fatal(code)
	}
	for _, want := range []string{
		"● routerd — запущен", "      работает: режим tproxy, туннель доступен", "○ pihole-FTL — остановлен", "? gost-run — не установлен",
		"IP forwarding: 1",
		":53    routerd        ● слушается",
		":5353  Pi-hole        ○ не слушается",
		":1080  GOST           ● слушается",
		"доменов 1, IP/подсетей 1",
		":67    routerd        ○ не слушается",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("нет %q:\n%s", want, out)
		}
	}
}

func TestStatusWithoutSystemd(t *testing.T) {
	env, o, _ := testEnv(t.TempDir(), nil)
	env.Services = func(context.Context) (services.Manager, error) { return nil, errors.New("нет шины") }
	if code := Run(env, []string{"status"}); code != 0 {
		t.Fatal(code)
	}
	if !strings.Contains(o.String(), "systemd недоступен: нет шины") || !strings.Contains(o.String(), "IP forwarding: N/A") ||
		!strings.Contains(o.String(), ":53    routerd        ? N/A") {
		t.Errorf("out:\n%s", o.String())
	}
}

func TestLogs(t *testing.T) {
	env, o, _ := testEnv(t.TempDir(), nil)
	var units []string
	env.Journal = func(_ context.Context, w io.Writer, unit string, lines int) error {
		units = append(units, unit)
		if unit == services.DefaultUnitGost {
			return errors.New("exit status 1")
		}
		_, err := io.WriteString(w, "line from "+unit+"\n")
		return err
	}
	if code := Run(env, []string{"logs"}); code != 0 {
		t.Fatal(code)
	}
	if strings.Join(units, ",") != "routerd.service,gost-run.service,dnscrypt-proxy.service,pihole-FTL.service" {
		t.Errorf("units: %v", units)
	}
	if !strings.Contains(o.String(), "--- systemd (routerd) ---\nline from routerd.service") || !strings.Contains(o.String(), "Нет логов") {
		t.Errorf("out:\n%s", o.String())
	}
}

// Юнит клиента туннеля задаётся в router.conf (VPN_SERVICE).
func TestVPNServiceFromConfig(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "router.conf"), []byte("VPN_SERVICE=vpn-client\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	f := servicestest.New(services.UnitDNSCryptSocket, services.UnitDNSCrypt, services.UnitPihole,
		services.UnitRouterd, "vpn-client.service")
	if _, _, code := runFake(dir, f, "start"); code != 0 || !f.Units["vpn-client.service"].Running() {
		t.Fatalf("start: code=%d calls=%v", code, f.Calls)
	}
	f.Calls = nil
	runFake(dir, f, "stop")
	if got := strings.Join(f.Calls, ","); got != "stop vpn-client.service,stop routerd.service" {
		t.Errorf("stop: %s", got)
	}
	if out, _, _ := runFake(dir, f, "status"); !strings.Contains(out, "vpn-client") {
		t.Errorf("status без vpn-client:\n%s", out)
	}
}

// restart без юнита туннеля оставляет routerd запущенным.
func TestRestartWithoutTunnelUnit(t *testing.T) {
	f := servicestest.New(services.UnitDNSCryptSocket, services.UnitDNSCrypt, services.UnitPihole, services.UnitRouterd)
	f.SetActive(services.UnitRouterd)
	out, errOut, code := runFake(t.TempDir(), f, "restart")
	if code != 0 || !f.Units[services.UnitRouterd].Running() {
		t.Errorf("code=%d routerd=%v\n%s%s", code, f.Units[services.UnitRouterd], out, errOut)
	}
}

// Остановка не удалась — restart всё равно запускает стек.
func TestRestartStartsAfterStopFailure(t *testing.T) {
	f := servicestest.New(stack...)
	f.SetActive(services.UnitRouterd)
	f.Fail[services.DefaultUnitGost] = true
	_, _, code := runFake(t.TempDir(), f, "restart")
	if code == 0 || !f.Units[services.UnitRouterd].Running() {
		t.Errorf("code=%d, routerd должен работать: %v", code, f.Units[services.UnitRouterd])
	}
}

func TestStatusLocalClients(t *testing.T) {
	dir := writeFiles(t, map[string]string{"router.conf": "LOCAL_CLIENTS=\"app:10.99.0.0/30 web:10.99.0.4/30\"\n"})
	f := servicestest.New(services.LocalUnit("app"))
	f.SetActive(services.LocalUnit("app"))
	out, _, code := runFake(dir, f, "status")
	if code != 0 {
		t.Fatal(code)
	}
	for _, want := range []string{
		"Локальные сервисы (LOCAL_CLIENTS):",
		"● routerd-local@app — запущен",
		"      10.99.0.2/30, шлюз 10.99.0.1 (rc-app), /run/netns/app:",
		"? routerd-local@web — не установлен",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("нет %q:\n%s", want, out)
		}
	}
}
