package cli

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/godbus/dbus/v5"

	"github.com/volkserg/rpi5-gorouter/internal/netcfg"
	"github.com/volkserg/rpi5-gorouter/internal/services"
	"github.com/volkserg/rpi5-gorouter/internal/services/servicestest"
)

type cliNM struct {
	ip4         map[string]dbus.Variant
	checkpoints []dbus.ObjectPath
	calls       []string
}

func (f *cliNM) DeviceByIface(context.Context, string) (dbus.ObjectPath, error) { return "/d", nil }
func (f *cliNM) Connections(context.Context) ([]dbus.ObjectPath, error) {
	return []dbus.ObjectPath{"/c"}, nil
}
func (f *cliNM) GetSettings(context.Context, dbus.ObjectPath) (netcfg.Settings, error) {
	return netcfg.Settings{
		"connection": {"id": dbus.MakeVariant("netplan-eth0"), "type": dbus.MakeVariant("802-3-ethernet")},
		"ipv4":       f.ip4,
	}, nil
}
func (f *cliNM) UpdateSettings(_ context.Context, _ dbus.ObjectPath, s netcfg.Settings) error {
	f.calls = append(f.calls, "update")
	f.ip4 = s["ipv4"]
	return nil
}
func (f *cliNM) Save(context.Context, dbus.ObjectPath) error {
	f.calls = append(f.calls, "save")
	return nil
}
func (f *cliNM) Activate(context.Context, dbus.ObjectPath, dbus.ObjectPath) error {
	f.calls = append(f.calls, "activate")
	return nil
}
func (f *cliNM) CheckpointCreate(context.Context, dbus.ObjectPath, time.Duration) (dbus.ObjectPath, error) {
	f.checkpoints = []dbus.ObjectPath{"/cp"}
	return "/cp", nil
}
func (f *cliNM) CheckpointDestroy(context.Context, dbus.ObjectPath) error {
	f.calls = append(f.calls, "destroy")
	f.checkpoints = nil
	return nil
}
func (f *cliNM) CheckpointRollback(context.Context, dbus.ObjectPath) error {
	f.calls = append(f.calls, "rollback")
	f.checkpoints = nil
	return nil
}
func (f *cliNM) Checkpoints(context.Context, dbus.ObjectPath) ([]dbus.ObjectPath, error) {
	return f.checkpoints, nil
}

func nmEnv(t *testing.T, nm *cliNM, f *servicestest.Fake) (Env, func() (string, string)) {
	env, o, e := testEnv(t.TempDir(), f)
	env.NM = func() (netcfg.NM, func(), error) { return nm, func() {}, nil }
	return env, func() (string, string) { return o.String(), e.String() }
}

func TestApplyNetwork(t *testing.T) {
	nm := &cliNM{ip4: map[string]dbus.Variant{"method": dbus.MakeVariant("auto")}}
	f := servicestest.New(services.UnitRouterd)
	f.SetActive(services.UnitRouterd)

	env, out := nmEnv(t, nm, f)
	if code := Run(env, []string{"apply-network", "--dry-run"}); code != 0 {
		t.Fatal(code)
	}
	o, _ := out()
	if !strings.Contains(o, "ipv4.method: auto → manual") || !strings.Contains(o, "ipv4.address: (нет) → 192.168.3.2/24") ||
		!strings.Contains(o, "dry-run") || len(nm.calls) != 0 {
		t.Errorf("dry-run:\n%s calls=%v", o, nm.calls)
	}

	env, out = nmEnv(t, nm, f)
	if code := Run(env, []string{"apply-network"}); code != 0 {
		_, e := out()
		t.Fatalf("code=%d err=%s", code, e)
	}
	o, _ = out()
	if !strings.Contains(o, "apply-network --confirm") || strings.Join(nm.calls, ",") != "update,activate" {
		t.Errorf("apply:\n%s calls=%v", o, nm.calls)
	}
	if f.Calls[len(f.Calls)-1] != "reload routerd.service" {
		t.Errorf("routerd должен перечитать конфиг: %v", f.Calls)
	}

	env, out = nmEnv(t, nm, f)
	Run(env, []string{"apply-network", "--confirm"})
	if o, _ := out(); !strings.Contains(o, "подтверждены") || !strings.HasSuffix(strings.Join(nm.calls, ","), "save,destroy") {
		t.Errorf("confirm:\n%s", o)
	}

	// Повторное применение — всё уже совпадает.
	env, out = nmEnv(t, nm, f)
	Run(env, []string{"apply-network"})
	if o, _ := out(); !strings.Contains(o, "уже соответствует") {
		t.Errorf("повторно:\n%s", o)
	}
}

func TestApplyNetworkErrors(t *testing.T) {
	nm := &cliNM{ip4: map[string]dbus.Variant{}}
	env, out := nmEnv(t, nm, servicestest.New())
	env.IsRoot = func() bool { return false }
	if code := Run(env, []string{"apply-network"}); code != 1 {
		t.Error("без root — ошибка")
	}
	env, out = nmEnv(t, nm, servicestest.New())
	if code := Run(env, []string{"apply-network", "--bogus"}); code != 1 {
		t.Error("неизвестный параметр — ошибка")
	}
	env, out = nmEnv(t, nm, servicestest.New())
	env.NM = func() (netcfg.NM, func(), error) { return nil, nil, errors.New("нет шины") }
	if code := Run(env, []string{"apply-network", "--rollback"}); code != 1 {
		t.Error("нет NetworkManager — ошибка")
	}
	if _, e := out(); !strings.Contains(e, "нет шины") {
		t.Errorf("stderr: %q", e)
	}
}
