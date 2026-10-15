package netcfg

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/godbus/dbus/v5"
)

type fakeNM struct {
	conns       map[dbus.ObjectPath]Settings
	updated     Settings
	activated   bool
	failUpdate  bool
	failActive  bool
	failSave    bool
	checkpoints []dbus.ObjectPath
	calls       []string
}

func (f *fakeNM) DeviceByIface(_ context.Context, iface string) (dbus.ObjectPath, error) {
	if iface != "eth0" {
		return "", errors.New("No device found")
	}
	return "/dev/eth0", nil
}
func (f *fakeNM) Connections(context.Context) ([]dbus.ObjectPath, error) {
	return []dbus.ObjectPath{"/c/wifi", "/c/1", "/c/2"}, nil
}
func (f *fakeNM) GetSettings(_ context.Context, c dbus.ObjectPath) (Settings, error) {
	return f.conns[c], nil
}
func (f *fakeNM) UpdateSettings(_ context.Context, c dbus.ObjectPath, s Settings) error {
	f.calls = append(f.calls, "update "+string(c))
	if f.failUpdate {
		return errors.New("update failed")
	}
	f.updated = s
	return nil
}
func (f *fakeNM) Save(_ context.Context, c dbus.ObjectPath) error {
	f.calls = append(f.calls, "save "+string(c))
	if f.failSave {
		return errors.New("save failed")
	}
	return nil
}
func (f *fakeNM) Activate(_ context.Context, c, d dbus.ObjectPath) error {
	f.calls = append(f.calls, "activate "+string(c))
	if f.failActive {
		return errors.New("activation failed")
	}
	f.activated = true
	return nil
}
func (f *fakeNM) CheckpointCreate(_ context.Context, d dbus.ObjectPath, r time.Duration) (dbus.ObjectPath, error) {
	f.calls = append(f.calls, "checkpoint "+r.String())
	f.checkpoints = append(f.checkpoints, "/cp/1")
	return "/cp/1", nil
}
func (f *fakeNM) CheckpointDestroy(_ context.Context, cp dbus.ObjectPath) error {
	f.calls = append(f.calls, "destroy "+string(cp))
	f.checkpoints = nil
	return nil
}
func (f *fakeNM) CheckpointRollback(_ context.Context, cp dbus.ObjectPath) error {
	f.calls = append(f.calls, "rollback "+string(cp))
	f.checkpoints = nil
	return nil
}
func (f *fakeNM) Checkpoints(context.Context, dbus.ObjectPath) ([]dbus.ObjectPath, error) {
	return f.checkpoints, nil
}

func v(x any) dbus.Variant { return dbus.MakeVariant(x) }

func newFake() *fakeNM {
	return &fakeNM{conns: map[dbus.ObjectPath]Settings{
		"/c/wifi": {"connection": {"id": v("home-wifi"), "type": v("802-11-wireless")}},
		"/c/1": {
			"connection": {"id": v("Wired connection 1"), "type": v("802-3-ethernet"), "interface-name": v("eth0")},
			"ipv4": {
				"method":    v("auto"),
				"addresses": v([][]uint32{{1, 24, 0}}),
				"dns-data":  v([]string{"192.168.3.1"}),
			},
		},
		"/c/2": {
			"connection": {"id": v("netplan-eth0"), "type": v("802-3-ethernet"), "interface-name": v("eth0")},
			"ipv4":       {"method": v("auto")},
			"ipv6":       {"method": v("ignore")},
		},
	}}
}

func params(conn string) Params {
	return Params{
		Iface: "eth0", ConnName: conn,
		Address: netip.MustParsePrefix("192.168.3.2/24"),
		Gateway: netip.MustParseAddr("192.168.3.1"),
		DNS:     []netip.Addr{netip.MustParseAddr("1.1.1.1"), netip.MustParseAddr("8.8.8.8")},
	}
}

func TestPrepareFindsConnectionByName(t *testing.T) {
	plan, err := Prepare(context.Background(), newFake(), params("netplan-eth0"))
	if err != nil || plan.Conn != "/c/2" || plan.ConnID != "netplan-eth0" || plan.Device != "/dev/eth0" {
		t.Fatalf("plan=%+v err=%v", plan, err)
	}
	ip4 := plan.settings["ipv4"]
	if ip4["method"].Value() != "manual" || ip4["gateway"].Value() != "192.168.3.1" || ip4["ignore-auto-dns"].Value() != true {
		t.Errorf("ipv4: %v", ip4)
	}
	ad := ip4["address-data"].Value().([]map[string]dbus.Variant)[0]
	if ad["address"].Value() != "192.168.3.2" || ad["prefix"].Value() != uint32(24) {
		t.Errorf("address-data: %v", ad)
	}
	// Остальные секции профиля сохранены.
	if plan.settings["ipv6"]["method"].Value() != "ignore" {
		t.Error("секция ipv6 потеряна")
	}
	d := describeIPv4(ip4)
	if d["dns"] != "1.1.1.1 8.8.8.8" || d["address"] != "192.168.3.2/24" {
		t.Errorf("describe: %v", d)
	}
}

func TestPrepareFallbackAndLegacyKeys(t *testing.T) {
	plan, err := Prepare(context.Background(), newFake(), params("no-such-conn"))
	if err != nil || plan.Conn != "/c/1" {
		t.Fatalf("запасной вариант — ethernet-подключение интерфейса: %+v %v", plan, err)
	}
	ip4 := plan.settings["ipv4"]
	if _, ok := ip4["addresses"]; ok {
		t.Error("устаревший addresses должен быть удалён (иначе NM игнорирует address-data и gateway)")
	}
	if _, ok := ip4["dns-data"]; ok {
		t.Error("dns-data заменяется на dns")
	}
	var keys []string
	for _, c := range plan.Changes {
		keys = append(keys, c.Key)
	}
	if strings.Join(keys, ",") != "ipv4.method,ipv4.address,ipv4.gateway,ipv4.dns,ipv4.ignore-auto-dns" {
		t.Errorf("changes: %+v", plan.Changes)
	}

	if _, err := Prepare(context.Background(), newFake(), Params{Iface: "eth1"}); err == nil {
		t.Error("нет устройства — ошибка")
	}
}

func TestApplyConfirm(t *testing.T) {
	nm := newFake()
	plan, _ := Prepare(context.Background(), nm, params("netplan-eth0"))
	cp, err := Apply(context.Background(), nm, plan, time.Minute)
	if err != nil || cp != "/cp/1" || !nm.activated {
		t.Fatalf("apply: %v %v", cp, err)
	}
	if strings.Join(nm.calls, ",") != "checkpoint 1m0s,update /c/2,activate /c/2" {
		t.Errorf("порядок: %v", nm.calls)
	}
	// Пока не подтверждено — повторное применение запрещено.
	if _, err := Apply(context.Background(), nm, plan, time.Minute); err == nil {
		t.Error("второе изменение поверх неподтверждённого")
	}
	nm.calls = nil
	if n, err := Confirm(context.Background(), nm, params("netplan-eth0")); n != 1 || err != nil {
		t.Errorf("confirm: %d %v", n, err)
	}
	// Профиль на диск — до снятия checkpoint.
	if strings.Join(nm.calls, ",") != "save /c/2,destroy /cp/1" {
		t.Errorf("подтверждение: %v", nm.calls)
	}
	if n, _ := Confirm(context.Background(), nm, params("netplan-eth0")); n != 0 {
		t.Error("подтверждать нечего")
	}
}

// Не удалось записать профиль — checkpoint остаётся, откат по таймеру сработает.
func TestConfirmSaveFails(t *testing.T) {
	nm := newFake()
	plan, _ := Prepare(context.Background(), nm, params("netplan-eth0"))
	Apply(context.Background(), nm, plan, time.Minute)
	nm.failSave = true
	if _, err := Confirm(context.Background(), nm, params("netplan-eth0")); err == nil {
		t.Error("ожидалась ошибка записи")
	}
	if len(nm.checkpoints) != 1 {
		t.Error("checkpoint должен остаться")
	}
}

func TestApplyRollsBackOnFailure(t *testing.T) {
	for name, set := range map[string]func(*fakeNM){
		"update":   func(f *fakeNM) { f.failUpdate = true },
		"activate": func(f *fakeNM) { f.failActive = true },
	} {
		nm := newFake()
		set(nm)
		plan, _ := Prepare(context.Background(), nm, params("netplan-eth0"))
		if _, err := Apply(context.Background(), nm, plan, time.Minute); err == nil || !strings.Contains(err.Error(), "возвращены") {
			t.Errorf("%s: err=%v", name, err)
		}
		if last := nm.calls[len(nm.calls)-1]; last != "rollback /cp/1" {
			t.Errorf("%s: ожидался немедленный откат, calls=%v", name, nm.calls)
		}
	}
}

func TestRollbackCommand(t *testing.T) {
	nm := newFake()
	plan, _ := Prepare(context.Background(), nm, params("netplan-eth0"))
	Apply(context.Background(), nm, plan, time.Minute)
	if n, err := Rollback(context.Background(), nm, "eth0"); n != 1 || err != nil || nm.calls[len(nm.calls)-1] != "rollback /cp/1" {
		t.Errorf("rollback: %d %v %v", n, err, nm.calls)
	}
}
