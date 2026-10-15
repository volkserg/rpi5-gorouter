// Package netcfg применяет статический адрес RPi через NetworkManager по
// D-Bus с защитой Checkpoint: если изменение не подтверждено
// за отведённое время (например, пропал доступ по SSH), NetworkManager сам
// возвращает прежние настройки. До подтверждения изменение живёт только в
// памяти NetworkManager: если RPi перезагрузится (например, пропало питание),
// она поднимется с прежним профилем с диска.
package netcfg

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/godbus/dbus/v5"
)

// Settings — настройки подключения NetworkManager (a{sa{sv}}).
type Settings = map[string]map[string]dbus.Variant

// NM — операции NetworkManager, нужные apply-network (подменяется в тестах).
type NM interface {
	DeviceByIface(ctx context.Context, iface string) (dbus.ObjectPath, error)
	Connections(ctx context.Context) ([]dbus.ObjectPath, error)
	GetSettings(ctx context.Context, conn dbus.ObjectPath) (Settings, error)
	// UpdateSettings меняет профиль только в памяти (на диске — прежний).
	UpdateSettings(ctx context.Context, conn dbus.ObjectPath, s Settings) error
	// Save записывает профиль из памяти на диск.
	Save(ctx context.Context, conn dbus.ObjectPath) error
	Activate(ctx context.Context, conn, dev dbus.ObjectPath) error
	CheckpointCreate(ctx context.Context, dev dbus.ObjectPath, rollback time.Duration) (dbus.ObjectPath, error)
	CheckpointDestroy(ctx context.Context, cp dbus.ObjectPath) error
	CheckpointRollback(ctx context.Context, cp dbus.ObjectPath) error
	// Checkpoints — checkpoint'ы, затрагивающие устройство dev.
	Checkpoints(ctx context.Context, dev dbus.ObjectPath) ([]dbus.ObjectPath, error)
}

// Params — что применить (из router.conf).
type Params struct {
	Iface    string
	ConnName string // NM_CONN; если такого нет — ethernet-подключение интерфейса
	Address  netip.Prefix
	Gateway  netip.Addr
	DNS      []netip.Addr
}

// Change — изменение одного параметра (для вывода и --dry-run).
type Change struct{ Key, Have, Want string }

// Plan — что будет применено.
type Plan struct {
	Conn     dbus.ObjectPath
	ConnID   string
	Device   dbus.ObjectPath
	Changes  []Change
	settings Settings
}

// Prepare находит подключение и вычисляет новые настройки, ничего не меняя.
func Prepare(ctx context.Context, nm NM, p Params) (*Plan, error) {
	dev, err := nm.DeviceByIface(ctx, p.Iface)
	if err != nil {
		return nil, fmt.Errorf("устройство %s в NetworkManager: %w", p.Iface, err)
	}
	conn, cur, err := findConnection(ctx, nm, p)
	if err != nil {
		return nil, err
	}
	next, changes := manualIPv4(cur, p)
	return &Plan{Conn: conn, ConnID: str(cur["connection"]["id"]), Device: dev, Changes: changes, settings: next}, nil
}

// Apply применяет план под защитой checkpoint: при ошибке откатывает сразу,
// при успехе возвращает checkpoint, который нужно подтвердить (Confirm)
// до истечения rollback — иначе NetworkManager откатит изменения сам.
func Apply(ctx context.Context, nm NM, plan *Plan, rollback time.Duration) (dbus.ObjectPath, error) {
	if pending, err := nm.Checkpoints(ctx, plan.Device); err == nil && len(pending) > 0 {
		return "", errors.New("есть неподтверждённое изменение сети — подтвердите (--confirm) или откатите (--rollback)")
	}
	cp, err := nm.CheckpointCreate(ctx, plan.Device, rollback)
	if err != nil {
		return "", fmt.Errorf("checkpoint NetworkManager: %w", err)
	}
	fail := func(step string, err error) (dbus.ObjectPath, error) {
		if rerr := nm.CheckpointRollback(ctx, cp); rerr != nil {
			return "", fmt.Errorf("%s: %w; откат тоже не удался: %v", step, err, rerr)
		}
		return "", fmt.Errorf("%s: %w (настройки возвращены)", step, err)
	}
	if err := nm.UpdateSettings(ctx, plan.Conn, plan.settings); err != nil {
		return fail("обновление подключения", err)
	}
	if err := nm.Activate(ctx, plan.Conn, plan.Device); err != nil {
		return fail("активация подключения", err)
	}
	return cp, nil
}

// Confirm подтверждает изменения: записывает профиль на диск и удаляет
// checkpoint'ы устройства. Запись — первой: если она не удалась, checkpoint
// остаётся и NetworkManager откатит изменения по таймеру.
func Confirm(ctx context.Context, nm NM, p Params) (int, error) {
	dev, err := nm.DeviceByIface(ctx, p.Iface)
	if err != nil {
		return 0, err
	}
	cps, err := nm.Checkpoints(ctx, dev)
	if err != nil || len(cps) == 0 {
		return 0, err
	}
	conn, _, err := findConnection(ctx, nm, p)
	if err != nil {
		return 0, err
	}
	if err := nm.Save(ctx, conn); err != nil {
		return 0, fmt.Errorf("запись профиля на диск: %w", err)
	}
	for _, cp := range cps {
		if err := nm.CheckpointDestroy(ctx, cp); err != nil {
			return 0, err
		}
	}
	return len(cps), nil
}

// Rollback немедленно откатывает неподтверждённые изменения.
func Rollback(ctx context.Context, nm NM, iface string) (int, error) {
	dev, err := nm.DeviceByIface(ctx, iface)
	if err != nil {
		return 0, err
	}
	cps, err := nm.Checkpoints(ctx, dev)
	if err != nil {
		return 0, err
	}
	for _, cp := range cps {
		if err := nm.CheckpointRollback(ctx, cp); err != nil {
			return 0, err
		}
	}
	return len(cps), nil
}

// findConnection — подключение NM_CONN, иначе первое ethernet-подключение
// интерфейса.
func findConnection(ctx context.Context, nm NM, p Params) (dbus.ObjectPath, Settings, error) {
	conns, err := nm.Connections(ctx)
	if err != nil {
		return "", nil, err
	}
	var fallback dbus.ObjectPath
	var fallbackS Settings
	for _, c := range conns {
		s, err := nm.GetSettings(ctx, c)
		if err != nil {
			continue
		}
		if str(s["connection"]["id"]) == p.ConnName {
			return c, s, nil
		}
		if fallback == "" && str(s["connection"]["type"]) == "802-3-ethernet" &&
			str(s["connection"]["interface-name"]) == p.Iface {
			fallback, fallbackS = c, s
		}
	}
	if fallback != "" {
		return fallback, fallbackS, nil
	}
	return "", nil, fmt.Errorf("нет подключения NetworkManager %q и ethernet-подключения для %s", p.ConnName, p.Iface)
}

// manualIPv4 — копия настроек со статическим IPv4 (по аналогии с nmcli con mod
// ipv4.method manual ipv4.addresses … ipv4.gateway … ipv4.dns … ipv4.ignore-auto-dns yes).
func manualIPv4(cur Settings, p Params) (Settings, []Change) {
	next := Settings{}
	for sec, kv := range cur {
		m := map[string]dbus.Variant{}
		for k, v := range kv {
			m[k] = v
		}
		next[sec] = m
	}
	if next["ipv4"] == nil {
		next["ipv4"] = map[string]dbus.Variant{}
	}
	ip4 := next["ipv4"]
	have := describeIPv4(cur["ipv4"])

	// Устаревшие ключи: если прислать "addresses", NetworkManager игнорирует
	// address-data и gateway; "dns-data" заменяем на "dns" (поддерживается везде).
	delete(ip4, "addresses")
	delete(ip4, "dns-data")
	ip4["method"] = dbus.MakeVariant("manual")
	ip4["address-data"] = dbus.MakeVariant([]map[string]dbus.Variant{{
		"address": dbus.MakeVariant(p.Address.Addr().String()),
		"prefix":  dbus.MakeVariant(uint32(p.Address.Bits())),
	}})
	ip4["gateway"] = dbus.MakeVariant(p.Gateway.String())
	dns := make([]uint32, 0, len(p.DNS))
	for _, a := range p.DNS {
		b := a.As4()
		// «Сетевой порядок байт» NetworkManager: байты адреса в памяти как есть.
		dns = append(dns, binary.NativeEndian.Uint32(b[:]))
	}
	ip4["dns"] = dbus.MakeVariant(dns)
	ip4["ignore-auto-dns"] = dbus.MakeVariant(true)

	want := describeIPv4(ip4)
	var changes []Change
	for _, k := range []string{"method", "address", "gateway", "dns", "ignore-auto-dns"} {
		if have[k] != want[k] {
			changes = append(changes, Change{Key: "ipv4." + k, Have: have[k], Want: want[k]})
		}
	}
	return next, changes
}

// describeIPv4 — значения ipv4 для сравнения и вывода.
func describeIPv4(ip4 map[string]dbus.Variant) map[string]string {
	d := map[string]string{
		"method":          str(ip4["method"]),
		"gateway":         str(ip4["gateway"]),
		"ignore-auto-dns": fmt.Sprint(ip4["ignore-auto-dns"].Value() == true),
		"address":         "",
	}
	if ads, ok := ip4["address-data"].Value().([]map[string]dbus.Variant); ok && len(ads) > 0 {
		d["address"] = fmt.Sprintf("%s/%v", str(ads[0]["address"]), ads[0]["prefix"].Value())
	}
	var dns []string
	if v, ok := ip4["dns"].Value().([]uint32); ok {
		for _, u := range v {
			var b [4]byte
			binary.NativeEndian.PutUint32(b[:], u)
			dns = append(dns, netip.AddrFrom4(b).String())
		}
	}
	if v, ok := ip4["dns-data"].Value().([]string); ok && len(dns) == 0 {
		dns = slices.Clone(v)
	}
	d["dns"] = strings.Join(dns, " ")
	for k, v := range d {
		if v == "" {
			d[k] = "(нет)"
		}
	}
	return d
}

func str(v dbus.Variant) string {
	s, _ := v.Value().(string)
	return s
}
