package netcfg

import (
	"context"
	"fmt"
	"time"

	"github.com/godbus/dbus/v5"
)

const (
	nmDest      = "org.freedesktop.NetworkManager"
	nmPath      = "/org/freedesktop/NetworkManager"
	nmIface     = "org.freedesktop.NetworkManager"
	nmSettings  = "/org/freedesktop/NetworkManager/Settings"
	nmConnIface = "org.freedesktop.NetworkManager.Settings.Connection"

	// NM_DEVICE_STATE_ACTIVATED / _FAILED.
	deviceActivated = 100
	deviceFailed    = 120
	// NM_SETTINGS_UPDATE2_FLAG_TO_DISK — сохранить профиль на диск.
	updateToDisk = 0x1
)

// DBusNM — NM поверх системной шины.
type DBusNM struct {
	conn *dbus.Conn
}

// ConnectNM подключается к системной шине.
func ConnectNM() (*DBusNM, error) {
	c, err := dbus.ConnectSystemBus()
	if err != nil {
		return nil, fmt.Errorf("системная шина D-Bus: %w", err)
	}
	return &DBusNM{conn: c}, nil
}

// Close закрывает соединение.
func (n *DBusNM) Close() { n.conn.Close() }

func (n *DBusNM) obj(p dbus.ObjectPath) dbus.BusObject { return n.conn.Object(nmDest, p) }

func (n *DBusNM) DeviceByIface(ctx context.Context, iface string) (dbus.ObjectPath, error) {
	var dev dbus.ObjectPath
	err := n.obj(nmPath).CallWithContext(ctx, nmIface+".GetDeviceByIpIface", 0, iface).Store(&dev)
	return dev, err
}

func (n *DBusNM) Connections(ctx context.Context) ([]dbus.ObjectPath, error) {
	var out []dbus.ObjectPath
	err := n.obj(nmSettings).CallWithContext(ctx, nmIface+".Settings.ListConnections", 0).Store(&out)
	return out, err
}

func (n *DBusNM) GetSettings(ctx context.Context, conn dbus.ObjectPath) (Settings, error) {
	var s Settings
	err := n.obj(conn).CallWithContext(ctx, nmConnIface+".GetSettings", 0).Store(&s)
	return s, err
}

func (n *DBusNM) UpdateSettings(ctx context.Context, conn dbus.ObjectPath, s Settings) error {
	var result map[string]dbus.Variant
	return n.obj(conn).CallWithContext(ctx, nmConnIface+".Update2", 0,
		s, uint32(updateToDisk), map[string]dbus.Variant{}).Store(&result)
}

// Activate активирует подключение на устройстве и ждёт, пока устройство
// перейдёт в состояние «активировано» (до 45 с).
func (n *DBusNM) Activate(ctx context.Context, conn, dev dbus.ObjectPath) error {
	var active dbus.ObjectPath
	if err := n.obj(nmPath).CallWithContext(ctx, nmIface+".ActivateConnection", 0, conn, dev, dbus.ObjectPath("/")).Store(&active); err != nil {
		return err
	}
	deadline := time.Now().Add(45 * time.Second)
	for time.Now().Before(deadline) {
		v, err := n.obj(dev).GetProperty(nmIface + ".Device.State")
		if err == nil {
			switch st, _ := v.Value().(uint32); st {
			case deviceActivated:
				return nil
			case deviceFailed:
				return fmt.Errorf("NetworkManager не смог активировать подключение")
			}
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(500 * time.Millisecond):
		}
	}
	return fmt.Errorf("подключение не активировалось за 45 с")
}

func (n *DBusNM) CheckpointCreate(ctx context.Context, dev dbus.ObjectPath, rollback time.Duration) (dbus.ObjectPath, error) {
	var cp dbus.ObjectPath
	err := n.obj(nmPath).CallWithContext(ctx, nmIface+".CheckpointCreate", 0,
		[]dbus.ObjectPath{dev}, uint32(rollback/time.Second), uint32(0)).Store(&cp)
	return cp, err
}

func (n *DBusNM) CheckpointDestroy(ctx context.Context, cp dbus.ObjectPath) error {
	return n.obj(nmPath).CallWithContext(ctx, nmIface+".CheckpointDestroy", 0, cp).Err
}

func (n *DBusNM) CheckpointRollback(ctx context.Context, cp dbus.ObjectPath) error {
	var result map[string]uint32
	return n.obj(nmPath).CallWithContext(ctx, nmIface+".CheckpointRollback", 0, cp).Store(&result)
}

func (n *DBusNM) Checkpoints(_ context.Context, dev dbus.ObjectPath) ([]dbus.ObjectPath, error) {
	v, err := n.obj(nmPath).GetProperty(nmIface + ".Checkpoints")
	if err != nil {
		return nil, err
	}
	all, _ := v.Value().([]dbus.ObjectPath)
	var out []dbus.ObjectPath
	for _, cp := range all {
		dv, err := n.obj(cp).GetProperty(nmIface + ".Checkpoint.Devices")
		if err != nil {
			continue
		}
		devs, _ := dv.Value().([]dbus.ObjectPath)
		for _, d := range devs {
			if d == dev {
				out = append(out, cp)
				break
			}
		}
	}
	return out, nil
}
