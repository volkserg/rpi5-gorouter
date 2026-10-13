package services

import (
	"context"
	"fmt"
	"strings"

	sddbus "github.com/coreos/go-systemd/v22/dbus"
)

// dbusManager — Manager поверх системной шины D-Bus.
type dbusManager struct {
	c *sddbus.Conn
}

// Connect подключается к systemd по системной шине. Для управляющих
// операций нужен root (иначе — polkit).
func Connect(ctx context.Context) (Manager, error) {
	c, err := sddbus.NewSystemConnectionContext(ctx)
	if err != nil {
		return nil, fmt.Errorf("подключение к systemd по D-Bus: %w", err)
	}
	return &dbusManager{c: c}, nil
}

func (m *dbusManager) Close() { m.c.Close() }

type jobFunc func(ctx context.Context, name, mode string, ch chan<- string) (int, error)

// run ставит задание и ждёт его результата ("done", "failed", "timeout",
// "dependency", "canceled", "skipped").
func (m *dbusManager) run(ctx context.Context, f jobFunc, unit string) error {
	ch := make(chan string, 1)
	if _, err := f(ctx, unit, "replace", ch); err != nil {
		return err
	}
	select {
	case res := <-ch:
		if res != "done" {
			return fmt.Errorf("задание systemd завершилось: %s", res)
		}
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (m *dbusManager) Start(ctx context.Context, unit string) error {
	return m.run(ctx, m.c.StartUnitContext, unit)
}

func (m *dbusManager) Stop(ctx context.Context, unit string) error {
	return m.run(ctx, m.c.StopUnitContext, unit)
}

func (m *dbusManager) Restart(ctx context.Context, unit string) error {
	return m.run(ctx, m.c.RestartUnitContext, unit)
}

func (m *dbusManager) Reload(ctx context.Context, unit string) error {
	return m.run(ctx, m.c.ReloadUnitContext, unit)
}

func (m *dbusManager) States(ctx context.Context, units ...string) ([]State, error) {
	us, err := m.c.ListUnitsByNamesContext(ctx, units)
	if err != nil {
		return nil, err
	}
	out := make([]State, 0, len(us))
	for _, u := range us {
		out = append(out, State{Name: u.Name, LoadState: u.LoadState, Active: u.ActiveState, Sub: u.SubState})
	}
	return out, nil
}

func (m *dbusManager) Disable(ctx context.Context, unit string) error {
	_, err := m.c.DisableUnitFilesContext(ctx, []string{unit}, false)
	if err != nil {
		return err
	}
	return m.c.ReloadContext(ctx)
}

func (m *dbusManager) Enabled(ctx context.Context, unit string) (bool, error) {
	p, err := m.c.GetUnitPropertyContext(ctx, unit, "UnitFileState")
	if err != nil {
		return false, err
	}
	s := strings.Trim(p.Value.String(), `"`)
	return s == "enabled" || s == "enabled-runtime", nil
}
