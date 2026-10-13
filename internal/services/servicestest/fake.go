// Package servicestest — поддельный services.Manager для тестов.
package servicestest

import (
	"context"
	"fmt"
	"sync"

	"github.com/volkserg/rpi5-gorouter/internal/services"
)

// Fake хранит состояния юнитов в памяти и записывает вызовы.
type Fake struct {
	mu        sync.Mutex
	Units     map[string]*services.State
	AutoStart map[string]bool
	// Fail — юниты, операции над которыми завершаются ошибкой.
	Fail  map[string]bool
	Calls []string // "start routerd.service", …
}

// New создаёт Fake с установленными (но остановленными) юнитами.
func New(installed ...string) *Fake {
	f := &Fake{Units: map[string]*services.State{}, AutoStart: map[string]bool{}, Fail: map[string]bool{}}
	for _, u := range installed {
		f.Units[u] = &services.State{Name: u, LoadState: "loaded", Active: "inactive", Sub: "dead"}
	}
	return f
}

// SetActive помечает юнит запущенным.
func (f *Fake) SetActive(units ...string) {
	for _, u := range units {
		f.Units[u].Active, f.Units[u].Sub = "active", "running"
	}
}

func (f *Fake) op(name, unit, active, sub string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.Calls = append(f.Calls, name+" "+unit)
	st, ok := f.Units[unit]
	if !ok {
		return fmt.Errorf("Unit %s not found.", unit)
	}
	if f.Fail[unit] {
		st.Active, st.Sub = "failed", "failed"
		return fmt.Errorf("задание systemd завершилось: failed")
	}
	if active != "" {
		st.Active, st.Sub = active, sub
	}
	return nil
}

func (f *Fake) Start(_ context.Context, u string) error { return f.op("start", u, "active", "running") }
func (f *Fake) Stop(_ context.Context, u string) error  { return f.op("stop", u, "inactive", "dead") }
func (f *Fake) Restart(_ context.Context, u string) error {
	return f.op("restart", u, "active", "running")
}
func (f *Fake) Reload(_ context.Context, u string) error { return f.op("reload", u, "", "") }

func (f *Fake) States(_ context.Context, units ...string) ([]services.State, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []services.State
	for _, u := range units {
		if st, ok := f.Units[u]; ok {
			out = append(out, *st)
		} else {
			out = append(out, services.State{Name: u, LoadState: "not-found", Active: "inactive", Sub: "dead"})
		}
	}
	return out, nil
}

func (f *Fake) Disable(_ context.Context, u string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.Calls = append(f.Calls, "disable "+u)
	f.AutoStart[u] = false
	return nil
}

func (f *Fake) Enabled(_ context.Context, u string) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.AutoStart[u], nil
}

func (f *Fake) Close() {}
