// Package services управляет systemd-юнитами router_service по D-Bus
// (по аналогии с systemctl) и знает порядок их запуска.
package services

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// Юниты, которыми управляет router_service.
const (
	UnitDNSCryptSocket = "dnscrypt-proxy.socket"
	UnitDNSCrypt       = "dnscrypt-proxy.service"
	UnitPihole         = "pihole-FTL.service"
	UnitRouterd        = "routerd.service"
	// DefaultUnitGost — юнит клиента туннеля по умолчанию (VPN_SERVICE).
	DefaultUnitGost = "gost-run.service"
	// UnitSystemDnsmasq — системный dnsmasq Debian: занимает :53, конфликтует с routerd.
	UnitSystemDnsmasq = "dnsmasq.service"
)

// LocalUnit — юнит сети локального сервиса (LOCAL_CLIENTS).
func LocalUnit(name string) string { return "routerd-local@" + name + ".service" }

// State — состояние юнита.
type State struct {
	Name      string
	LoadState string // loaded, not-found, masked, …
	Active    string // active, inactive, failed, activating, …
	Sub       string // running, exited, dead, listening, …
}

// Running — юнит активен (для socket — слушает, для oneshot — выполнен).
func (s State) Running() bool { return s.Active == "active" }

// Installed — юнит известен systemd.
func (s State) Installed() bool { return s.LoadState != "" && s.LoadState != "not-found" }

// Manager — операции над юнитами. Методы Start/Stop/Restart/Reload ждут
// завершения задания systemd и возвращают ошибку, если оно не "done".
type Manager interface {
	Start(ctx context.Context, unit string) error
	Stop(ctx context.Context, unit string) error
	Restart(ctx context.Context, unit string) error
	Reload(ctx context.Context, unit string) error
	States(ctx context.Context, units ...string) ([]State, error)
	// Disable отключает автозапуск (аналог systemctl disable).
	Disable(ctx context.Context, unit string) error
	// Enabled сообщает, включён ли автозапуск юнита.
	Enabled(ctx context.Context, unit string) (bool, error)
	// StatusText — текст STATUS= службы (sd_notify), пусто если не задан.
	StatusText(ctx context.Context, unit string) (string, error)
	// SocketListen — адреса, которые слушает socket-юнит (127.0.0.1:5053).
	SocketListen(ctx context.Context, unit string) ([]string, error)
	Close()
}

// Step — шаг запуска стека.
type Step struct {
	Unit string
	// Required — ошибка шага прерывает запуск; иначе — предупреждение
	// (без dnscrypt-proxy или Pi-hole routerd всё равно запускается).
	Required bool
}

// StartOrder — порядок запуска: DNS-цепочка снизу вверх, затем routerd
// (DNS :53, DHCP, nftables), затем туннель (юнит gost — VPN_SERVICE).
func StartOrder(gost string) []Step {
	return []Step{
		{Unit: UnitDNSCryptSocket},
		{Unit: UnitDNSCrypt},
		{Unit: UnitPihole},
		{Unit: UnitRouterd, Required: true},
		{Unit: gost},
	}
}

// StopOrder — что останавливает `stop`: туннель и routerd. Pi-hole и
// dnscrypt-proxy остаются работать.
func StopOrder(gost string) []string { return []string{gost, UnitRouterd} }

// StatusUnits — юниты, показываемые в status.
func StatusUnits(gost string) []string {
	return []string{UnitRouterd, gost, UnitDNSCrypt, UnitDNSCryptSocket, UnitPihole}
}

// Logger получает сообщения о ходе операций: warn=true — предупреждение.
type Logger func(warn bool, format string, a ...any)

// StartStack запускает юниты в порядке StartOrder. Перед routerd
// останавливается и отключается системный dnsmasq (конфликт порта 53).
func StartStack(ctx context.Context, m Manager, gost string, log Logger) error {
	installed := installedUnits(ctx, m, StartOrder(gost))
	for _, s := range StartOrder(gost) {
		if !s.Required && !installed(s.Unit) {
			log(true, "Предупреждение: %s не установлен — пропущен", s.Unit)
			continue
		}
		if s.Unit == UnitRouterd {
			if err := disableSystemDnsmasq(ctx, m, log); err != nil {
				log(true, "Предупреждение: системный dnsmasq: %v", err)
			}
		}
		if err := m.Start(ctx, s.Unit); err != nil {
			if s.Required {
				return fmt.Errorf("%s: %w", s.Unit, err)
			}
			log(true, "Предупреждение: %s не запущен: %v", s.Unit, err)
		}
	}
	return nil
}

// StopStack останавливает юниты из StopOrder; ошибки собираются, но не
// прерывают остановку остальных.
func StopStack(ctx context.Context, m Manager, gost string) error {
	var errs []error
	var steps []Step
	for _, u := range StopOrder(gost) {
		steps = append(steps, Step{Unit: u})
	}
	installed := installedUnits(ctx, m, steps)
	for _, u := range StopOrder(gost) {
		// Юнита нет (например, клиент туннеля ещё не установлен) — останавливать нечего.
		if !installed(u) {
			continue
		}
		if err := m.Stop(ctx, u); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", u, err))
		}
	}
	return errors.Join(errs...)
}

// installedUnits — какие из юнитов есть в systemd. Если systemd не ответил,
// считается, что есть все: тогда ошибку покажет сама операция.
func installedUnits(ctx context.Context, m Manager, steps []Step) func(string) bool {
	units := make([]string, len(steps))
	for i, s := range steps {
		units[i] = s.Unit
	}
	sts, err := m.States(ctx, units...)
	if err != nil {
		return func(string) bool { return true }
	}
	have := map[string]bool{}
	for _, st := range sts {
		have[st.Name] = st.Installed()
	}
	return func(u string) bool { return have[u] }
}

func disableSystemDnsmasq(ctx context.Context, m Manager, log Logger) error {
	st, err := m.States(ctx, UnitSystemDnsmasq)
	if err != nil {
		return err
	}
	if len(st) == 0 || !st[0].Installed() {
		return nil
	}
	if st[0].Running() {
		log(true, "Останавливаю системный dnsmasq (конфликт порта 53)...")
		if err := m.Stop(ctx, UnitSystemDnsmasq); err != nil {
			return err
		}
	}
	if on, err := m.Enabled(ctx, UnitSystemDnsmasq); err != nil {
		return err
	} else if on {
		log(true, "Отключаю автозапуск системного dnsmasq...")
		return m.Disable(ctx, UnitSystemDnsmasq)
	}
	return nil
}

// StartRetry запускает unit, повторяя попытку после паузы delay (всего
// attempts попыток): systemd отклоняет частые запуски юнита (start-limit,
// по умолчанию 5 за 10 с), и после паузы запуск снова разрешён.
// retry вызывается перед каждой повторной попыткой.
func StartRetry(ctx context.Context, m Manager, unit string, attempts int, delay time.Duration, retry func(attempt int, err error)) error {
	var err error
	for attempt := 1; attempt <= attempts; attempt++ {
		if err = m.Start(ctx, unit); err == nil || attempt == attempts {
			return err
		}
		if retry != nil {
			retry(attempt, err)
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("%w (%v)", err, ctx.Err())
		case <-time.After(delay):
		}
	}
	return err
}
