// Package services управляет systemd-юнитами router_service по D-Bus
// (вместо systemctl) и знает порядок их запуска.
package services

import (
	"context"
	"errors"
	"fmt"
)

// Юниты, которыми управляет router_service.
const (
	UnitDNSCryptSocket = "dnscrypt-proxy.socket"
	UnitDNSCrypt       = "dnscrypt-proxy.service"
	UnitPihole         = "pihole-FTL.service"
	UnitRouterd        = "routerd.service"
	UnitGost           = "gost-run.service"
	// UnitSystemDnsmasq — системный dnsmasq Debian: занимает :53, конфликтует с routerd.
	UnitSystemDnsmasq = "dnsmasq.service"
)

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
	Close()
}

// Step — шаг запуска стека.
type Step struct {
	Unit string
	// Required — ошибка шага прерывает запуск; иначе — предупреждение,
	// как в bash-версии (dnscrypt-proxy и Pi-hole могли не стартовать).
	Required bool
}

// StartOrder — порядок запуска: DNS-цепочка снизу вверх, затем routerd
// (DNS :53, DHCP, nftables), затем туннель.
var StartOrder = []Step{
	{Unit: UnitDNSCryptSocket},
	{Unit: UnitDNSCrypt},
	{Unit: UnitPihole},
	{Unit: UnitRouterd, Required: true},
	{Unit: UnitGost},
}

// StopOrder — что останавливает `stop`: туннель и routerd. Pi-hole и
// dnscrypt-proxy остаются работать, как и в bash-версии.
var StopOrder = []string{UnitGost, UnitRouterd}

// StatusUnits — юниты, показываемые в status.
var StatusUnits = []string{UnitRouterd, UnitGost, UnitDNSCrypt, UnitDNSCryptSocket, UnitPihole}

// Logger получает сообщения о ходе операций: warn=true — предупреждение.
type Logger func(warn bool, format string, a ...any)

// StartStack запускает юниты в порядке StartOrder. Перед routerd
// останавливается и отключается системный dnsmasq (конфликт порта 53).
func StartStack(ctx context.Context, m Manager, log Logger) error {
	for _, s := range StartOrder {
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
func StopStack(ctx context.Context, m Manager) error {
	var errs []error
	for _, u := range StopOrder {
		if err := m.Stop(ctx, u); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", u, err))
		}
	}
	return errors.Join(errs...)
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
