package services_test

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/volkserg/rpi5-gorouter/internal/services"
	"github.com/volkserg/rpi5-gorouter/internal/services/servicestest"
)

var all = []string{
	services.UnitDNSCryptSocket, services.UnitDNSCrypt, services.UnitPihole,
	services.UnitRouterd, services.DefaultUnitGost,
}

func nolog(bool, string, ...any) {}

func TestStartOrder(t *testing.T) {
	f := servicestest.New(all...)
	if err := services.StartStack(context.Background(), f, services.DefaultUnitGost, nolog); err != nil {
		t.Fatal(err)
	}
	want := "start dnscrypt-proxy.socket,start dnscrypt-proxy.service,start pihole-FTL.service,start routerd.service,start gost-run.service"
	if got := strings.Join(f.Calls, ","); got != want {
		t.Errorf("порядок:\n got %s\nwant %s", got, want)
	}
}

func TestStartOptionalFailureContinues(t *testing.T) {
	f := servicestest.New(all...)
	f.Fail[services.UnitPihole] = true
	var warns []string
	log := func(warn bool, format string, a ...any) {
		if warn {
			warns = append(warns, format)
		}
	}
	if err := services.StartStack(context.Background(), f, services.DefaultUnitGost, log); err != nil {
		t.Fatalf("ошибка необязательного юнита не должна прерывать запуск: %v", err)
	}
	if len(warns) != 1 {
		t.Errorf("ожидалось одно предупреждение: %v", warns)
	}
	if f.Units[services.DefaultUnitGost].Active != "active" {
		t.Error("gost-run должен быть запущен")
	}
}

func TestStartRequiredFailureStops(t *testing.T) {
	f := servicestest.New(all...)
	f.Fail[services.UnitRouterd] = true
	err := services.StartStack(context.Background(), f, services.DefaultUnitGost, nolog)
	if err == nil || !strings.Contains(err.Error(), "routerd.service") {
		t.Fatalf("err = %v", err)
	}
	if f.Units[services.DefaultUnitGost].Active == "active" {
		t.Error("после отказа routerd туннель запускаться не должен")
	}
}

func TestStartDisablesSystemDnsmasq(t *testing.T) {
	f := servicestest.New(append(all, services.UnitSystemDnsmasq)...)
	f.SetActive(services.UnitSystemDnsmasq)
	f.AutoStart[services.UnitSystemDnsmasq] = true
	if err := services.StartStack(context.Background(), f, services.DefaultUnitGost, nolog); err != nil {
		t.Fatal(err)
	}
	calls := strings.Join(f.Calls, ",")
	if !strings.Contains(calls, "stop dnsmasq.service,disable dnsmasq.service,start routerd.service") {
		t.Errorf("системный dnsmasq должен быть остановлен и отключён до routerd: %s", calls)
	}
}

func TestStopStack(t *testing.T) {
	f := servicestest.New(all...)
	f.SetActive(all...)
	if err := services.StopStack(context.Background(), f, services.DefaultUnitGost); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(f.Calls, ","); got != "stop gost-run.service,stop routerd.service" {
		t.Errorf("got %s", got)
	}
	if f.Units[services.UnitPihole].Active != "active" {
		t.Error("Pi-hole должен остаться запущенным")
	}
}

// flakyStart — запуск юнита отклоняется первые n раз (как start-limit systemd).
type flakyStart struct {
	*servicestest.Fake
	n int
}

func (f *flakyStart) Start(ctx context.Context, u string) error {
	if f.n > 0 {
		f.n--
		return errors.New("start-limit-hit")
	}
	return f.Fake.Start(ctx, u)
}

func TestStartRetry(t *testing.T) {
	ctx := context.Background()
	f := &flakyStart{Fake: servicestest.New(services.UnitPihole), n: 2}
	var retries []int
	err := services.StartRetry(ctx, f, services.UnitPihole, 3, time.Millisecond, func(a int, _ error) { retries = append(retries, a) })
	if err != nil || len(retries) != 2 {
		t.Fatalf("ожидался успех с третьей попытки: err=%v, повторы=%v", err, retries)
	}
	if st, _ := f.States(ctx, services.UnitPihole); !st[0].Running() {
		t.Error("юнит не запущен")
	}

	f = &flakyStart{Fake: servicestest.New(services.UnitPihole), n: 5}
	if err := services.StartRetry(ctx, f, services.UnitPihole, 3, time.Millisecond, nil); err == nil {
		t.Error("после всех попыток ожидалась ошибка")
	}
}

// Клиент туннеля ещё не установлен: стек запускается и останавливается без ошибок.
func TestStackWithoutTunnelUnit(t *testing.T) {
	f := servicestest.New(services.UnitDNSCryptSocket, services.UnitDNSCrypt, services.UnitPihole, services.UnitRouterd)
	var warns []string
	log := func(warn bool, format string, a ...any) {
		if warn {
			warns = append(warns, fmt.Sprintf(format, a...))
		}
	}
	if err := services.StartStack(context.Background(), f, services.DefaultUnitGost, log); err != nil {
		t.Fatal(err)
	}
	if !f.Units[services.UnitRouterd].Running() || len(warns) != 1 || !strings.Contains(warns[0], "не установлен") {
		t.Errorf("start: warns=%v", warns)
	}
	f.Calls = nil
	if err := services.StopStack(context.Background(), f, services.DefaultUnitGost); err != nil {
		t.Errorf("stop: %v", err)
	}
	if got := strings.Join(f.Calls, ","); got != "stop routerd.service" {
		t.Errorf("stop: %s", got)
	}
}
