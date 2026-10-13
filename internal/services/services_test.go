package services_test

import (
	"context"
	"strings"
	"testing"

	"github.com/volkserg/rpi5-gorouter/internal/services"
	"github.com/volkserg/rpi5-gorouter/internal/services/servicestest"
)

var all = []string{
	services.UnitDNSCryptSocket, services.UnitDNSCrypt, services.UnitPihole,
	services.UnitRouterd, services.UnitGost,
}

func nolog(bool, string, ...any) {}

func TestStartOrder(t *testing.T) {
	f := servicestest.New(all...)
	if err := services.StartStack(context.Background(), f, nolog); err != nil {
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
	if err := services.StartStack(context.Background(), f, log); err != nil {
		t.Fatalf("ошибка необязательного юнита не должна прерывать запуск: %v", err)
	}
	if len(warns) != 1 {
		t.Errorf("ожидалось одно предупреждение: %v", warns)
	}
	if f.Units[services.UnitGost].Active != "active" {
		t.Error("gost-run должен быть запущен")
	}
}

func TestStartRequiredFailureStops(t *testing.T) {
	f := servicestest.New(all...)
	f.Fail[services.UnitRouterd] = true
	err := services.StartStack(context.Background(), f, nolog)
	if err == nil || !strings.Contains(err.Error(), "routerd.service") {
		t.Fatalf("err = %v", err)
	}
	if f.Units[services.UnitGost].Active == "active" {
		t.Error("после отказа routerd туннель запускаться не должен")
	}
}

func TestStartDisablesSystemDnsmasq(t *testing.T) {
	f := servicestest.New(append(all, services.UnitSystemDnsmasq)...)
	f.SetActive(services.UnitSystemDnsmasq)
	f.AutoStart[services.UnitSystemDnsmasq] = true
	if err := services.StartStack(context.Background(), f, nolog); err != nil {
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
	if err := services.StopStack(context.Background(), f); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(f.Calls, ","); got != "stop gost-run.service,stop routerd.service" {
		t.Errorf("got %s", got)
	}
	if f.Units[services.UnitPihole].Active != "active" {
		t.Error("Pi-hole должен остаться запущенным")
	}
}
