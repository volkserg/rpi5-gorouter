//go:build linux

// Package daemon — долгоживущий процесс routerd (routerd run): применяет
// sysctl и правила nftables, ведёт DNS-фильтр, перечитывает конфиги по SIGHUP
// и убирает за собой правила при остановке.
package daemon

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	sddaemon "github.com/coreos/go-systemd/v22/daemon"
	"github.com/google/nftables"
	"golang.org/x/sys/unix"

	"github.com/volkserg/rpi5-gorouter/internal/config"
	"github.com/volkserg/rpi5-gorouter/internal/dnsmasq"
	"github.com/volkserg/rpi5-gorouter/internal/firewall"
	"github.com/volkserg/rpi5-gorouter/internal/lists"
	"github.com/volkserg/rpi5-gorouter/internal/services"
	"github.com/volkserg/rpi5-gorouter/internal/sysctl"
)

// DefaultRunDir — каталог сгенерированных файлов времени выполнения.
const DefaultRunDir = "/run/routerd"

// Options — параметры демона.
type Options struct {
	ConfigDir string
	ProcRoot  string
	RunDir    string
	Log       *slog.Logger
	Services  func(context.Context) (services.Manager, error)
}

type daemon struct {
	Options
	nft *nftables.Conn
}

// Run работает до SIGTERM/SIGINT. Ошибка первого применения конфигурации
// фатальна (systemd увидит отказ запуска); ошибки перезагрузки — нет:
// остаются прежние правила, а причина видна в status и журнале.
func Run(ctx context.Context, o Options) error {
	nft, err := nftables.New()
	if err != nil {
		return fmt.Errorf("netlink nftables: %w", err)
	}
	d := &daemon{Options: o, nft: nft}

	sigs := make(chan os.Signal, 4)
	signal.Notify(sigs, syscall.SIGHUP, syscall.SIGTERM, syscall.SIGINT)
	defer signal.Stop(sigs)

	summary, err := d.apply(ctx, true)
	if err != nil {
		d.cleanup()
		return err
	}
	d.Log.Info("routerd запущен", "состояние", summary)
	notify("READY=1", "STATUS="+summary)

	for {
		select {
		case <-ctx.Done():
			d.cleanup()
			return nil
		case sig := <-sigs:
			if sig != syscall.SIGHUP {
				d.Log.Info("остановка по сигналу", "сигнал", sig.String())
				notify("STOPPING=1")
				d.cleanup()
				return nil
			}
			notify("RELOADING=1", "MONOTONIC_USEC="+monotonicUsec())
			summary, err := d.apply(ctx, false)
			if err != nil {
				d.Log.Error("перезагрузка не удалась, действуют прежние правила", "ошибка", err)
				notify("READY=1", "STATUS=ошибка перезагрузки: "+err.Error())
				continue
			}
			d.Log.Info("конфигурация перезагружена", "состояние", summary)
			notify("READY=1", "STATUS="+summary)
		}
	}
}

// apply читает конфиги и приводит систему к ним.
func (d *daemon) apply(ctx context.Context, initial bool) (string, error) {
	cfg, warns, err := config.Load(config.Path(d.ConfigDir))
	for _, w := range warns {
		d.Log.Warn(string(w))
	}
	if err != nil {
		return "", err
	}
	vpn, _, err := lists.ReadVPN(filepath.Join(d.ConfigDir, lists.VPNFileName))
	if err != nil {
		return "", err
	}
	for _, ln := range vpn.Invalid() {
		d.Log.Warn("запись пропущена", "файл", lists.VPNFileName, "строка", ln.Num, "ошибка", ln.Err)
	}
	overrides, bad, err := lists.ReadOverrides(filepath.Join(d.ConfigDir, lists.OverrideFileName))
	if err != nil {
		return "", err
	}
	for _, b := range bad {
		d.Log.Warn("правило пропущено", "файл", lists.OverrideFileName, "строка", b.Line, "ошибка", b.Err)
	}

	changed, err := sysctl.Apply(d.ProcRoot, sysctl.Router(cfg.Iface))
	if len(changed) > 0 {
		d.Log.Info("sysctl изменены", "параметры", changed)
	}
	if err != nil {
		// Не фатально: например, в контейнере /proc/sys только для чтения.
		d.Log.Warn("sysctl", "ошибка", err)
	}

	entries := vpn.Entries()
	var static []netip.Prefix
	var domains int
	for _, e := range entries {
		if e.Kind == lists.KindNet {
			static = append(static, e.Prefix)
		} else {
			domains++
		}
	}
	recreated, err := firewall.Apply(d.nft, firewall.Spec{
		Iface:          cfg.Iface,
		LAN:            cfg.LANSubnet,
		RedirectPort:   cfg.VPNPort,
		QUICReject:     cfg.QUICReject,
		DynamicTimeout: cfg.VPNDynamicTimeout,
		Static:         static,
	})
	if err != nil {
		return "", err
	}
	if recreated {
		d.Log.Warn("таблица nftables пересоздана: адреса, узнанные из DNS, сброшены")
	}

	if err := d.syncDNS(ctx, dnsmasq.Render(cfg, entries, overrides), initial || recreated); err != nil {
		return "", err
	}
	return fmt.Sprintf("работает: доменов %d, IP/подсетей %d, DNS-override %d, режим %s",
		domains, len(static), len(overrides), cfg.VPNMode), nil
}

// syncDNS записывает конфиг dnsmasq и перезапускает его, если конфиг
// изменился (или force — после старта и пересоздания set'ов).
func (d *daemon) syncDNS(ctx context.Context, conf []byte, force bool) error {
	path := filepath.Join(d.RunDir, "dnsmasq.conf")
	old, _ := os.ReadFile(path)
	if !force && bytes.Equal(old, conf) {
		return nil
	}
	if err := os.MkdirAll(d.RunDir, 0o755); err != nil {
		return err
	}
	if err := writeAtomic(path, conf); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	m, err := d.Services(ctx)
	if err != nil {
		return err
	}
	defer m.Close()
	if err := m.Restart(ctx, dnsmasq.Unit); err != nil {
		return fmt.Errorf("перезапуск %s: %w", dnsmasq.Unit, err)
	}
	return nil
}

// cleanup убирает правила routerd (как stop в bash-версии); dnsmasq
// останавливает systemd (PartOf=routerd.service).
func (d *daemon) cleanup() {
	if err := firewall.Remove(d.nft); err != nil {
		d.Log.Error("удаление таблицы nftables", "ошибка", err)
	}
}

func notify(state ...string) {
	var b bytes.Buffer
	for _, s := range state {
		b.WriteString(s)
		b.WriteByte('\n')
	}
	_, _ = sddaemon.SdNotify(false, b.String())
}

// monotonicUsec — CLOCK_MONOTONIC в микросекундах: systemd требует его
// вместе с RELOADING=1 для Type=notify-reload.
func monotonicUsec() string {
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts); err != nil {
		return "0"
	}
	return strconv.FormatInt(ts.Nano()/1000, 10)
}

func writeAtomic(path string, data []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	_, werr := tmp.Write(data)
	cerr := tmp.Close()
	if err := errors.Join(werr, cerr); err != nil {
		return err
	}
	if err := os.Chmod(tmp.Name(), 0o644); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}
