// Command webdemo — веб-интерфейс routerd на машине разработчика (macOS или
// Linux) с поддельным демоном: посмотреть страницы без стенда.
//
//	go run ./testbed/webdemo            https://127.0.0.1:8443, вход demo / demo-password
//	go run ./testbed/webdemo -listen 127.0.0.1:9443
//
// Состояние туннеля меняется само (доступен → недоступен → перехват снят),
// числа в списках — тоже, чтобы были видны все состояния панели.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/volkserg/rpi5-gorouter/internal/api"
	"github.com/volkserg/rpi5-gorouter/internal/web"
)

const (
	demoUser     = "demo"
	demoPassword = "demo-password"
)

type fake struct {
	mu      sync.Mutex
	started time.Time
	phase   int
}

func (f *fake) Status() api.Status {
	f.mu.Lock()
	defer f.mu.Unlock()
	st := api.Status{
		Version: "demo", StartedAt: f.started, Mode: "tproxy", Failover: "closed",
		TunnelUp: true, Domains: 214, Nets: 37, Overrides: 3, LocalClients: 2, DHCP: true,
		RPiIP: "192.168.3.2", LAN: "192.168.3.0/24",
	}
	switch f.phase % 3 {
	case 1:
		st.TunnelUp = false
	case 2:
		st.TunnelUp, st.Failover, st.Bypass = false, "open", true
	}
	st.Domains += f.phase % 4
	return st
}

func main() {
	listen := flag.String("listen", "127.0.0.1:8443", "адрес веб-интерфейса")
	period := flag.Duration("period", 20*time.Second, "как часто меняется состояние туннеля")
	flag.Parse()
	log := slog.New(slog.NewTextHandler(os.Stderr, nil))

	ap, err := netip.ParseAddrPort(*listen)
	if err != nil {
		fmt.Fprintln(os.Stderr, "webdemo:", err)
		os.Exit(2)
	}
	// Короткий путь: длина пути unix-сокета ограничена.
	dir, err := os.MkdirTemp("", "webdemo")
	if err != nil {
		fmt.Fprintln(os.Stderr, "webdemo:", err)
		os.Exit(1)
	}
	defer os.RemoveAll(dir)

	hash, err := web.HashPassword(demoPassword)
	if err == nil {
		err = web.WriteUsers(filepath.Join(dir, web.UsersFileName), map[string]string{demoUser: hash}, -1)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "webdemo:", err)
		os.Exit(1)
	}

	f := &fake{started: time.Now().Add(-26 * time.Hour)}
	sock := filepath.Join(dir, "api.sock")
	l, err := api.Listen(sock)
	if err != nil {
		fmt.Fprintln(os.Stderr, "webdemo: сокет API:", err)
		os.Exit(1)
	}
	go http.Serve(l, api.Handler(f))
	go func() {
		for range time.Tick(*period) {
			f.mu.Lock()
			f.phase++
			f.mu.Unlock()
		}
	}()

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	fmt.Fprintf(os.Stderr, "Веб-интерфейс: https://%s  вход: %s / %s (сертификат самоподписанный)\n", ap, demoUser, demoPassword)
	err = web.Serve(ctx, web.Options{
		Listen:    ap,
		UsersFile: filepath.Join(dir, web.UsersFileName),
		StateDir:  dir,
		APISocket: sock,
		CertIPs:   []netip.Addr{ap.Addr()},
		CertNames: []string{"localhost"},
		Version:   "demo",
		Log:       log,
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "webdemo:", err)
		os.Exit(1)
	}
}
