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
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/volkserg/rpi5-gorouter/internal/access"
	"github.com/volkserg/rpi5-gorouter/internal/api"
	"github.com/volkserg/rpi5-gorouter/internal/lists"
	"github.com/volkserg/rpi5-gorouter/internal/web"
)

const (
	demoUser     = "demo"
	demoPassword = "demo-password"
)

// Примерные списки демо (каталог конфигов создаётся заново при каждом запуске).
const (
	demoVPN = `# Внутренние ресурсы компании
corp.example.com
intranet.example.com
git.example.com
wiki.example.org
jira.example.org
# Подсети офиса и площадки
10.20.0.0/16
172.16.40.0/24
192.0.2.15
`
	demoOverrides = `# Внутренний DNS компании
corp.example.com 10.20.0.53
corp.example.com 10.20.0.54
intranet.example.com 10.20.0.53#5353
`
	demoConf = `LOCAL_CLIENTS="app:10.99.0.0/30"
`
)

type fake struct {
	mu      sync.Mutex
	dir     string
	started time.Time
	phase   int
	tracker *access.Tracker
	tunnel  api.TunnelCheck
}

func parseInt(s string) (int, error) { return strconv.Atoi(s) }
func itoa(n int) string              { return strconv.Itoa(n) }

func (f *fake) Access(q access.Query) (access.Result, bool) { return f.tracker.Query(q), true }

// vpnEntries — записи-домены из файла списка демо.
func (f *fake) vpnEntries() []string {
	l, _, err := lists.ReadVPN(filepath.Join(f.dir, lists.VPNFileName))
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range l.Entries() {
		if e.Kind == lists.KindDomain {
			out = append(out, e.Domain)
		}
	}
	return out
}

func (f *fake) Status() api.Status {
	f.mu.Lock()
	defer f.mu.Unlock()
	st := api.Status{
		Version: "demo", StartedAt: f.started, Mode: "tproxy", Failover: "closed",
		TunnelUp: true, LocalClients: 1, DHCP: true,
		RPiIP: "192.168.3.2", LAN: "192.168.3.0/24", Access: true, HistoryDays: 7,
	}
	if l, _, err := lists.ReadVPN(filepath.Join(f.dir, lists.VPNFileName)); err == nil {
		for _, e := range l.Entries() {
			if e.Kind == lists.KindDomain {
				st.Domains++
			} else {
				st.Nets++
			}
		}
	}
	if o, _, err := lists.ReadOverrides(filepath.Join(f.dir, lists.OverrideFileName)); err == nil {
		st.Overrides = len(o)
	}
	switch f.phase % 3 {
	case 1:
		st.TunnelUp = false
	case 2:
		st.TunnelUp, st.Failover, st.Bypass = false, "open", true
	}
	return st
}

// Apply — как у демона: короткая пауза на «применение».
func (f *fake) Apply(user, what string) error {
	slog.Info("применено", "пользователь", user, "изменение", what)
	time.Sleep(300 * time.Millisecond)
	return nil
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

	for name, text := range map[string]string{lists.VPNFileName: demoVPN, lists.OverrideFileName: demoOverrides, "router.conf": demoConf} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(text), 0o644); err != nil {
			fmt.Fprintln(os.Stderr, "webdemo:", err)
			os.Exit(1)
		}
	}
	f := &fake{dir: dir, started: time.Now().Add(-26 * time.Hour)}
	vpnHas := vpnChecker(f.vpnEntries)
	f.tracker = newTracker(vpnHas)
	go (&traffic{t: f.tracker, vpnHas: vpnHas}).run()
	sock := filepath.Join(dir, "api.sock")
	l, err := api.Listen(sock)
	if err != nil {
		fmt.Fprintln(os.Stderr, "webdemo: сокет API:", err)
		os.Exit(1)
	}
	go http.Serve(l, api.Handler(f, dir))
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
