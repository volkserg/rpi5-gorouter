package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"syscall"

	"github.com/volkserg/rpi5-gorouter/internal/api"
	"github.com/volkserg/rpi5-gorouter/internal/config"
	"github.com/volkserg/rpi5-gorouter/internal/web"
)

// defaultWebState — каталог ключа сессий и сертификата, если systemd не
// передал STATE_DIRECTORY (StateDirectory=routerd-web).
const defaultWebState = "/var/lib/routerd-web"

const webUsage = `Использование:
  routerd web serve             веб-интерфейс (запускается юнитом routerd-web.service)
  routerd web passwd <логин>    добавить пользователя или сменить пароль
  routerd web deluser <логин>   удалить пользователя
  routerd web users             список пользователей
  routerd web check <логин>     код 0, если пароль из stdin верный (для автоматизации)

Пароль вводится с терминала дважды или одной строкой из stdin:
  echo 'пароль' | sudo routerd web passwd admin
`

// runWeb — routerd web <команда>.
func runWeb(configDir string, args []string) int {
	if len(args) == 0 {
		fmt.Fprint(os.Stderr, webUsage)
		return 2
	}
	users := filepath.Join(configDir, web.UsersFileName)
	cmd, rest := args[0], args[1:]
	needLogin := func() (string, bool) {
		if len(rest) != 1 {
			fmt.Fprint(os.Stderr, webUsage)
			return "", false
		}
		return rest[0], true
	}
	switch cmd {
	case "serve":
		return webServe(configDir, users)
	case "users":
		m, err := web.ReadUsers(users)
		if err != nil {
			return fail("routerd web users: %v", err)
		}
		if len(m) == 0 {
			fmt.Println("(нет пользователей)")
			return 0
		}
		names := make([]string, 0, len(m))
		for n := range m {
			names = append(names, n)
		}
		sort.Strings(names)
		fmt.Println(strings.Join(names, "\n"))
		return 0
	case "passwd":
		name, ok := needLogin()
		if !ok {
			return 2
		}
		return webPasswd(users, name)
	case "deluser":
		name, ok := needLogin()
		if !ok {
			return 2
		}
		m, err := web.ReadUsers(users)
		if err != nil {
			return fail("routerd web deluser: %v", err)
		}
		if _, ok := m[name]; !ok {
			return fail("Пользователя %s нет.", name)
		}
		delete(m, name)
		if err := web.WriteUsers(users, m, web.WebGID()); err != nil {
			return fail("routerd web deluser: %v", err)
		}
		fmt.Printf("Пользователь %s удалён, его сессии завершены.\n", name)
		return 0
	case "check":
		name, ok := needLogin()
		if !ok {
			return 2
		}
		m, err := web.ReadUsers(users)
		if err != nil {
			return fail("routerd web check: %v", err)
		}
		pw, err := bufio.NewReader(os.Stdin).ReadString('\n')
		if err != nil && !errors.Is(err, io.EOF) {
			return fail("routerd web check: %v", err)
		}
		if h, ok := m[name]; ok && web.VerifyPassword(strings.TrimRight(pw, "\r\n"), h) {
			return 0
		}
		return 1
	case "help", "-h", "--help":
		fmt.Print(webUsage)
		return 0
	}
	fmt.Fprint(os.Stderr, webUsage)
	return 2
}

func fail(format string, a ...any) int {
	fmt.Fprintf(os.Stderr, format+"\n", a...)
	return 1
}

func webPasswd(path, name string) int {
	if err := web.ValidLogin(name); err != nil {
		return fail("Ошибка: %v", err)
	}
	pw, err := readPassword()
	if err != nil {
		return fail("Ошибка: %v", err)
	}
	if len([]rune(pw)) < web.MinPasswordLen {
		return fail("Ошибка: пароль должен быть не короче %d символов.", web.MinPasswordLen)
	}
	m, err := web.ReadUsers(path)
	if err != nil {
		return fail("Ошибка: %v", err)
	}
	hash, err := web.HashPassword(pw)
	if err != nil {
		return fail("Ошибка: %v", err)
	}
	action := "добавлен"
	if _, ok := m[name]; ok {
		action = "обновлён (прежние сессии завершены)"
	}
	m[name] = hash
	if err := web.WriteUsers(path, m, web.WebGID()); err != nil {
		return fail("Ошибка: %v", err)
	}
	fmt.Printf("Пользователь %s %s.\n", name, action)
	if web.WebGID() < 0 {
		fmt.Printf("Внимание: группы %s нет — сервис веб-интерфейса не прочитает %s. Установите routerd заново (install.sh или роль).\n", api.WebGroup, path)
	}
	return 0
}

// readPassword — пароль с терминала (дважды, без эха) или строкой из stdin.
func readPassword() (string, error) {
	st, err := os.Stdin.Stat()
	if err != nil || st.Mode()&os.ModeCharDevice == 0 {
		line, err := bufio.NewReader(os.Stdin).ReadString('\n')
		if err != nil && !errors.Is(err, io.EOF) {
			return "", err
		}
		return strings.TrimRight(line, "\r\n"), nil
	}
	in := bufio.NewReader(os.Stdin)
	ask := func(prompt string) (string, error) {
		fmt.Fprint(os.Stderr, prompt)
		var s string
		err := withoutEcho(os.Stdin, func() error {
			var err error
			s, err = in.ReadString('\n')
			return err
		})
		fmt.Fprintln(os.Stderr)
		return strings.TrimRight(s, "\r\n"), err
	}
	first, err := ask("Пароль: ")
	if err != nil {
		return "", err
	}
	second, err := ask("Повторите пароль: ")
	if err != nil {
		return "", err
	}
	if first != second {
		return "", errors.New("пароли не совпадают")
	}
	return first, nil
}

func webServe(configDir, users string) int {
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
			if a.Key == slog.TimeKey && len(groups) == 0 {
				return slog.Attr{}
			}
			return a
		},
	}))
	cfg, _, err := config.Load(config.Path(configDir))
	if err != nil {
		return fail("routerd web serve: %v", err)
	}
	if !cfg.WebUI {
		fmt.Fprintln(os.Stderr, "routerd web serve: веб-интерфейс выключен (WEB_UI=no в router.conf)")
		return 0
	}
	state := os.Getenv("STATE_DIRECTORY")
	if state == "" {
		state = defaultWebState
	}
	listen := netip.AddrPortFrom(cfg.RPi5IP, cfg.WebPort)
	// Стенд: адрес, на котором слушать (сервис работает в namespace RPi).
	if v := os.Getenv("ROUTERD_WEB_LISTEN"); v != "" {
		if listen, err = netip.ParseAddrPort(v); err != nil {
			return fail("ROUTERD_WEB_LISTEN: %v", err)
		}
	}
	names := []string{}
	if h, err := os.Hostname(); err == nil && h != "" {
		h = strings.ToLower(strings.TrimSuffix(h, "."+cfg.LocalDomain))
		names = append(names, h, h+"."+cfg.LocalDomain)
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	err = web.Serve(ctx, web.Options{
		Listen:    listen,
		UsersFile: users,
		StateDir:  state,
		APISocket: api.SocketPath(),
		CertIPs:   []netip.Addr{cfg.RPi5IP},
		CertNames: names,
		Version:   version,
		Log:       log,
	})
	if err != nil {
		return fail("routerd web serve: %v", err)
	}
	return 0
}
