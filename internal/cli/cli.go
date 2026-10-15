// Package cli — команды управления routerd (rsc, router_service_ctl, routerd <команда>).
package cli

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"unicode/utf8"

	"github.com/volkserg/rpi5-gorouter/internal/config"
	"github.com/volkserg/rpi5-gorouter/internal/dhcp"
	"github.com/volkserg/rpi5-gorouter/internal/lists"
	"github.com/volkserg/rpi5-gorouter/internal/netcfg"
	"github.com/volkserg/rpi5-gorouter/internal/services"
)

// Env — окружение команды; в тестах подменяется.
type Env struct {
	// Prog — имя, под которым вызвана команда (rsc, routerd…), для подсказок.
	Prog           string
	Stdout, Stderr io.Writer
	ConfigDir      string
	Color          bool
	// ProcRoot — корень procfs (/proc).
	ProcRoot string
	// StateDir — каталог состояния routerd (аренды DHCP).
	StateDir string
	// IsRoot сообщает, запущена ли команда от root.
	IsRoot func() bool
	// Services подключается к systemd.
	Services func(context.Context) (services.Manager, error)
	// Journal печатает последние lines строк журнала юнита в w.
	Journal func(ctx context.Context, w io.Writer, unit string, lines int) error
	// NM подключается к NetworkManager по D-Bus.
	NM func() (netcfg.NM, func(), error)
}

// DefaultEnv — окружение процесса: каталог конфигов из ROUTERD_CONFIG_DIR
// (для стенда и тестов) или стандартный, цвет — только на терминале.
func DefaultEnv() Env {
	dir := os.Getenv("ROUTERD_CONFIG_DIR")
	if dir == "" {
		dir = config.DefaultDir
	}
	state := os.Getenv("ROUTERD_STATE_DIR")
	if state == "" {
		state = dhcp.DefaultStateDir
	}
	return Env{
		Prog:      DefaultProg,
		Stdout:    os.Stdout,
		Stderr:    os.Stderr,
		ConfigDir: dir,
		Color:     isTerminal(os.Stdout) && os.Getenv("NO_COLOR") == "",
		ProcRoot:  "/proc",
		StateDir:  state,
		IsRoot:    func() bool { return os.Geteuid() == 0 },
		Services:  services.Connect,
		Journal:   journalctl,
		NM: func() (netcfg.NM, func(), error) {
			n, err := netcfg.ConnectNM()
			if err != nil {
				return nil, nil, err
			}
			return n, n.Close, nil
		},
	}
}

// journalctl — единственный внешний вызов routerd (согласованное исключение):
// своего читателя журнала systemd без cgo нет.
func journalctl(ctx context.Context, w io.Writer, unit string, lines int) error {
	cmd := exec.CommandContext(ctx, "journalctl", "-u", unit, "--no-pager", "-n", strconv.Itoa(lines))
	cmd.Stdout, cmd.Stderr = w, w
	return cmd.Run()
}

func isTerminal(f *os.File) bool {
	st, err := f.Stat()
	return err == nil && st.Mode()&os.ModeCharDevice != 0
}

type command struct {
	name, args, help string
	run              func(*ctx, []string) int
}

// commands — в порядке вывода справки; пустая запись — разделитель групп.
var commands = []command{
	{"status", "", "Показать состояние всех компонентов", cmdStatus},
	{"info", "", "Показать информацию о конфигурации и конфигах", cmdInfo},
	{"start", "", "Запустить все компоненты", cmdStart},
	{"stop", "", "Остановить все компоненты", cmdStop},
	{"restart", "", "Перезапустить все компоненты", cmdRestart},
	{"apply-network", "[--dry-run|--confirm|--rollback]", "Применить сеть из router.conf (NetworkManager)", cmdApplyNetwork},
	{"logs", "", "Показать логи", cmdLogs},
	{"check-config", "[--router-conf|--vpn-file|--override-file <файл>]", "Проверить router.conf и списки (или отдельный файл)", cmdCheckConfig},
	{},
	{"add-vpn-domain", "<domain>", "Добавить домен для VPN", cmdAddDomain},
	{"remove-vpn-domain", "<domain>", "Удалить домен из VPN", cmdRemoveDomain},
	{"add-vpn-ip", "<ip|cidr>", "Добавить IP-адрес или подсеть для VPN", cmdAddIP},
	{"remove-vpn-ip", "<ip|cidr>", "Удалить IP-адрес или подсеть из VPN", cmdRemoveIP},
	{"list-vpn-domains", "", "Показать список доменов и IP для VPN", cmdListVPN},
	{"load-vpn-domains", "<file>", "Загрузить домены из файла", cmdLoadDomains},
	{"load-vpn-ips", "<file>", "Загрузить IP/CIDR из файла", cmdLoadIPs},
	{"reload-vpn-domains", "", "Перезагрузить список доменов и IP", cmdReload},
}

// ctx — состояние одного вызова команды.
type ctx struct {
	Env
	c palette
}

func (x *ctx) out(format string, a ...any) { fmt.Fprintf(x.Stdout, format+"\n", a...) }
func (x *ctx) okf(format string, a ...any) {
	fmt.Fprintf(x.Stdout, x.c.Green+format+x.c.NC+"\n", a...)
}
func (x *ctx) notef(format string, a ...any) {
	fmt.Fprintf(x.Stdout, x.c.Yellow+format+x.c.NC+"\n", a...)
}
func (x *ctx) errf(format string, a ...any) {
	fmt.Fprintf(x.Stderr, x.c.Red+format+x.c.NC+"\n", a...)
}
func (x *ctx) warnf(format string, a ...any) {
	fmt.Fprintf(x.Stderr, x.c.Yellow+format+x.c.NC+"\n", a...)
}

func (x *ctx) routerConf() string { return config.Path(x.ConfigDir) }
func (x *ctx) vpnFile() string    { return filepath.Join(x.ConfigDir, lists.VPNFileName) }
func (x *ctx) overrideFile() string {
	return filepath.Join(x.ConfigDir, lists.OverrideFileName)
}

// loadConfig читает router.conf и печатает предупреждения.
func (x *ctx) loadConfig() (*config.Config, bool) {
	cfg, warns, err := config.Load(x.routerConf())
	for _, w := range warns {
		x.warnf("Предупреждение: %s", w)
	}
	if err != nil {
		x.errf("Ошибка конфигурации: %v", err)
		return nil, false
	}
	return cfg, true
}

// DefaultProg — основное имя команды управления (symlink на routerd).
const DefaultProg = "rsc"

// Run выполняет команду управления и возвращает код выхода.
func Run(env Env, args []string) int {
	if env.Prog == "" {
		env.Prog = DefaultProg
	}
	x := &ctx{Env: env, c: newPalette(env.Color)}
	name := "help"
	if len(args) > 0 {
		name, args = args[0], args[1:]
	}
	switch name {
	case "help", "--help", "-h":
		x.usage()
		return 0
	}
	for _, c := range commands {
		if c.name != name || c.run == nil {
			continue
		}
		return c.run(x, args)
	}
	x.errf("Неизвестная команда: %s", name)
	fmt.Fprintf(x.Stdout, "Использование: %s help\n", x.Prog)
	return 1
}

func (x *ctx) usage() {
	x.out("Использование: %s <команда> [аргументы]", x.Prog)
	x.out("")
	x.out("Команды:")
	// Колонка описаний — по самой длинной строке до maxWidth; более длинные
	// строки команд переносят описание на следующую строку.
	const maxWidth = 50
	width := 0
	for _, c := range commands {
		if n := utf8.RuneCountInString(c.name+" "+c.args) + 2; n <= maxWidth {
			width = max(width, n)
		}
	}
	for _, c := range commands {
		if c.name == "" {
			x.out("")
			continue
		}
		cmd := c.name + " " + c.args
		if utf8.RuneCountInString(cmd)+2 > width {
			x.out("  %s", cmd)
			x.out("  %*s%s", width, "", c.help)
			continue
		}
		x.out("  %-*s%s", width, cmd, c.help)
	}
}

type palette struct{ Red, Green, Yellow, Cyan, NC string }

func newPalette(on bool) palette {
	if !on {
		return palette{}
	}
	return palette{Red: "\033[0;31m", Green: "\033[0;32m", Yellow: "\033[1;33m", Cyan: "\033[0;36m", NC: "\033[0m"}
}
