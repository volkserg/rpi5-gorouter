// Command routerd — шлюз LAN для Raspberry Pi 5.
//
// Один бинарник, несколько имён:
//
//	routerd run                   демон (systemd-юнит routerd.service)
//	routerd version
//	routerd completion bash|zsh   автодополнение rsc и router_service_ctl
//	routerd local-client up|down <имя>  сеть локального сервиса (routerd-local@.service)
//	routerd <команда> …           команды управления (routerd ctl <команда> — то же)
//	rsc <команда> …               то же через symlink на routerd
//	router_service_ctl <команда>  то же через symlink на routerd
package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime/debug"

	"github.com/volkserg/rpi5-gorouter/internal/cli"
)

// version задаётся при сборке: -ldflags "-X main.version=…".
var version = "dev"

// ctlNames — имена symlink'ов, под которыми бинарник работает как команда управления.
var ctlNames = map[string]bool{cli.DefaultProg: true, "router_service_ctl": true}

func main() {
	os.Exit(run(os.Args))
}

func run(args []string) int {
	env := cli.DefaultEnv()
	if base := filepath.Base(args[0]); ctlNames[base] {
		env.Prog = base
		return cli.Run(env, args[1:])
	}
	env.Prog = "routerd"
	if len(args) < 2 {
		usage(os.Stderr)
		return 2
	}
	switch args[1] {
	case "run":
		return runDaemon()
	case "ctl":
		return cli.Run(env, args[2:])
	case "version", "--version":
		fmt.Println(versionString())
		return 0
	case "completion":
		shell := ""
		if len(args) > 2 {
			shell = args[2]
		}
		if err := cli.Completion(os.Stdout, shell); err != nil {
			fmt.Fprintln(os.Stderr, "routerd:", err)
			return 2
		}
		return 0
	case "local-client":
		return runLocalClient(env.ConfigDir, args[2:])
	case "help", "--help", "-h":
		usage(os.Stdout)
		fmt.Println()
		return cli.Run(env, []string{"help"})
	}
	return cli.Run(env, args[1:])
}

func usage(w io.Writer) {
	fmt.Fprint(w, `Использование:
  routerd run                         демон (запускается systemd)
  routerd version                     версия сборки
  routerd completion <bash|zsh>       автодополнение rsc и router_service_ctl
  routerd local-client <up|down> <имя> сеть локального сервиса (из routerd-local@<имя>.service)
  routerd <команда> [аргументы]       команды управления (routerd help; короче — rsc <команда>)
`)
}

func versionString() string {
	v := version
	if bi, ok := debug.ReadBuildInfo(); ok {
		for _, s := range bi.Settings {
			if s.Key == "vcs.revision" && len(s.Value) >= 12 {
				v += " (" + s.Value[:12] + ")"
			}
		}
	}
	return "routerd " + v
}
