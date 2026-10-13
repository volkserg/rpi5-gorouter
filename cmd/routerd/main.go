// Command routerd — router_service на Go.
//
// Один бинарник, два имени:
//
//	routerd run                   демон (systemd-юнит routerd.service)
//	routerd ctl <команда> …       CLI (то же, что router_service_ctl)
//	router_service_ctl <команда>  через symlink на routerd
//	routerd version
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime/debug"

	"github.com/volkserg/rpi5-gorouter/internal/cli"
)

// version задаётся при сборке: -ldflags "-X main.version=…".
var version = "dev"

func main() {
	os.Exit(run(os.Args))
}

func run(args []string) int {
	env := cli.DefaultEnv()
	if filepath.Base(args[0]) == "router_service_ctl" {
		return cli.Run(env, args[1:])
	}
	if len(args) < 2 {
		usage()
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
	case "help", "--help", "-h":
		usage()
		return 0
	}
	fmt.Fprintf(os.Stderr, "routerd: неизвестная команда %q\n", args[1])
	usage()
	return 2
}

func usage() {
	fmt.Fprint(os.Stderr, `Использование:
  routerd run                         демон (запускается systemd)
  routerd ctl <команда> [аргументы]   команды router_service_ctl (routerd ctl help)
  routerd version                     версия сборки
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
