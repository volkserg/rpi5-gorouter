//go:build linux

package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"

	"github.com/volkserg/rpi5-gorouter/internal/api"
	"github.com/volkserg/rpi5-gorouter/internal/cli"
	"github.com/volkserg/rpi5-gorouter/internal/config"
	"github.com/volkserg/rpi5-gorouter/internal/daemon"
	"github.com/volkserg/rpi5-gorouter/internal/localclient"
)

func runDaemon() int {
	env := cli.DefaultEnv()
	// В журнале systemd время уже есть — не дублируем.
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
			if a.Key == slog.TimeKey && len(groups) == 0 {
				return slog.Attr{}
			}
			return a
		},
	}))
	err := daemon.Run(context.Background(), daemon.Options{
		ConfigDir: env.ConfigDir,
		ProcRoot:  env.ProcRoot,
		StateDir:  env.StateDir,
		Log:       log,
		Services:  env.Services,
		Version:   version,
		APISocket: api.SocketPath(),
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "routerd: %v\n", err)
		return 1
	}
	return 0
}

// runLocalClient — routerd local-client up|down <имя>: сеть локального
// сервиса из LOCAL_CLIENTS (вызывается юнитом routerd-local@<имя>.service).
func runLocalClient(configDir string, args []string) int {
	if len(args) != 2 || (args[0] != "up" && args[0] != "down") {
		fmt.Fprintln(os.Stderr, "использование: routerd local-client up|down <имя>")
		return 2
	}
	name := args[1]
	if args[0] == "down" {
		// Конфиг не нужен: сервис могли уже убрать из LOCAL_CLIENTS.
		if err := localclient.Down(name); err != nil {
			fmt.Fprintf(os.Stderr, "routerd local-client down %s: %v\n", name, err)
			return 1
		}
		fmt.Printf("%s: сеть убрана\n", name)
		return 0
	}
	cfg, _, err := config.Load(config.Path(configDir))
	if err != nil {
		fmt.Fprintf(os.Stderr, "routerd local-client up %s: %v\n", name, err)
		return 1
	}
	l, ok := cfg.LocalClient(name)
	if !ok {
		fmt.Fprintf(os.Stderr, "routerd local-client up %s: сервиса нет в LOCAL_CLIENTS (%s)\n", name, config.Path(configDir))
		return 1
	}
	if err := localclient.Up(l, cfg.RPi5IP); err != nil {
		fmt.Fprintf(os.Stderr, "routerd local-client up %s: %v\n", name, err)
		return 1
	}
	fmt.Printf("%s: %s/%d в %s, шлюз %s (%s), DNS %s\n", name, l.ClientIP(), l.Net.Bits(),
		localclient.NetnsPath(name), l.HostIP(), l.Iface(), cfg.RPi5IP)
	return 0
}
