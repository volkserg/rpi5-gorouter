//go:build linux

package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"

	"github.com/volkserg/rpi5-gorouter/internal/cli"
	"github.com/volkserg/rpi5-gorouter/internal/daemon"
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
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "routerd: %v\n", err)
		return 1
	}
	return 0
}
