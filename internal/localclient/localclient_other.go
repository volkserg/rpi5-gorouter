//go:build !linux

package localclient

import (
	"errors"
	"net/netip"

	"github.com/volkserg/rpi5-gorouter/internal/config"
)

var errLinux = errors.New("network namespace есть только в Linux")

// Up — только Linux.
func Up(config.LocalClient, netip.Addr) error { return errLinux }

// Down — только Linux.
func Down(string) error { return errLinux }
