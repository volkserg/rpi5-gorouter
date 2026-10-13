//go:build linux

package dnsproxy

import (
	"syscall"

	"golang.org/x/sys/unix"
)

// freebind разрешает привязку к адресу, которого ещё нет на интерфейсе:
// routerd может стартовать раньше, чем NetworkManager назначит статический IP.
func freebind(_, _ string, c syscall.RawConn) error {
	var serr error
	err := c.Control(func(fd uintptr) {
		serr = unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_FREEBIND, 1)
	})
	if err != nil {
		return err
	}
	return serr
}
