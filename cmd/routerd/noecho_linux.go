//go:build linux

package main

import (
	"os"

	"golang.org/x/sys/unix"
)

// withoutEcho выполняет fn с выключенным эхом терминала (ввод пароля).
func withoutEcho(f *os.File, fn func() error) error {
	fd := int(f.Fd())
	old, err := unix.IoctlGetTermios(fd, unix.TCGETS)
	if err != nil {
		return fn()
	}
	t := *old
	t.Lflag &^= unix.ECHO
	if err := unix.IoctlSetTermios(fd, unix.TCSETS, &t); err != nil {
		return fn()
	}
	defer unix.IoctlSetTermios(fd, unix.TCSETS, old)
	return fn()
}
