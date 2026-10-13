//go:build !linux

package dnsproxy

import "syscall"

func freebind(_, _ string, _ syscall.RawConn) error { return nil }
