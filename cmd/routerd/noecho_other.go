//go:build !linux

package main

import "os"

// withoutEcho: вне Linux эхо не выключается (команды web passwd нужны на RPi).
func withoutEcho(_ *os.File, fn func() error) error { return fn() }
