//go:build !linux

package main

import (
	"fmt"
	"os"
)

func runDaemon() int {
	fmt.Fprintln(os.Stderr, "routerd run: демон работает только на Linux")
	return 1
}
