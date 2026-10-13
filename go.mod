module github.com/volkserg/rpi5-gorouter

// 1.24 — версия golang из Debian 13 (trixie): модуль должен собираться
// и пакетным Go в VM стенда, и на самой RPi.
go 1.24

require (
	github.com/coreos/go-systemd/v22 v22.7.0
	github.com/google/nftables v0.3.0
	golang.org/x/sys v0.28.0
)

require (
	github.com/godbus/dbus/v5 v5.1.0 // indirect
	github.com/google/go-cmp v0.6.0 // indirect
	github.com/mdlayher/netlink v1.7.3-0.20250113171957-fbb4dce95f42 // indirect
	github.com/mdlayher/socket v0.5.0 // indirect
	golang.org/x/net v0.33.0 // indirect
	golang.org/x/sync v0.6.0 // indirect
)
