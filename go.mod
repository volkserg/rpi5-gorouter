module github.com/volkserg/rpi5-gorouter

// 1.24 — версия golang из Debian 13 (trixie): модуль должен собираться
// и пакетным Go в VM стенда, и на самой RPi.
go 1.24.0

require (
	github.com/coreos/go-systemd/v22 v22.7.0
	github.com/google/nftables v0.3.0
	github.com/miekg/dns v1.1.72
	github.com/vishvananda/netlink v1.3.1
	github.com/vishvananda/netns v0.0.5
	golang.org/x/sys v0.39.0
)

require (
	github.com/godbus/dbus/v5 v5.1.0 // indirect
	github.com/google/go-cmp v0.6.0 // indirect
	github.com/mdlayher/netlink v1.7.3-0.20250113171957-fbb4dce95f42 // indirect
	github.com/mdlayher/socket v0.5.0 // indirect
	golang.org/x/mod v0.31.0 // indirect
	golang.org/x/net v0.48.0 // indirect
	golang.org/x/sync v0.19.0 // indirect
	golang.org/x/tools v0.40.0 // indirect
)
