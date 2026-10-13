module github.com/volkserg/rpi5-gorouter

// 1.25 — минимум для актуальных зависимостей. Бинарник собирается на машине
// разработчика (кросс-компиляция, статический); на Debian 13 Go 1.25+ есть в
// trixie-backports, а штатный 1.24 сам скачает нужный тулчейн (GOTOOLCHAIN=auto).
go 1.25.0

require (
	github.com/BurntSushi/toml v1.6.0
	github.com/coreos/go-systemd/v22 v22.7.0
	github.com/godbus/dbus/v5 v5.1.0
	github.com/google/nftables v0.3.0
	github.com/insomniacslk/dhcp v0.0.0-20260901064844-234b97448fae
	github.com/miekg/dns v1.1.73
	github.com/vishvananda/netlink v1.3.1
	github.com/vishvananda/netns v0.0.5
	golang.org/x/sys v0.47.0
)

require (
	github.com/google/go-cmp v0.6.0 // indirect
	github.com/josharian/native v1.1.0 // indirect
	github.com/mdlayher/netlink v1.7.3-0.20250113171957-fbb4dce95f42 // indirect
	github.com/mdlayher/socket v0.5.0 // indirect
	github.com/pierrec/lz4/v4 v4.1.14 // indirect
	github.com/u-root/uio v0.0.0-20230220225925-ffce2a382923 // indirect
	golang.org/x/net v0.57.0 // indirect
	golang.org/x/sync v0.22.0 // indirect
)
