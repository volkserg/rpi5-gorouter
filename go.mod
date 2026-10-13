module github.com/volkserg/rpi5-gorouter

// 1.24 — версия golang из Debian 13 (trixie): модуль должен собираться
// и пакетным Go в VM стенда, и на самой RPi.
go 1.24

require github.com/coreos/go-systemd/v22 v22.7.0

require github.com/godbus/dbus/v5 v5.1.0 // indirect
