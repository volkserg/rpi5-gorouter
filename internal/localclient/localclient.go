// Package localclient поднимает и убирает сетевое окружение локального
// сервиса RPi (LOCAL_CLIENTS): именованный network namespace, veth-пару с
// адресами и маршрутом по умолчанию через RPi, resolv.conf с DNS routerd.
//
// Вызывается из юнита routerd-local@<имя>.service (routerd local-client
// up|down <имя>), а не из демона: создание namespace требует CAP_SYS_ADMIN
// и общего с системой пространства монтирования, а демон работает в
// урезанном юните. Правила nftables для сервиса применяет демон — по имени
// veth, поэтому порядок запуска юнитов не важен.
package localclient

import (
	"path/filepath"
)

const (
	// NetnsDir — каталог именованных network namespace (как у ip netns).
	NetnsDir = "/run/netns"
	// ResolvDir — каталог resolv.conf для namespace (как у ip netns exec).
	ResolvDir = "/etc/netns"
	// PeerIface — имя veth внутри namespace сервиса.
	PeerIface = "eth0"
)

// NetnsPath — путь к namespace сервиса (для NetworkNamespacePath= в юните).
func NetnsPath(name string) string { return filepath.Join(NetnsDir, name) }

// ResolvPath — resolv.conf сервиса (для BindReadOnlyPaths= в юните).
func ResolvPath(name string) string { return filepath.Join(ResolvDir, name, "resolv.conf") }
