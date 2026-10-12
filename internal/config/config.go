// Package config читает router.conf — центральный конфиг сети, общий с
// bash-версией router_service, — проверяет его и вычисляет производные
// параметры LAN (маска, broadcast).
package config

import (
	"errors"
	"fmt"
	"io/fs"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
)

const (
	// DefaultDir — каталог конфигов на устройстве.
	DefaultDir = "/usr/local/etc/router_service"
	// FileName — имя центрального конфига в каталоге конфигов.
	FileName = "router.conf"
	// RedirectPort — порт GOST redirect://, куда nftables заворачивает
	// TCP к VPN-адресам.
	RedirectPort = 1080
)

// Config — проверенные параметры сети из router.conf.
type Config struct {
	Iface     string
	NMConn    string
	RouterIP  netip.Addr
	RPi5IP    netip.Addr
	LANSubnet netip.Prefix
	PoolStart netip.Addr
	PoolEnd   netip.Addr
	// DNS — upstream DNS для самой RPi5 (DNS1, DNS2); пустые значения пропущены.
	DNS []netip.Addr
}

// Значения по умолчанию совпадают с дефолтами bash-скриптов
// (${VAR:-default}): пустое значение тоже заменяется дефолтом.
var defaults = map[string]string{
	"IFACE":          "eth0",
	"NM_CONN":        "netplan-eth0",
	"ROUTER_IP":      "192.168.3.1",
	"RPI5_IP":        "192.168.3.2",
	"LAN_SUBNET":     "192.168.3.0/24",
	"LAN_POOL_START": "192.168.3.100",
	"LAN_POOL_END":   "192.168.3.250",
	"DNS1":           "1.1.1.1",
	"DNS2":           "8.8.8.8",
}

// Warning — некритичное замечание к конфигу (неизвестный ключ, отсутствующий файл).
type Warning string

// Load читает router.conf по пути path. Отсутствие файла — не ошибка:
// как и bash-скрипты, используем встроенные значения и сообщаем об этом.
func Load(path string) (*Config, []Warning, error) {
	f, err := os.Open(path)
	if errors.Is(err, fs.ErrNotExist) {
		cfg, err := FromValues(nil)
		return cfg, []Warning{Warning(fmt.Sprintf("%s не найден, используются значения по умолчанию", path))}, err
	}
	if err != nil {
		return nil, nil, err
	}
	defer f.Close()

	assigns, err := ParseAssignments(f)
	if err != nil {
		return nil, nil, fmt.Errorf("%s: %w", path, err)
	}
	values := make(map[string]string, len(assigns))
	var warns []Warning
	for _, a := range assigns {
		if _, known := defaults[a.Key]; !known {
			warns = append(warns, Warning(fmt.Sprintf("%s:%d: неизвестный параметр %s — игнорируется", path, a.Line, a.Key)))
			continue
		}
		values[a.Key] = a.Value
	}
	cfg, err := FromValues(values)
	if err != nil {
		return nil, warns, fmt.Errorf("%s: %w", path, err)
	}
	return cfg, warns, nil
}

// Path возвращает путь к router.conf в каталоге dir.
func Path(dir string) string { return filepath.Join(dir, FileName) }

// FromValues строит и проверяет Config из сырых значений; отсутствующие
// и пустые ключи заменяются значениями по умолчанию.
func FromValues(values map[string]string) (*Config, error) {
	get := func(k string) string {
		if v := strings.TrimSpace(values[k]); v != "" {
			return v
		}
		return defaults[k]
	}

	var errs []error
	addr := func(k string) netip.Addr {
		a, err := netip.ParseAddr(get(k))
		if err != nil || !a.Is4() {
			errs = append(errs, fmt.Errorf("%s=%q: ожидается IPv4-адрес", k, get(k)))
			return netip.Addr{}
		}
		return a
	}

	cfg := &Config{
		Iface:     get("IFACE"),
		NMConn:    get("NM_CONN"),
		RouterIP:  addr("ROUTER_IP"),
		RPi5IP:    addr("RPI5_IP"),
		PoolStart: addr("LAN_POOL_START"),
		PoolEnd:   addr("LAN_POOL_END"),
	}
	for _, k := range []string{"DNS1", "DNS2"} {
		if a := addr(k); a.IsValid() {
			cfg.DNS = append(cfg.DNS, a)
		}
	}
	if p, err := netip.ParsePrefix(get("LAN_SUBNET")); err != nil || !p.Addr().Is4() {
		errs = append(errs, fmt.Errorf("LAN_SUBNET=%q: ожидается подсеть IPv4 в виде a.b.c.d/N", get("LAN_SUBNET")))
	} else {
		cfg.LANSubnet = p
	}
	if len(errs) > 0 {
		return nil, errors.Join(errs...)
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

// Validate проверяет согласованность адресации. Bash-версия этого не делала:
// ошибка в router.conf всплывала только при старте Kea или вообще молча.
func (c *Config) Validate() error {
	var errs []error
	fail := func(format string, a ...any) { errs = append(errs, fmt.Errorf(format, a...)) }

	if err := validIfaceName(c.Iface); err != nil {
		fail("IFACE=%q: %v", c.Iface, err)
	}
	if c.NMConn == "" {
		fail("NM_CONN: пустое имя подключения")
	}

	p := c.LANSubnet
	if p.Bits() < 8 || p.Bits() > 30 {
		fail("LAN_SUBNET=%s: длина префикса должна быть от 8 до 30", p)
		return errors.Join(errs...)
	}
	if p.Masked() != p {
		fail("LAN_SUBNET=%s: адрес должен быть адресом сети (%s)", p, p.Masked())
		return errors.Join(errs...)
	}

	for _, h := range []struct {
		key string
		a   netip.Addr
	}{
		{"ROUTER_IP", c.RouterIP},
		{"RPI5_IP", c.RPi5IP},
		{"LAN_POOL_START", c.PoolStart},
		{"LAN_POOL_END", c.PoolEnd},
	} {
		if !c.isHost(h.a) {
			fail("%s=%s: не является адресом узла в %s", h.key, h.a, p)
		}
	}
	if len(errs) > 0 {
		return errors.Join(errs...)
	}

	if c.RouterIP == c.RPi5IP {
		fail("ROUTER_IP и RPI5_IP совпадают (%s)", c.RPi5IP)
	}
	if c.PoolStart.Compare(c.PoolEnd) > 0 {
		fail("пул DHCP: LAN_POOL_START=%s больше LAN_POOL_END=%s", c.PoolStart, c.PoolEnd)
	}
	for _, h := range []struct {
		key string
		a   netip.Addr
	}{{"RPI5_IP", c.RPi5IP}, {"ROUTER_IP", c.RouterIP}} {
		if c.InPool(h.a) {
			fail("%s=%s попадает в пул DHCP %s - %s", h.key, h.a, c.PoolStart, c.PoolEnd)
		}
	}
	return errors.Join(errs...)
}

// isHost — адрес лежит в LAN и не совпадает с адресом сети или broadcast.
func (c *Config) isHost(a netip.Addr) bool {
	return a.IsValid() && c.LANSubnet.Contains(a) && a != c.LANSubnet.Addr() && a != c.Broadcast()
}

// InPool сообщает, входит ли адрес в пул DHCP.
func (c *Config) InPool(a netip.Addr) bool {
	return a.Compare(c.PoolStart) >= 0 && a.Compare(c.PoolEnd) <= 0
}

// Netmask — маска LAN в точечной нотации (24 → 255.255.255.0).
func (c *Config) Netmask() netip.Addr {
	m := ^uint32(0) << (32 - c.LANSubnet.Bits())
	return netip.AddrFrom4([4]byte{byte(m >> 24), byte(m >> 16), byte(m >> 8), byte(m)})
}

// Broadcast — broadcast-адрес LAN (адрес сети | ^маска).
func (c *Config) Broadcast() netip.Addr {
	n := c.LANSubnet.Masked().Addr().As4()
	m := c.Netmask().As4()
	for i := range n {
		n[i] |= ^m[i]
	}
	return netip.AddrFrom4(n)
}

func validIfaceName(s string) error {
	// Ограничения ядра Linux: IFNAMSIZ-1 символов, без '/', ':' и пробелов.
	if s == "" || len(s) > 15 || s == "." || s == ".." {
		return errors.New("недопустимое имя интерфейса")
	}
	if strings.ContainsAny(s, "/: \t") {
		return errors.New("недопустимые символы в имени интерфейса")
	}
	return nil
}
