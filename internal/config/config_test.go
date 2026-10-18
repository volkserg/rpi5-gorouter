package config

import (
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestParseAssignments(t *testing.T) {
	in := `
# комментарий
IFACE=eth1
export NM_CONN="my conn"
ROUTER_IP='10.0.0.1'   # хвостовой комментарий
RPI5_IP=10.0.0."2"
DNS1="1.1.1.1"
EMPTY=
`
	got, err := ParseAssignments(strings.NewReader(in))
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{
		"IFACE": "eth1", "NM_CONN": "my conn", "ROUTER_IP": "10.0.0.1",
		"RPI5_IP": "10.0.0.2", "DNS1": "1.1.1.1", "EMPTY": "",
	}
	if len(got) != len(want) {
		t.Fatalf("got %d assignments, want %d: %+v", len(got), len(want), got)
	}
	for _, a := range got {
		if want[a.Key] != a.Value {
			t.Errorf("%s = %q, want %q", a.Key, a.Value, want[a.Key])
		}
	}
}

func TestParseAssignmentsRejects(t *testing.T) {
	for _, in := range []string{
		"IFACE=$OTHER",
		`IFACE="${X}"`,
		"IFACE=`hostname`",
		"IFACE=eth0; rm -rf /",
		"IFACE=eth 0",
		`IFACE="eth0`,
		"IFACE='eth0",
		"1FACE=eth0",
		"IFACE =eth0",
		"just a command",
	} {
		if _, err := ParseAssignments(strings.NewReader(in)); err == nil {
			t.Errorf("%q: ожидалась ошибка", in)
		}
	}
}

func TestDefaultsMatchReference(t *testing.T) {
	cfg, err := FromValues(nil)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Iface != "eth0" || cfg.NMConn != "netplan-eth0" ||
		cfg.RouterIP.String() != "192.168.3.1" || cfg.RPi5IP.String() != "192.168.3.2" ||
		cfg.LANSubnet.String() != "192.168.3.0/24" ||
		cfg.PoolStart.String() != "192.168.3.100" || cfg.PoolEnd.String() != "192.168.3.250" ||
		len(cfg.DNS) != 2 || cfg.DNS[0].String() != "1.1.1.1" || cfg.DNS[1].String() != "8.8.8.8" {
		t.Errorf("неожиданные значения по умолчанию: %+v", cfg)
	}
}

func TestDerived(t *testing.T) {
	for _, tc := range []struct {
		subnet, router, rpi, start, end string
		mask, bcast                     string
	}{
		{"192.168.3.0/24", "192.168.3.1", "192.168.3.2", "192.168.3.100", "192.168.3.250", "255.255.255.0", "192.168.3.255"},
		{"10.10.0.0/16", "10.10.0.1", "10.10.0.2", "10.10.1.0", "10.10.1.255", "255.255.0.0", "10.10.255.255"},
		{"192.168.4.0/23", "192.168.4.1", "192.168.4.2", "192.168.5.0", "192.168.5.200", "255.255.254.0", "192.168.5.255"},
		{"172.16.0.0/30", "172.16.0.1", "172.16.0.2", "172.16.0.1", "172.16.0.0", "255.255.255.252", "172.16.0.3"},
	} {
		v := map[string]string{"LAN_SUBNET": tc.subnet, "ROUTER_IP": tc.router, "RPI5_IP": tc.rpi,
			"LAN_POOL_START": tc.start, "LAN_POOL_END": tc.end}
		c := &Config{LANSubnet: netip.MustParsePrefix(tc.subnet)}
		if got := c.Netmask().String(); got != tc.mask {
			t.Errorf("%s: netmask %s, want %s", tc.subnet, got, tc.mask)
		}
		if got := c.Broadcast().String(); got != tc.bcast {
			t.Errorf("%s: broadcast %s, want %s", tc.subnet, got, tc.bcast)
		}
		if tc.subnet == "172.16.0.0/30" {
			continue // в /30 нет места под пул — только проверка маски
		}
		if _, err := FromValues(v); err != nil {
			t.Errorf("%s: %v", tc.subnet, err)
		}
	}
}

func TestValidateErrors(t *testing.T) {
	for name, v := range map[string]map[string]string{
		"не адрес сети":          {"LAN_SUBNET": "192.168.3.5/24"},
		"префикс /31":            {"LAN_SUBNET": "192.168.3.0/31"},
		"роутер вне подсети":     {"ROUTER_IP": "192.168.4.1"},
		"rpi = broadcast":        {"RPI5_IP": "192.168.3.255"},
		"rpi = роутер":           {"RPI5_IP": "192.168.3.1"},
		"пул перевёрнут":         {"LAN_POOL_START": "192.168.3.200", "LAN_POOL_END": "192.168.3.100"},
		"rpi в пуле":             {"RPI5_IP": "192.168.3.150"},
		"пул вне подсети":        {"LAN_POOL_END": "192.168.4.10"},
		"битый октет":            {"ROUTER_IP": "192.168.3.999"},
		"IPv6 вместо IPv4":       {"DNS1": "2606:4700::1111"},
		"длинное имя интерфейса": {"IFACE": "averyveryverylongname"},
		"слэш в интерфейсе":      {"IFACE": "eth/0"},
	} {
		if _, err := FromValues(v); err == nil {
			t.Errorf("%s: ожидалась ошибка", name)
		}
	}
}

func TestLoad(t *testing.T) {
	dir := t.TempDir()

	cfg, warns, err := Load(Path(dir))
	if err != nil || cfg == nil || len(warns) != 1 {
		t.Fatalf("отсутствующий файл: cfg=%v warns=%v err=%v", cfg, warns, err)
	}

	conf := "IFACE=eth1\nUNKNOWN_KEY=1\nRPI5_IP=192.168.3.3\n"
	if err := os.WriteFile(filepath.Join(dir, FileName), []byte(conf), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, warns, err = Load(Path(dir))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Iface != "eth1" || cfg.RPi5IP.String() != "192.168.3.3" || cfg.RouterIP.String() != "192.168.3.1" {
		t.Errorf("неожиданный конфиг: %+v", cfg)
	}
	if len(warns) != 1 || !strings.Contains(string(warns[0]), "UNKNOWN_KEY") {
		t.Errorf("ожидалось предупреждение про UNKNOWN_KEY: %v", warns)
	}
}

// Поставляемый пример конфига должен читаться без ошибок и предупреждений.
func TestExampleRouterConf(t *testing.T) {
	cfg, warns, err := Load(filepath.Join("..", "..", "deploy", "config", "router.conf"))
	if err != nil {
		t.Fatal(err)
	}
	if len(warns) != 0 {
		t.Errorf("предупреждения: %v", warns)
	}
	if cfg.LANSubnet.String() != "192.168.3.0/24" || cfg.NMConn != "netplan-eth0" {
		t.Errorf("неожиданный конфиг: %+v", cfg)
	}
}

func TestRouterdKeys(t *testing.T) {
	cfg, err := FromValues(nil)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.VPNMode != ModeRedirect || cfg.VPNPort != 1080 || !cfg.QUICReject ||
		cfg.VPNDynamicTimeout != 24*time.Hour || cfg.DNSUpstream.String() != "127.0.0.1:5353" ||
		cfg.FilterAAAA != FilterAAAAVPN || !cfg.DNSECS ||
		!cfg.DHCPEnabled || cfg.DHCPLeaseTime != 24*time.Hour || cfg.LocalDomain != "lan" ||
		!cfg.PiholeManage || cfg.PiholeTOML != "/etc/pihole/pihole.toml" || cfg.DNSCryptAddr.String() != "127.0.0.1:5053" {
		t.Errorf("дефолты: %+v", cfg)
	}
	cfg, err = FromValues(map[string]string{"VPN_PORT": "12345", "QUIC_REJECT": "no",
		"VPN_DYNAMIC_TIMEOUT": "30s", "DNS_UPSTREAM": "10.0.0.53"})
	if err != nil {
		t.Fatal(err)
	}
	if c2, err := FromValues(map[string]string{"VPN_MODE": "route", "VPN_FAILOVER": "open", "VPN_TUN": "wg1"}); err != nil ||
		c2.VPNMode != ModeRoute || !c2.VPNFailoverOpen || c2.VPNTun != "wg1" {
		t.Errorf("route/open/wg1: %+v %v", c2, err)
	}
	if cfg.VPNPort != 12345 || cfg.QUICReject || cfg.VPNDynamicTimeout != 30*time.Second || cfg.DNSUpstream.String() != "10.0.0.53:53" {
		t.Errorf("заданные значения: %+v", cfg)
	}
	for name, v := range map[string]map[string]string{
		"неизвестный режим":  {"VPN_MODE": "magic"},
		"VPN_FAILOVER=maybe": {"VPN_FAILOVER": "maybe"},
		"FILTER_AAAA=some":   {"FILTER_AAAA": "some"},
		"DNS_ECS=maybe":      {"DNS_ECS": "maybe"},
		"аренда 10s":         {"DHCP_LEASE_TIME": "10s"},
		"PIHOLE_TOML отн.":   {"PIHOLE_TOML": "pihole.toml"},
		"домен с пробелом":   {"LOCAL_DOMAIN": "my lan"},
		"VPN_TUN со слэшем":  {"VPN_TUN": "tun/0"},
		"порт 0":             {"VPN_PORT": "0"},
		"QUIC_REJECT=maybe":  {"QUIC_REJECT": "maybe"},
		"таймаут меньше 1s":  {"VPN_DYNAMIC_TIMEOUT": "500ms"},
		"upstream не IP":     {"DNS_UPSTREAM": "pihole.lan"},
	} {
		if _, err := FromValues(v); err == nil {
			t.Errorf("%s: ожидалась ошибка", name)
		}
	}
}

func TestVPNService(t *testing.T) {
	for in, want := range map[string]string{"": "gost-run.service", "gost-run": "gost-run.service", "vpn@corp.service": "vpn@corp.service"} {
		cfg, err := FromValues(map[string]string{"VPN_SERVICE": in})
		if err != nil || cfg.VPNService != want {
			t.Errorf("%q: %v %v, ожидалось %s", in, cfg, err, want)
		}
	}
	for _, bad := range []string{"gost run", "gost-run.socket", "../x.service"} {
		if _, err := FromValues(map[string]string{"VPN_SERVICE": bad}); err == nil {
			t.Errorf("%q: ожидалась ошибка", bad)
		}
	}
}

func TestLocalClients(t *testing.T) {
	cfg, err := FromValues(nil)
	if err != nil || len(cfg.LocalClients) != 0 {
		t.Fatalf("по умолчанию локальных сервисов нет: %v %v", cfg.LocalClients, err)
	}
	cfg, err = FromValues(map[string]string{"LOCAL_CLIENTS": " app:10.99.0.0/30   web-2:10.99.0.8/29 "})
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.LocalClients) != 2 {
		t.Fatalf("сервисы: %+v", cfg.LocalClients)
	}
	app, ok := cfg.LocalClient("app")
	if !ok || app.Iface() != "rc-app" || app.HostIP().String() != "10.99.0.1" || app.ClientIP().String() != "10.99.0.2" {
		t.Errorf("app: %+v %s %s %s", app, app.Iface(), app.HostIP(), app.ClientIP())
	}
	if web, _ := cfg.LocalClient("web-2"); web.HostIP().String() != "10.99.0.9" || web.ClientIP().String() != "10.99.0.10" {
		t.Errorf("web-2: %s %s", web.HostIP(), web.ClientIP())
	}
	if _, ok := cfg.LocalClient("nope"); ok {
		t.Error("неизвестное имя найдено")
	}
	for name, v := range map[string]string{
		"без подсети":          "app",
		"длинное имя":          "abcdefghijklm:10.99.0.0/30",
		"заглавные":            "App:10.99.0.0/30",
		"дефис в начале":       "-app:10.99.0.0/30",
		"не адрес сети":        "app:10.99.0.1/30",
		"префикс /31":          "app:10.99.0.0/31",
		"префикс /16":          "app:10.99.0.0/16",
		"IPv6":                 "app:fd00::/126",
		"пересечение с LAN":    "app:192.168.3.0/30",
		"повтор имени":         "app:10.99.0.0/30 app:10.99.0.4/30",
		"пересечение подсетей": "app:10.99.0.0/29 web:10.99.0.4/30",
		"мусор вместо подсети": "app:ten",
	} {
		if _, err := FromValues(map[string]string{"LOCAL_CLIENTS": v}); err == nil {
			t.Errorf("%s (%q): ожидалась ошибка", name, v)
		}
	}
}
