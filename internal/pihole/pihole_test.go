package pihole

import (
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/BurntSushi/toml"
)

var lan = netip.MustParsePrefix("192.168.3.0/24")

func desired() Desired {
	return Desired{
		Port:      5353,
		Upstreams: []string{"127.0.0.1#5053"},
		ECS:       true,
		RevServer: RevServerEntry(lan, netip.MustParseAddrPort("127.0.0.1:53"), "lan"),
		LAN:       lan,
	}
}

func fixture(t *testing.T) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", "pihole.toml"))
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "pihole.toml")
	if err := os.WriteFile(path, data, 0o640); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestCheckAndApply(t *testing.T) {
	path := fixture(t)
	drifts, err := Check(path, desired())
	if err != nil {
		t.Fatal(err)
	}
	keys := []string{}
	for _, d := range drifts {
		keys = append(keys, d.Key)
	}
	if strings.Join(keys, ",") != "port,upstreams,EDNS0ECS,revServers" {
		t.Fatalf("drifts: %v", drifts)
	}
	if err := Apply(path, drifts); err != nil {
		t.Fatal(err)
	}
	if again, err := Check(path, desired()); err != nil || len(again) != 0 {
		t.Fatalf("после Apply расхождений быть не должно: %v %v", again, err)
	}

	var got struct {
		DNS struct {
			Upstreams     []string
			Port          int
			EDNS0ECS      bool
			RevServers    []string
			ListeningMode string `toml:"listeningMode"`
			Domain        struct{ Name string }
		}
		Webserver struct{ Port string }
	}
	if _, err := toml.DecodeFile(path, &got); err != nil {
		t.Fatalf("файл после правки должен оставаться валидным TOML: %v", err)
	}
	if got.DNS.Port != 5353 || got.DNS.Upstreams[0] != "127.0.0.1#5053" || !got.DNS.EDNS0ECS {
		t.Errorf("dns: %+v", got.DNS)
	}
	// Чужая запись revServers сохранена, наша добавлена.
	if strings.Join(got.DNS.RevServers, "|") != "true,10.20.0.0/16,10.20.0.53,corp.example|true,192.168.3.0/24,127.0.0.1#53,lan" {
		t.Errorf("revServers: %v", got.DNS.RevServers)
	}
	// Остальное не тронуто: соседний ключ, вложенная таблица, webserver.port.
	if got.DNS.ListeningMode != "ALL" || got.DNS.Domain.Name != "lan" || got.Webserver.Port != "80o,443os,[::]:80o,[::]:443os" {
		t.Errorf("затронуты чужие ключи: %+v %+v", got.DNS, got.Webserver)
	}
	if st, _ := os.Stat(path); st.Mode().Perm() != 0o640 {
		t.Errorf("права не сохранены: %v", st.Mode())
	}
}

func TestMissingKeyInserted(t *testing.T) {
	path := filepath.Join(t.TempDir(), "pihole.toml")
	os.WriteFile(path, []byte("[dns]\n  upstreams = []\n\n  [dns.cache]\n    size = 10000\n\n[misc]\n  port = 1\n"), 0o644)
	drifts, err := Check(path, desired())
	if err != nil {
		t.Fatal(err)
	}
	if err := Apply(path, drifts); err != nil {
		t.Fatal(err)
	}
	var got struct {
		DNS struct {
			Port  int
			Cache struct{ Size int }
		}
		Misc struct{ Port int }
	}
	if _, err := toml.DecodeFile(path, &got); err != nil {
		t.Fatal(err)
	}
	if got.DNS.Port != 5353 || got.DNS.Cache.Size != 10000 || got.Misc.Port != 1 {
		t.Errorf("got %+v", got)
	}
}

func TestNoRevServerWithoutDHCP(t *testing.T) {
	path := fixture(t)
	d := desired()
	d.RevServer = ""
	drifts, _ := Check(path, d)
	for _, dr := range drifts {
		if dr.Key == "revServers" {
			t.Errorf("без DHCP routerd не добавляет запись, а чужие не трогает: %v", dr)
		}
	}
}
