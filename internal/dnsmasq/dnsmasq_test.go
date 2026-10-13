package dnsmasq

import (
	"strings"
	"testing"

	"github.com/volkserg/rpi5-gorouter/internal/config"
	"github.com/volkserg/rpi5-gorouter/internal/lists"
)

func TestRender(t *testing.T) {
	cfg, err := config.FromValues(map[string]string{"IFACE": "eth1"})
	if err != nil {
		t.Fatal(err)
	}
	l, _ := lists.ParseVPN(strings.NewReader("corp.example.com\n10.20.0.0/16\nGit.Example.NET\n"))
	ovs, _, _ := lists.ParseOverrides(strings.NewReader("corp.example.com 10.20.0.53\nexample.org 1.1.1.1:5353\n"))

	got := string(Render(cfg, l.Entries(), ovs))
	want := `# Сгенерировано routerd — не редактировать, изменения будут перезаписаны.
port=53
interface=eth1
bind-interfaces
no-resolv
cache-size=0
dns-forward-max=300
bogus-priv
server=127.0.0.1#5353
nftset=/corp.example.com/4#ip#router_service#vpn_dynamic
nftset=/git.example.net/4#ip#router_service#vpn_dynamic
server=/corp.example.com/10.20.0.53#53
server=/example.org/1.1.1.1#5353
`
	if got != want {
		t.Errorf("got:\n%s\nwant:\n%s", got, want)
	}
}
