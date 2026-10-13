package sysinfo

import (
	"os"
	"path/filepath"
	"testing"
)

const tcpData = `  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0100007F:13C5 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1 1 0000000000000000 100 0 0 10 0
   1: 0203A8C0:0035 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 2 1 0000000000000000 100 0 0 10 0
   2: 0203A8C0:0016 0103A8C0:D431 01 00000000:00000000 02:00000000 00000000     0        0 3 4 0000000000000000 20 4 30 10 -1
`

const udpData = `   sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode ref pointer drops
  10: 00000000:0043 00000000:0000 07 00000000:00000000 00:00000000 00000000     0        0 5 2 0000000000000000 0
`

const tcp6Data = `  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000000000000000000000000000:14E9 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000   999        0 6 1 0000000000000000 100 0 0 10 0
`

func TestListeningPorts(t *testing.T) {
	root := t.TempDir()
	must(t, os.MkdirAll(filepath.Join(root, "net"), 0o755))
	must(t, os.WriteFile(filepath.Join(root, "net", "tcp"), []byte(tcpData), 0o644))
	must(t, os.WriteFile(filepath.Join(root, "net", "tcp6"), []byte(tcp6Data), 0o644))
	must(t, os.WriteFile(filepath.Join(root, "net", "udp"), []byte(udpData), 0o644))

	p, err := ListeningPorts(root)
	if err != nil {
		t.Fatal(err)
	}
	for _, port := range []uint16{5061, 53, 5353} {
		if !p.TCP[port] {
			t.Errorf("TCP %d должен слушаться", port)
		}
	}
	if p.TCP[22] {
		t.Error("установленное соединение на 22 — не LISTEN")
	}
	if !p.UDP[67] {
		t.Error("UDP 67 должен быть привязан")
	}
}

func TestSysctl(t *testing.T) {
	root := t.TempDir()
	must(t, os.MkdirAll(filepath.Join(root, "sys", "net", "ipv4"), 0o755))
	must(t, os.WriteFile(filepath.Join(root, "sys", "net", "ipv4", "ip_forward"), []byte("1\n"), 0o644))
	v, err := Sysctl(root, "net.ipv4.ip_forward")
	if err != nil || v != "1" {
		t.Errorf("v=%q err=%v", v, err)
	}
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func TestListeningPortsNoProc(t *testing.T) {
	if _, err := ListeningPorts(t.TempDir()); err == nil {
		t.Error("без /proc/net ожидалась ошибка")
	}
}
