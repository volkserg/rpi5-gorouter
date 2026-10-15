// Package sysinfo читает состояние системы из /proc для команды status
// (по аналогии с ss). Корень /proc подменяется в тестах.
package sysinfo

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// Ports — порты, на которых есть сокеты: TCP в состоянии LISTEN,
// UDP — любые привязанные.
type Ports struct {
	TCP map[uint16]bool
	UDP map[uint16]bool
}

// tcpListen — код состояния TCP_LISTEN в /proc/net/tcp.
const tcpListen = "0A"

// ListeningPorts разбирает /proc/net/{tcp,tcp6,udp,udp6}. Отсутствующие
// файлы (например, без IPv6) пропускаются; если нет ни одного — ошибка,
// чтобы status показал N/A, а не «не слушается».
func ListeningPorts(procRoot string) (Ports, error) {
	p := Ports{TCP: map[uint16]bool{}, UDP: map[uint16]bool{}}
	found := 0
	for _, f := range []struct {
		name string
		dst  map[uint16]bool
		tcp  bool
	}{
		{"tcp", p.TCP, true}, {"tcp6", p.TCP, true},
		{"udp", p.UDP, false}, {"udp6", p.UDP, false},
	} {
		err := scanSockets(filepath.Join(procRoot, "net", f.name), f.tcp, f.dst)
		switch {
		case err == nil:
			found++
		case !os.IsNotExist(err):
			return p, err
		}
	}
	if found == 0 {
		return p, fmt.Errorf("%s/net: нет данных о сокетах", procRoot)
	}
	return p, nil
}

func scanSockets(path string, tcp bool, dst map[uint16]bool) error {
	fh, err := os.Open(path)
	if err != nil {
		return err
	}
	defer fh.Close()
	sc := bufio.NewScanner(fh)
	sc.Scan() // заголовок
	for sc.Scan() {
		// sl local_address rem_address st …; local_address = HEXIP:HEXPORT
		f := strings.Fields(sc.Text())
		if len(f) < 4 || (tcp && f[3] != tcpListen) {
			continue
		}
		i := strings.LastIndexByte(f[1], ':')
		if i < 0 {
			continue
		}
		if port, err := strconv.ParseUint(f[1][i+1:], 16, 16); err == nil {
			dst[uint16(port)] = true
		}
	}
	return sc.Err()
}

// Sysctl читает значение sysctl по имени в точечной нотации
// (net.ipv4.ip_forward → <procRoot>/sys/net/ipv4/ip_forward).
func Sysctl(procRoot, name string) (string, error) {
	b, err := os.ReadFile(filepath.Join(procRoot, "sys", filepath.FromSlash(strings.ReplaceAll(name, ".", "/"))))
	return strings.TrimSpace(string(b)), err
}
