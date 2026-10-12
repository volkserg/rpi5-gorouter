package lists

import (
	"bufio"
	"fmt"
	"io"
	"net/netip"
	"strconv"
	"strings"

	"github.com/volkserg/rpi5-gorouter/internal/domain"
)

// OverrideFileName — имя файла DNS-override в каталоге конфигов.
const OverrideFileName = "dns_override.txt"

// Override — правило «домен (и поддомены) резолвить через upstream».
type Override struct {
	Line     int
	Domain   string
	Upstream netip.AddrPort
}

// LineError — ошибка разбора строки файла.
type LineError struct {
	Line int
	Text string
	Err  error
}

func (e LineError) Error() string { return fmt.Sprintf("строка %d: %v", e.Line, e.Err) }

// ParseOverrides разбирает dns_override.txt: «domain upstream[:port]».
// Порт принимается и через '#' (синтаксис dnsmasq), т.к. документированная
// форма с ':' в bash-версии на самом деле не работала. Несколько строк
// с одним доменом задают несколько upstream — как server= в dnsmasq.
func ParseOverrides(r io.Reader) ([]Override, []LineError, error) {
	var out []Override
	var bad []LineError
	sc := bufio.NewScanner(r)
	for n := 1; sc.Scan(); n++ {
		text := sc.Text()
		s := strings.TrimSpace(text)
		if s == "" || s[0] == '#' {
			continue
		}
		if i := strings.Index(s, " #"); i >= 0 {
			s = s[:i]
		}
		if i := strings.Index(s, "\t#"); i >= 0 {
			s = s[:i]
		}
		f := strings.Fields(s)
		if len(f) != 2 {
			bad = append(bad, LineError{n, text, fmt.Errorf("ожидается «домен upstream[:порт]»")})
			continue
		}
		d := domain.Normalize(f[0])
		if err := domain.Validate(d); err != nil {
			bad = append(bad, LineError{n, text, fmt.Errorf("домен %q: %w", f[0], err)})
			continue
		}
		up, err := ParseUpstream(f[1])
		if err != nil {
			bad = append(bad, LineError{n, text, err})
			continue
		}
		out = append(out, Override{Line: n, Domain: d, Upstream: up})
	}
	return out, bad, sc.Err()
}

// ParseUpstream разбирает адрес DNS-сервера: IP, IP:порт, IP#порт, [IPv6]:порт.
// Порт по умолчанию — 53.
func ParseUpstream(s string) (netip.AddrPort, error) {
	if ap, err := netip.ParseAddrPort(s); err == nil {
		if ap.Port() == 0 {
			return netip.AddrPort{}, fmt.Errorf("upstream %q: порт 0", s)
		}
		return ap, nil
	}
	host, port := s, uint16(53)
	if h, p, ok := strings.Cut(s, "#"); ok {
		v, err := strconv.ParseUint(p, 10, 16)
		if err != nil || v == 0 {
			return netip.AddrPort{}, fmt.Errorf("upstream %q: некорректный порт", s)
		}
		host, port = h, uint16(v)
	}
	a, err := netip.ParseAddr(host)
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("upstream %q: ожидается IP-адрес (имена не поддерживаются)", s)
	}
	return netip.AddrPortFrom(a, port), nil
}
