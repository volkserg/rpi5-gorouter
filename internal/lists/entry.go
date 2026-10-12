// Package lists — файлы списков router_service: vpn_domains.txt (домены,
// IP и подсети для VPN) и dns_override.txt (домены с отдельным upstream DNS).
// Формат файлов совместим с bash-версией.
package lists

import (
	"fmt"
	"net/netip"
	"strings"

	"github.com/volkserg/rpi5-gorouter/internal/domain"
)

// Kind — тип записи vpn_domains.txt.
type Kind int

const (
	// KindDomain — домен; IP попадают в set по DNS-ответам.
	KindDomain Kind = iota + 1
	// KindNet — IP-адрес или подсеть; попадает в set напрямую.
	KindNet
)

// Entry — проверенная запись vpn_domains.txt.
type Entry struct {
	Kind   Kind
	Domain string       // для KindDomain: нормализованное имя
	Prefix netip.Prefix // для KindNet: подсеть, одиночный IP — /32
}

// ParseEntry классифицирует запись: IP, подсеть или домен.
// В отличие от bash (регулярка [0-9]+), IP проверяется строго:
// 999.1.1.1 — ошибка, а не «IP», который потом молча не добавится в set.
// Подсеть с ненулевыми битами хоста нормализуется: 1.2.3.4/24 → 1.2.3.0/24.
func ParseEntry(s string) (Entry, error) {
	if s == "" {
		return Entry{}, fmt.Errorf("пустая запись")
	}
	if looksLikeIP(s) {
		if strings.Contains(s, "/") {
			p, err := netip.ParsePrefix(s)
			if err != nil || !p.Addr().Is4() {
				return Entry{}, fmt.Errorf("%q: некорректная подсеть IPv4", s)
			}
			return Entry{Kind: KindNet, Prefix: p.Masked()}, nil
		}
		a, err := netip.ParseAddr(s)
		if err != nil || !a.Is4() {
			return Entry{}, fmt.Errorf("%q: некорректный IPv4-адрес", s)
		}
		return Entry{Kind: KindNet, Prefix: netip.PrefixFrom(a, 32)}, nil
	}
	if strings.Contains(s, ":") {
		return Entry{}, fmt.Errorf("%q: IPv6 не поддерживается", s)
	}
	d := domain.Normalize(s)
	if err := domain.Validate(d); err != nil {
		return Entry{}, fmt.Errorf("%q: %w", s, err)
	}
	return Entry{Kind: KindDomain, Domain: d}, nil
}

// looksLikeIP — строка состоит только из цифр, точек и '/'; такую запись
// трактуем как IP/подсеть (числовых TLD не бывает).
func looksLikeIP(s string) bool {
	for i := 0; i < len(s); i++ {
		if c := s[i]; (c < '0' || c > '9') && c != '.' && c != '/' {
			return false
		}
	}
	return true
}

// String — каноническая форма записи: домен, IP (для /32) или подсеть.
func (e Entry) String() string {
	switch e.Kind {
	case KindDomain:
		return e.Domain
	case KindNet:
		if e.IsSingleIP() {
			return e.Prefix.Addr().String()
		}
		return e.Prefix.String()
	}
	return ""
}

// IsSingleIP — запись является одиночным адресом (/32).
func (e Entry) IsSingleIP() bool { return e.Kind == KindNet && e.Prefix.Bits() == 32 }

// Equal сравнивает записи по смыслу: 1.2.3.4 == 1.2.3.4/32, Intranet.com == intranet.com.
func (e Entry) Equal(o Entry) bool {
	return e.Kind == o.Kind && e.Domain == o.Domain && e.Prefix == o.Prefix
}
