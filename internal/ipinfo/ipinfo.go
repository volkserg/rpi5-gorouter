// Package ipinfo — кому может принадлежать адрес: PTR и автономная система
// (сеть, страна, название оператора) по DNS-сервису Team Cymru
// (origin.asn.cymru.com). Всё — обычными DNS-запросами через резолвер routerd.
package ipinfo

import (
	"context"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// Info — сведения об адресе; пустые поля — не нашлось.
type Info struct {
	// Names — имена, под которыми устройства получали адрес в DNS-ответах.
	Names []string `json:"names,omitempty"`
	// SNI — имена из TLS ClientHello соединений устройств с адресом по IP
	// (без запроса к DNS routerd).
	SNI     []string `json:"sni,omitempty"`
	PTR     string   `json:"ptr,omitempty"`
	ASN     uint32   `json:"asn,omitempty"`
	ASName  string   `json:"as_name,omitempty"`
	Prefix  string   `json:"prefix,omitempty"`
	Country string   `json:"country,omitempty"`
}

// Empty — ничего не нашлось.
func (i Info) Empty() bool {
	return len(i.Names) == 0 && len(i.SNI) == 0 && i.PTR == "" && i.ASN == 0
}

// Exchange — DNS-запрос к резолверу.
type Exchange func(ctx context.Context, q *dns.Msg) (*dns.Msg, error)

// Timeout — предел на все запросы: сведения второстепенны, проверку не задерживают.
const Timeout = 3 * time.Second

// Lookup — PTR и автономная система адреса. Ошибки не возвращает: чего не
// нашлось, того в Info нет. Автономную систему ищет только для публичных адресов.
func Lookup(ctx context.Context, ex Exchange, ip netip.Addr) Info {
	ctx, cancel := context.WithTimeout(ctx, Timeout)
	defer cancel()
	var info Info
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		if name, err := dns.ReverseAddr(ip.String()); err == nil {
			if rrs := query(ctx, ex, name, dns.TypePTR); len(rrs) > 0 {
				if p, ok := rrs[0].(*dns.PTR); ok {
					info.PTR = strings.TrimSuffix(p.Ptr, ".")
				}
			}
		}
	}()
	if Public(ip) {
		var asn uint32
		for _, t := range txt(ctx, ex, originName(ip)) {
			if asn, info.Prefix, info.Country = ParseOrigin(t); asn != 0 {
				break
			}
		}
		if asn != 0 {
			info.ASN = asn
			for _, t := range txt(ctx, ex, "AS"+strconv.FormatUint(uint64(asn), 10)+".asn.cymru.com.") {
				if name := ParseASName(t); name != "" {
					info.ASName = name
					break
				}
			}
		}
	}
	wg.Wait()
	return info
}

// Public — адрес из интернета: не частный, не служебный, не CGNAT.
func Public(ip netip.Addr) bool {
	ip = ip.Unmap()
	return ip.IsGlobalUnicast() && !ip.IsPrivate() && !cgnat.Contains(ip)
}

var cgnat = netip.MustParsePrefix("100.64.0.0/10")

// originName — 1.2.3.4 → 4.3.2.1.origin.asn.cymru.com.
func originName(ip netip.Addr) string {
	ip = ip.Unmap()
	if ip.Is4() {
		b := ip.As4()
		return strconv.Itoa(int(b[3])) + "." + strconv.Itoa(int(b[2])) + "." +
			strconv.Itoa(int(b[1])) + "." + strconv.Itoa(int(b[0])) + ".origin.asn.cymru.com."
	}
	rev, _ := dns.ReverseAddr(ip.String())
	return strings.TrimSuffix(rev, "ip6.arpa.") + "origin6.asn.cymru.com."
}

// ParseOrigin — «15169 | 8.8.8.0/24 | US | arin | 2023-12-28»: первая из
// автономных систем (их бывает несколько через пробел), сеть, страна.
func ParseOrigin(s string) (asn uint32, prefix, country string) {
	f := fields(s)
	if len(f) < 3 {
		return 0, "", ""
	}
	first, _, _ := strings.Cut(f[0], " ")
	n, err := strconv.ParseUint(first, 10, 32)
	if err != nil {
		return 0, "", ""
	}
	return uint32(n), f[1], f[2]
}

// ParseASName — «15169 | US | arin | 2000-03-30 | GOOGLE, US» → «GOOGLE».
func ParseASName(s string) string {
	f := fields(s)
	if len(f) < 5 {
		return ""
	}
	name := f[4]
	if i := strings.LastIndex(name, ", "); i > 0 && len(name)-i-2 == 2 {
		name = name[:i]
	}
	return strings.TrimSpace(name)
}

func fields(s string) []string {
	f := strings.Split(s, "|")
	for i := range f {
		f[i] = strings.TrimSpace(f[i])
	}
	return f
}

func query(ctx context.Context, ex Exchange, name string, t uint16) []dns.RR {
	q := new(dns.Msg)
	q.SetQuestion(name, t)
	resp, err := ex(ctx, q)
	if err != nil || resp.Rcode != dns.RcodeSuccess {
		return nil
	}
	return resp.Answer
}

func txt(ctx context.Context, ex Exchange, name string) []string {
	var out []string
	for _, rr := range query(ctx, ex, name, dns.TypeTXT) {
		if t, ok := rr.(*dns.TXT); ok {
			out = append(out, strings.Join(t.Txt, ""))
		}
	}
	return out
}
