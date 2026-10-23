package ipinfo

import (
	"context"
	"errors"
	"net/netip"
	"testing"

	"github.com/miekg/dns"
)

func TestParse(t *testing.T) {
	asn, prefix, cc := ParseOrigin("13335 209242 | 104.16.0.0/13 | US | arin | 2014-03-28")
	if asn != 13335 || prefix != "104.16.0.0/13" || cc != "US" {
		t.Fatalf("ParseOrigin = %d %q %q", asn, prefix, cc)
	}
	if asn, _, _ := ParseOrigin("мусор"); asn != 0 {
		t.Fatalf("мусор разобран: %d", asn)
	}
	for in, want := range map[string]string{
		"15169 | US | arin | 2000-03-30 | GOOGLE, US":            "GOOGLE",
		"24940 | DE | ripencc | 2002-06-03 | HETZNER-AS, DE":     "HETZNER-AS",
		"64500 | ZZ | test | 2024-01-01 | LAB-NET Example, Inc.": "LAB-NET Example, Inc.",
		"1 | US": "",
	} {
		if got := ParseASName(in); got != want {
			t.Errorf("ParseASName(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestPublic(t *testing.T) {
	for s, want := range map[string]bool{
		"8.8.8.8": true, "203.0.113.10": true, "192.168.3.10": false,
		"10.1.2.3": false, "100.64.1.1": false, "127.0.0.1": false, "169.254.1.1": false,
	} {
		if got := Public(netip.MustParseAddr(s)); got != want {
			t.Errorf("Public(%s) = %v", s, got)
		}
	}
}

func TestLookup(t *testing.T) {
	answers := map[string]dns.RR{
		"8.8.8.8.in-addr.arpa.":         &dns.PTR{Hdr: dns.RR_Header{Name: "8.8.8.8.in-addr.arpa.", Rrtype: dns.TypePTR, Class: dns.ClassINET}, Ptr: "dns.google."},
		"8.8.8.8.origin.asn.cymru.com.": &dns.TXT{Hdr: dns.RR_Header{Rrtype: dns.TypeTXT, Class: dns.ClassINET}, Txt: []string{"15169 | 8.8.8.0/24 | US | arin | 2023-12-28"}},
		"AS15169.asn.cymru.com.":        &dns.TXT{Hdr: dns.RR_Header{Rrtype: dns.TypeTXT, Class: dns.ClassINET}, Txt: []string{"15169 | US | arin | 2000-03-30 | GOOGLE, US"}},
	}
	ex := func(_ context.Context, q *dns.Msg) (*dns.Msg, error) {
		r := new(dns.Msg)
		r.SetReply(q)
		if rr, ok := answers[q.Question[0].Name]; ok {
			r.Answer = []dns.RR{rr}
		} else {
			r.Rcode = dns.RcodeNameError
		}
		return r, nil
	}
	got := Lookup(context.Background(), ex, netip.MustParseAddr("8.8.8.8"))
	want := Info{PTR: "dns.google", ASN: 15169, ASName: "GOOGLE", Prefix: "8.8.8.0/24", Country: "US"}
	if got.PTR != want.PTR || got.ASN != want.ASN || got.ASName != want.ASName || got.Prefix != want.Prefix || got.Country != want.Country {
		t.Fatalf("Lookup = %+v, want %+v", got, want)
	}
	// Частный адрес: только PTR, к Team Cymru не обращаемся.
	asked := false
	priv := func(ctx context.Context, q *dns.Msg) (*dns.Msg, error) {
		if q.Question[0].Qtype == dns.TypeTXT {
			asked = true
		}
		return nil, errors.New("нет ответа")
	}
	if i := Lookup(context.Background(), priv, netip.MustParseAddr("192.168.3.10")); !i.Empty() || asked {
		t.Fatalf("частный адрес: %+v, запрос TXT: %v", i, asked)
	}
}
