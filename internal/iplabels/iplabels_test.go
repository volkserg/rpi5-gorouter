package iplabels

import (
	"net/netip"
	"strings"
	"testing"
)

var ip = netip.MustParseAddr("203.0.113.77")

func TestStore(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Auto(ip, "messenger.example", SourceCert); err != nil {
		t.Fatal(err)
	}
	if l, ok := s.Get(ip); !ok || l.Name != "messenger.example" || l.Source != SourceCert {
		t.Fatalf("Get = %+v %v", l, ok)
	}
	// Заданное вручную автоматическое не перезаписывает.
	if err := s.Set(ip, "Мессенджер"); err != nil {
		t.Fatal(err)
	}
	if l, _ := s.Auto(ip, "other.example", SourcePTR); l.Name != "Мессенджер" || l.Source != SourceUser {
		t.Fatalf("Auto поверх ручного: %+v", l)
	}
	if err := s.Set(ip, strings.Repeat("я", MaxLen+1)); err == nil {
		t.Fatal("длинное имя принято")
	}
	// Переживает перезапуск.
	s2, _ := Open(dir)
	if l, _ := s2.Get(ip); l.Name != "Мессенджер" {
		t.Fatalf("после перезапуска: %+v", l)
	}
	if err := s2.Set(ip, ""); err != nil {
		t.Fatal(err)
	}
	if _, ok := s2.Get(ip); ok {
		t.Fatal("пустое имя не забыло адрес")
	}
	s2.Auto(ip, "a.example", SourceCert)
	s2.Auto(netip.MustParseAddr("198.51.100.1"), "b.example", SourcePTR)
	if n, err := s2.Reset(); err != nil || n != 2 || s2.Len() != 0 {
		t.Fatalf("Reset = %d, %v, осталось %d", n, err, s2.Len())
	}
	if s3, _ := Open(dir); s3.Len() != 0 {
		t.Fatal("сброс не записан")
	}
}

func TestEvict(t *testing.T) {
	m := map[netip.Addr]Label{
		netip.MustParseAddr("192.0.2.1"): {Name: "old", Source: SourceCert, At: 1},
		netip.MustParseAddr("192.0.2.2"): {Name: "mine", Source: SourceUser, At: 0},
		netip.MustParseAddr("192.0.2.3"): {Name: "new", Source: SourceAS, At: 5},
	}
	evict(m, 1)
	if _, ok := m[netip.MustParseAddr("192.0.2.1")]; ok || len(m) != 2 {
		t.Fatalf("evict: %+v", m)
	}
}

func TestGuess(t *testing.T) {
	for _, c := range []struct {
		names         []string
		subj, ptr, as string
		want, src     string
	}{
		{[]string{"*.cdn.example", "cdn.example"}, "", "x.ptr.example", "CDN", "cdn.example", SourceCert},
		{nil, "localhost", "host-1.example", "NET", "host-1.example", SourcePTR},
		{nil, "", "", "HETZNER-AS", "HETZNER-AS", SourceAS},
		{nil, "", "", "", "", ""},
	} {
		if n, s := Guess(c.names, c.subj, c.ptr, c.as); n != c.want || s != c.src {
			t.Errorf("Guess(%v, %q, %q, %q) = %q %q", c.names, c.subj, c.ptr, c.as, n, s)
		}
	}
}
