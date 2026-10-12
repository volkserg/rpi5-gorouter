package domain

import "testing"

func TestValidate(t *testing.T) {
	for _, ok := range []string{"intranet.com", "img3.corpimg.com", "a", "ru", "_dmarc.example.com", "xn--80ak6aa92e.com", "1node.example.net"} {
		if err := Validate(ok); err != nil {
			t.Errorf("%q: %v", ok, err)
		}
	}
	for _, bad := range []string{"", ".com", "a..b", "-a.com", "a-.com", "*.example.com", "пример.рф", "a b.com", "a/b.com"} {
		if err := Validate(bad); err == nil {
			t.Errorf("%q: ожидалась ошибка", bad)
		}
	}
}

func TestNormalize(t *testing.T) {
	if got := Normalize("Intranet.COM."); got != "intranet.com" {
		t.Errorf("got %q", got)
	}
}

func TestMatcher(t *testing.T) {
	m := NewMatcher[string]()
	m.Set("corpmedia.com", "vpn")
	m.Set("manifest.corpmedia.com", "specific")
	m.Set("com", "tld")

	for _, tc := range []struct{ name, val, dom string }{
		{"corpmedia.com", "vpn", "corpmedia.com"},
		{"node1.corpmedia.com.", "vpn", "corpmedia.com"},
		{"MANIFEST.corpmedia.com", "specific", "manifest.corpmedia.com"},
		{"a.manifest.corpmedia.com", "specific", "manifest.corpmedia.com"},
		{"notcorpmedia.com", "tld", "com"},
		{"example.com", "tld", "com"},
	} {
		v, d, ok := m.Lookup(tc.name)
		if !ok || v != tc.val || d != tc.dom {
			t.Errorf("%s: got (%q, %q, %v), want (%q, %q)", tc.name, v, d, ok, tc.val, tc.dom)
		}
	}
	if _, _, ok := m.Lookup("example.org"); ok {
		t.Error("example.org не должен совпадать")
	}
}
