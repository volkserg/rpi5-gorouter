package lists

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseEntry(t *testing.T) {
	for in, want := range map[string]string{
		"intranet.com":    "intranet.com",
		"Intranet.COM.":   "intranet.com",
		"1.2.3.4":         "1.2.3.4",
		"1.2.3.4/32":      "1.2.3.4",
		"142.250.0.0/15":  "142.250.0.0/15",
		"142.251.10.7/15": "142.250.0.0/15",
		"0.0.0.0/0":       "0.0.0.0/0",
	} {
		e, err := ParseEntry(in)
		if err != nil {
			t.Errorf("%q: %v", in, err)
			continue
		}
		if e.String() != want {
			t.Errorf("%q → %q, want %q", in, e.String(), want)
		}
	}
	for _, bad := range []string{"999.1.1.1", "1.2.3", "1.2.3.4/33", "01.2.3.4", "1.2.3.4/", "2001:db8::1", "*.example.com", "a..b", "1.2.3.4.5"} {
		if _, err := ParseEntry(bad); err == nil {
			t.Errorf("%q: ожидалась ошибка", bad)
		}
	}
}

func TestEntryEqual(t *testing.T) {
	a, _ := ParseEntry("1.2.3.4")
	b, _ := ParseEntry("1.2.3.4/32")
	if !a.Equal(b) {
		t.Error("1.2.3.4 должен совпадать с 1.2.3.4/32")
	}
	c, _ := ParseEntry("Example.com")
	d, _ := ParseEntry("example.com")
	if !c.Equal(d) {
		t.Error("сравнение доменов должно быть регистронезависимым")
	}
}

func TestParseVPN(t *testing.T) {
	in := "# заголовок\n\nintranet.com\n  cdnhost.com  \n  # отступ — тоже комментарий\n1.2.3.4 # сервер\n10.0.0.0/8\nbad entry\n999.1.1.1\nintranet.com\n"
	l, err := ParseVPN(strings.NewReader(in))
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, e := range l.Entries() {
		got = append(got, e.String())
	}
	if strings.Join(got, ",") != "intranet.com,cdnhost.com,1.2.3.4,10.0.0.0/8" {
		t.Errorf("entries: %v", got)
	}
	inv := l.Invalid()
	if len(inv) != 2 || inv[0].Num != 8 || inv[1].Num != 9 {
		t.Errorf("invalid: %+v", inv)
	}
	// Сериализация без правок сохраняет файл байт в байт.
	if string(l.Bytes()) != in {
		t.Errorf("round-trip изменил файл:\n%s", l.Bytes())
	}
}

func TestReferenceVPNFile(t *testing.T) {
	l, exists, err := ReadVPN(filepath.Join("testdata", VPNFileName))
	if err != nil || !exists {
		t.Fatal(exists, err)
	}
	if inv := l.Invalid(); len(inv) != 0 {
		t.Errorf("референсный список содержит ошибки: %+v", inv)
	}
	if len(l.Entries()) == 0 {
		t.Error("референсный список пуст")
	}
}

func TestAddRemove(t *testing.T) {
	l, _ := ParseVPN(strings.NewReader("# c\nintranet.com\n1.2.3.4\n"))
	e, _ := ParseEntry("INTRANET.com")
	if l.Add(e) {
		t.Error("дубликат с другим регистром не должен добавляться")
	}
	ip, _ := ParseEntry("1.2.3.4/32")
	if l.Add(ip) {
		t.Error("1.2.3.4/32 — дубликат 1.2.3.4")
	}
	n, _ := ParseEntry("5.6.7.8/24")
	if !l.Add(n) {
		t.Error("новая подсеть должна добавиться")
	}
	if got := string(l.Bytes()); got != "# c\nintranet.com\n1.2.3.4\n5.6.7.0/24\n" {
		t.Errorf("после Add:\n%s", got)
	}
	if l.Remove(ip) != 1 || l.Remove(ip) != 0 {
		t.Error("Remove должен удалить ровно одну строку")
	}
	if got := string(l.Bytes()); got != "# c\nintranet.com\n5.6.7.0/24\n" {
		t.Errorf("после Remove:\n%s", got)
	}
}

// Похожие строки не должны удаляться: в bash sed /^a.com$/d считал точку regex.
func TestRemoveExactOnly(t *testing.T) {
	l, _ := ParseVPN(strings.NewReader("a.com\nabcom.net\nsub.a.com\n"))
	e, _ := ParseEntry("a.com")
	l.Remove(e)
	if got := string(l.Bytes()); got != "abcom.net\nsub.a.com\n" {
		t.Errorf("got:\n%s", got)
	}
}

func TestMerge(t *testing.T) {
	l, _ := ParseVPN(strings.NewReader("intranet.com\n1.2.3.4\n"))
	src, _ := ParseVPN(strings.NewReader("# список\nintranet.com\npartner.com\npartner.com\n9.9.9.9\nbad entry\n"))

	res := l.Merge(src, KindDomain)
	if res.Total != 3 || len(res.Added) != 1 || res.Skipped != 2 || len(res.Foreign) != 1 || len(res.Invalid) != 1 {
		t.Errorf("domains: %+v", res)
	}
	res = l.Merge(src, KindNet)
	if res.Total != 1 || len(res.Added) != 1 || res.Skipped != 0 || len(res.Foreign) != 3 {
		t.Errorf("ips: %+v", res)
	}
	if got := string(l.Bytes()); got != "intranet.com\n1.2.3.4\npartner.com\n9.9.9.9\n" {
		t.Errorf("got:\n%s", got)
	}
}

func TestUpdateVPN(t *testing.T) {
	path := filepath.Join(t.TempDir(), VPNFileName)
	// Файл без завершающего перевода строки: bash склеил бы новую запись с последней.
	if err := os.WriteFile(path, []byte("intranet.com"), 0o640); err != nil {
		t.Fatal(err)
	}
	e, _ := ParseEntry("cdnhost.com")
	err := UpdateVPN(path, func(l *VPNList) (bool, error) { return l.Add(e), nil })
	if err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(path)
	if string(data) != "intranet.com\ncdnhost.com\n" {
		t.Errorf("got %q", data)
	}
	if st, _ := os.Stat(path); st.Mode().Perm() != 0o640 {
		t.Errorf("права не сохранены: %v", st.Mode())
	}

	// Без изменений файл не переписывается.
	before, _ := os.Stat(path)
	if err := UpdateVPN(path, func(l *VPNList) (bool, error) { return l.Add(e), nil }); err != nil {
		t.Fatal(err)
	}
	if after, _ := os.Stat(path); !after.ModTime().Equal(before.ModTime()) {
		t.Error("файл переписан без изменений")
	}
}

func TestUpdateVPNCreatesFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), VPNFileName)
	e, _ := ParseEntry("10.1.0.0/16")
	if err := UpdateVPN(path, func(l *VPNList) (bool, error) { return l.Add(e), nil }); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(path)
	if string(data) != "10.1.0.0/16\n" {
		t.Errorf("got %q", data)
	}
}

func TestParseOverrides(t *testing.T) {
	in := "# c\ncorp.example.com 8.8.8.8\nexample.org 1.1.1.1:5353\nexample.net 9.9.9.9#5353 # хвост\nexample.org 8.8.4.4\nonlydomain\nbad..dom 8.8.8.8\nx.com dns.google\n"
	ovs, bad, err := ParseOverrides(strings.NewReader(in))
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, o := range ovs {
		got = append(got, o.Domain+"="+o.Upstream.String())
	}
	want := "corp.example.com=8.8.8.8:53,example.org=1.1.1.1:5353,example.net=9.9.9.9:5353,example.org=8.8.4.4:53"
	if strings.Join(got, ",") != want {
		t.Errorf("got %v", got)
	}
	if len(bad) != 3 || bad[0].Line != 6 {
		t.Errorf("bad: %+v", bad)
	}
}

func TestReferenceOverrideFile(t *testing.T) {
	ovs, bad, err := ReadOverrides(filepath.Join("testdata", OverrideFileName))
	if err != nil || len(bad) != 0 || len(ovs) != 1 || ovs[0].Domain != "corp.example.com" {
		t.Errorf("ovs=%+v bad=%+v err=%v", ovs, bad, err)
	}
}
