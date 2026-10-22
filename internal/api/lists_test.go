package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func listsSetup(t *testing.T, vpn, conf string) (string, *fakeBackend, http.Handler) {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "vpn_domains.txt"), []byte(vpn), 0o644); err != nil {
		t.Fatal(err)
	}
	if conf != "" {
		if err := os.WriteFile(filepath.Join(dir, "router.conf"), []byte(conf), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	b := &fakeBackend{}
	return dir, b, Handler(b, dir)
}

func call(h http.Handler, method, path, body string, out any) int {
	r := httptest.NewRequest(method, "http://routerd"+path, strings.NewReader(body))
	r.Header.Set(UserHeader, "admin")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if out != nil {
		_ = json.Unmarshal(w.Body.Bytes(), out)
	}
	return w.Code
}

func readFile(t *testing.T, dir, name string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func TestVPNListAddRemove(t *testing.T) {
	dir, b, h := listsSetup(t, "# мои домены\nexample.com\n10.0.0.0/8\nbad entry\n", "")

	var l VPNList
	if code := call(h, "GET", "/v1/vpn", "", &l); code != 200 {
		t.Fatalf("GET: %d", code)
	}
	if l.Domains != 1 || l.Nets != 1 || len(l.Invalid) != 1 || l.Invalid[0].Line != 4 {
		t.Errorf("список: %+v", l)
	}

	var c Change
	if code := call(h, "POST", "/v1/vpn", `{"value":" Corp.Example.ORG "}`, &c); code != 200 || !c.Changed ||
		c.Entry.Value != "corp.example.org" || c.Entry.Kind != "domain" || !c.Normalized {
		t.Errorf("добавление: %d %+v", code, c)
	}
	if code := call(h, "POST", "/v1/vpn", `{"value":"192.168.50.7/24"}`, &c); code != 200 || c.Entry.Value != "192.168.50.0/24" || c.Entry.Kind != "net" {
		t.Errorf("подсеть нормализована: %d %+v", code, c)
	}
	if code := call(h, "POST", "/v1/vpn", `{"value":"example.com"}`, &c); code != 200 || c.Changed {
		t.Errorf("повтор: %d %+v", code, c)
	}
	if len(b.applied) != 2 || !strings.Contains(b.applied[0], "admin: добавлено в список VPN: corp.example.org") {
		t.Errorf("применение только при изменении, с пользователем: %v", b.applied)
	}
	var e Error
	if code := call(h, "POST", "/v1/vpn", `{"value":"999.1.1.1"}`, &e); code != 400 || e.Error == "" {
		t.Errorf("некорректный IP: %d %+v", code, e)
	}
	if code := call(h, "DELETE", "/v1/vpn?value=10.0.0.0%2F8", "", &c); code != 200 || !c.Changed {
		t.Errorf("удаление: %d %+v", code, c)
	}
	if code := call(h, "DELETE", "/v1/vpn?value=nope.example", "", &c); code != 200 || c.Changed {
		t.Errorf("удаление отсутствующего: %d %+v", code, c)
	}
	got := readFile(t, dir, "vpn_domains.txt")
	if got != "# мои домены\nexample.com\nbad entry\ncorp.example.org\n192.168.50.0/24\n" {
		t.Errorf("файл (комментарии и порядок сохранены):\n%s", got)
	}
}

func TestVPNLocalConflict(t *testing.T) {
	dir, b, h := listsSetup(t, "", `LOCAL_CLIENTS="app:10.99.0.0/30"`+"\n")
	var e Error
	if code := call(h, "POST", "/v1/vpn", `{"value":"10.99.0.0/16"}`, &e); code != 400 || !strings.Contains(e.Error, "LOCAL_CLIENTS") {
		t.Errorf("пересечение с локальным сервисом: %d %+v", code, e)
	}
	var res ImportResult
	if code := call(h, "POST", "/v1/vpn/import?mode=merge&apply=1", "10.99.0.2\nok.example\n", &res); code != 422 || len(res.Conflicts) != 1 {
		t.Errorf("импорт с конфликтом: %d %+v", code, res)
	}
	if readFile(t, dir, "vpn_domains.txt") != "" || len(b.applied) != 0 {
		t.Error("при конфликте файл изменён")
	}
}

func TestVPNImport(t *testing.T) {
	dir, b, h := listsSetup(t, "a.example\nb.example\n10.0.0.0/8\n", "")
	src := "# новый\nb.example\nc.example\n172.16.0.0/12\nне домен\n"

	var res ImportResult
	if code := call(h, "POST", "/v1/vpn/import?mode=merge", src, &res); code != 200 || res.Applied ||
		len(res.Added) != 2 || len(res.Removed) != 0 || res.Kept != 1 || len(res.Invalid) != 1 {
		t.Errorf("merge, предпросмотр: %d %+v", code, res)
	}
	if code := call(h, "POST", "/v1/vpn/import?mode=replace", src, &res); code != 200 ||
		len(res.Added) != 2 || len(res.Removed) != 2 || res.Kept != 1 {
		t.Errorf("replace, предпросмотр: %d %+v", code, res)
	}
	if len(b.applied) != 0 {
		t.Error("предпросмотр применил изменения")
	}
	if code := call(h, "POST", "/v1/vpn/import?mode=replace&apply=1", src, &res); code != 422 || res.Applied {
		t.Errorf("replace с битой строкой: %d %+v", code, res)
	}
	if code := call(h, "POST", "/v1/vpn/import?mode=merge&apply=1", src, &res); code != 200 || !res.Applied {
		t.Errorf("merge: %d %+v", code, res)
	}
	if got := readFile(t, dir, "vpn_domains.txt"); got != "a.example\nb.example\n10.0.0.0/8\nc.example\n172.16.0.0/12\n" {
		t.Errorf("после merge:\n%s", got)
	}
	clean := "# новый\nb.example\nc.example\n"
	if code := call(h, "POST", "/v1/vpn/import?mode=replace&apply=1", clean, &res); code != 200 || !res.Applied || len(res.Removed) != 3 {
		t.Errorf("replace: %d %+v", code, res)
	}
	if got := readFile(t, dir, "vpn_domains.txt"); got != clean {
		t.Errorf("после replace — файл как загружен:\n%s", got)
	}
	if code := call(h, "POST", "/v1/vpn/import?mode=other", clean, nil); code != 400 {
		t.Errorf("неизвестный режим: %d", code)
	}

	r := httptest.NewRequest("GET", "http://routerd/v1/vpn/file", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Body.String() != clean || !strings.Contains(w.Header().Get("Content-Disposition"), "vpn_domains.txt") {
		t.Errorf("экспорт: %q %v", w.Body.String(), w.Header())
	}
}

func TestOverrides(t *testing.T) {
	dir, b, h := listsSetup(t, "", "")
	var o Overrides
	if code := call(h, "GET", "/v1/overrides", "", &o); code != 200 || o.Text != "" || len(o.Rules) != 0 {
		t.Errorf("нет файла: %d %+v", code, o)
	}
	bad := "corp.example 10.0.0.53\nbroken\n"
	if code := call(h, "PUT", "/v1/overrides", bad, &o); code != 422 || len(o.Invalid) != 1 || o.Invalid[0].Line != 2 {
		t.Errorf("с ошибкой: %d %+v", code, o)
	}
	if _, err := os.Stat(filepath.Join(dir, "dns_override.txt")); !errors.Is(err, os.ErrNotExist) {
		t.Error("файл с ошибкой сохранён")
	}
	good := "# внутренний DNS\ncorp.example 10.0.0.53\ncorp.example 10.0.0.54#5353"
	if code := call(h, "PUT", "/v1/overrides?check=1", good, &o); code != 200 || len(o.Rules) != 2 || len(b.applied) != 0 {
		t.Errorf("проверка без сохранения: %d %+v %v", code, o, b.applied)
	}
	if code := call(h, "PUT", "/v1/overrides", good, &o); code != 200 || len(o.Rules) != 2 || o.Rules[1].Server != "10.0.0.54:5353" {
		t.Errorf("сохранение: %d %+v", code, o)
	}
	if readFile(t, dir, "dns_override.txt") != good+"\n" || len(b.applied) != 1 {
		t.Errorf("файл и применение: %v", b.applied)
	}

	b.err = errors.New("сбой")
	var e Error
	if code := call(h, "PUT", "/v1/overrides", good, &e); code != 500 || !strings.Contains(e.Error, "не применён: сбой") {
		t.Errorf("ошибка применения: %d %+v", code, e)
	}
}
