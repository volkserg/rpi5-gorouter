package web

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestPassword(t *testing.T) {
	h, err := HashPassword("correct horse")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(h, "pbkdf2-sha256$600000$") {
		t.Errorf("формат хеша: %s", h)
	}
	if !VerifyPassword("correct horse", h) {
		t.Error("верный пароль не принят")
	}
	for _, bad := range []string{"correct horse ", "", "Correct horse"} {
		if VerifyPassword(bad, h) {
			t.Errorf("неверный пароль %q принят", bad)
		}
	}
	for _, stored := range []string{"", "scrypt$1$2$3", "pbkdf2-sha256$x$a$b", "pbkdf2-sha256$1$!!$b"} {
		if VerifyPassword("x", stored) {
			t.Errorf("испорченный хеш %q принят", stored)
		}
	}
}

func TestUsersFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), UsersFileName)
	m, err := ReadUsers(path)
	if err != nil || len(m) != 0 {
		t.Fatalf("нет файла: %v %v", m, err)
	}
	if err := WriteUsers(path, map[string]string{"b": "h2", "a": "h1"}, -1); err != nil {
		t.Fatal(err)
	}
	st, _ := os.Stat(path)
	if st.Mode().Perm() != 0o640 {
		t.Errorf("права: %v", st.Mode())
	}
	data, _ := os.ReadFile(path)
	if !strings.HasSuffix(string(data), "a:h1\nb:h2\n") {
		t.Errorf("содержимое:\n%s", data)
	}
	s := &userStore{path: path}
	if h, ok := s.get("a"); !ok || h != "h1" {
		t.Errorf("get a: %q %v", h, ok)
	}
	// Изменение файла подхватывается без перезапуска.
	if err := WriteUsers(path, map[string]string{"a": "h1-new"}, -1); err != nil {
		t.Fatal(err)
	}
	if h, _ := s.get("a"); h != "h1-new" {
		t.Errorf("после смены пароля: %q", h)
	}
	if _, ok := s.get("b"); ok {
		t.Error("удалённый пользователь найден")
	}
}

func TestValidLogin(t *testing.T) {
	for _, ok := range []string{"admin", "a.b-c_d@e"} {
		if ValidLogin(ok) != nil {
			t.Errorf("%q отклонён", ok)
		}
	}
	for _, bad := range []string{"", "a:b", "имя", "a b", strings.Repeat("a", 65)} {
		if ValidLogin(bad) == nil {
			t.Errorf("%q принят", bad)
		}
	}
}

func TestToken(t *testing.T) {
	secret := []byte("0123456789abcdef0123456789abcdef")
	now := time.Unix(1_800_000_000, 0)
	users := map[string]string{"admin": "hash1"}
	lookup := func(u string) (string, bool) { h, ok := users[u]; return h, ok }
	tok := makeToken(secret, "admin", "hash1", now.Add(time.Hour))
	if u, ok := checkToken(secret, tok, now, lookup); !ok || u != "admin" {
		t.Fatalf("действительная сессия отклонена: %q %v", u, ok)
	}
	if _, ok := checkToken(secret, tok, now.Add(time.Hour), lookup); ok {
		t.Error("истёкшая сессия принята")
	}
	if _, ok := checkToken([]byte("другой ключ другой ключ другой к"), tok, now, lookup); ok {
		t.Error("сессия с чужим ключом принята")
	}
	users["admin"] = "hash2" // смена пароля завершает сессии
	if _, ok := checkToken(secret, tok, now, lookup); ok {
		t.Error("сессия после смены пароля принята")
	}
	users["admin"] = "hash1"
	parts := strings.Split(tok, ".")
	forged := b64.EncodeToString([]byte("root")) + "." + parts[1] + "." + parts[2]
	users["root"] = "hash1"
	if _, ok := checkToken(secret, forged, now, lookup); ok {
		t.Error("подменённый логин принят")
	}
	for _, bad := range []string{"", "a.b", "a.b.c.d", "!!.1.x"} {
		if _, ok := checkToken(secret, bad, now, lookup); ok {
			t.Errorf("%q принят", bad)
		}
	}
}

func TestLimiter(t *testing.T) {
	l := newLoginLimiter()
	now := time.Unix(1_800_000_000, 0)
	for i := 0; i < limitFree; i++ {
		if l.blocked("1.2.3.4", now) != 0 {
			t.Fatalf("блокировка после %d неудач", i)
		}
		l.fail("1.2.3.4", now)
	}
	if l.blocked("1.2.3.4", now) != 0 {
		t.Fatal("блокировка ровно после limitFree неудач")
	}
	l.fail("1.2.3.4", now)
	if w := l.blocked("1.2.3.4", now); w != limitBase {
		t.Errorf("пауза после первой лишней неудачи: %v", w)
	}
	l.fail("1.2.3.4", now)
	if w := l.blocked("1.2.3.4", now); w != 2*limitBase {
		t.Errorf("пауза удваивается: %v", w)
	}
	for i := 0; i < 10; i++ {
		l.fail("1.2.3.4", now)
	}
	if w := l.blocked("1.2.3.4", now); w != limitMax {
		t.Errorf("пауза не больше limitMax: %v", w)
	}
	if l.blocked("5.6.7.8", now) != 0 {
		t.Error("другой адрес заблокирован")
	}
	l.ok("1.2.3.4")
	if l.blocked("1.2.3.4", now) != 0 {
		t.Error("после успешного входа блокировка осталась")
	}
}

func TestCert(t *testing.T) {
	dir := t.TempDir()
	now := time.Now()
	ips := []netip.Addr{netip.MustParseAddr("192.168.3.2")}
	c, issued, err := ensureCert(dir, ips, []string{"rpi", "rpi.lan"}, now)
	if err != nil || !issued || c.Leaf == nil && len(c.Certificate) == 0 {
		t.Fatalf("выпуск: %v %v", issued, err)
	}
	if _, issued, err := ensureCert(dir, ips, []string{"rpi", "rpi.lan"}, now); err != nil || issued {
		t.Errorf("тот же сертификат перевыпущен: %v %v", issued, err)
	}
	if _, issued, _ := ensureCert(dir, []netip.Addr{netip.MustParseAddr("192.168.3.5")}, nil, now); !issued {
		t.Error("смена адреса: сертификат не перевыпущен")
	}
	if _, issued, _ := ensureCert(dir, []netip.Addr{netip.MustParseAddr("192.168.3.5")}, nil, now.Add(certValidity)); !issued {
		t.Error("истекающий сертификат не перевыпущен")
	}
	st, _ := os.Stat(filepath.Join(dir, keyFile))
	if st.Mode().Perm() != 0o600 {
		t.Errorf("права ключа: %v", st.Mode())
	}
}

func testServer(t *testing.T) (*server, http.Handler) {
	dir := t.TempDir()
	users := filepath.Join(dir, UsersFileName)
	h, err := HashPassword("secret-pass")
	if err != nil {
		t.Fatal(err)
	}
	if err := WriteUsers(users, map[string]string{"admin": h}, -1); err != nil {
		t.Fatal(err)
	}
	s, err := newServer(Options{UsersFile: users, StateDir: dir, APISocket: filepath.Join(dir, "none.sock"),
		Version: "test", Log: slog.New(slog.NewTextHandler(io.Discard, nil))})
	if err != nil {
		t.Fatal(err)
	}
	return s, s.handler()
}

func do(h http.Handler, method, path, body string, hdr map[string]string, cookies ...*http.Cookie) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, "https://rpi:8443"+path, strings.NewReader(body))
	r.RemoteAddr = "192.168.3.50:40000"
	for k, v := range hdr {
		r.Header.Set(k, v)
	}
	for _, c := range cookies {
		r.AddCookie(c)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

var csrf = map[string]string{csrfHeader: "1", "Content-Type": "application/json"}

func TestLoginFlow(t *testing.T) {
	_, h := testServer(t)

	// Без входа: панель → страница входа, API → 401.
	if w := do(h, "GET", "/", "", nil); w.Code != http.StatusFound || w.Header().Get("Location") != "/login" {
		t.Errorf("/ без входа: %d %s", w.Code, w.Header().Get("Location"))
	}
	if w := do(h, "GET", "/api/v1/status", "", nil); w.Code != http.StatusUnauthorized {
		t.Errorf("API без входа: %d", w.Code)
	}
	if w := do(h, "GET", "/login", "", nil); w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "login.js") {
		t.Errorf("/login: %d", w.Code)
	}
	if w := do(h, "GET", "/login", "", nil); !strings.Contains(w.Header().Get("Content-Security-Policy"), "frame-ancestors 'none'") {
		t.Error("нет заголовка CSP")
	}

	// Без заголовка CSRF или с чужого сайта — отказ.
	good := `{"username":"admin","password":"secret-pass","remember":true}`
	if w := do(h, "POST", "/api/login", good, map[string]string{"Content-Type": "application/json"}); w.Code != http.StatusForbidden {
		t.Errorf("вход без CSRF: %d", w.Code)
	}
	if w := do(h, "POST", "/api/login", good, map[string]string{csrfHeader: "1", "Origin": "https://evil.example"}); w.Code != http.StatusForbidden {
		t.Errorf("вход с чужого Origin: %d", w.Code)
	}

	if w := do(h, "POST", "/api/login", `{"username":"admin","password":"wrong"}`, csrf); w.Code != http.StatusUnauthorized {
		t.Errorf("неверный пароль: %d", w.Code)
	}
	if w := do(h, "POST", "/api/login", `{"username":"nobody","password":"x"}`, csrf); w.Code != http.StatusUnauthorized {
		t.Errorf("нет пользователя: %d", w.Code)
	}

	w := do(h, "POST", "/api/login", good, map[string]string{csrfHeader: "1", "Origin": "https://rpi:8443"})
	if w.Code != http.StatusOK {
		t.Fatalf("вход: %d %s", w.Code, w.Body)
	}
	cs := w.Result().Cookies()
	if len(cs) != 1 || !cs[0].Secure || !cs[0].HttpOnly || cs[0].SameSite != http.SameSiteStrictMode {
		t.Fatalf("cookie: %+v", cs)
	}
	if cs[0].MaxAge != int(rememberTTL.Seconds()) {
		t.Errorf("«запомнить устройство»: MaxAge %d", cs[0].MaxAge)
	}
	sess := cs[0]

	if w := do(h, "GET", "/", "", nil, sess); w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "app.js") {
		t.Errorf("панель после входа: %d", w.Code)
	}
	if w := do(h, "GET", "/login", "", nil, sess); w.Code != http.StatusFound {
		t.Errorf("/login после входа: %d", w.Code)
	}
	if w := do(h, "GET", "/api/me", "", nil, sess); w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"user":"admin"`) {
		t.Errorf("/api/me: %d %s", w.Code, w.Body)
	}
	// Демон недоступен (нет сокета) — понятная ошибка, не 500.
	if w := do(h, "GET", "/api/v1/status", "", nil, sess); w.Code != http.StatusBadGateway {
		t.Errorf("API без демона: %d", w.Code)
	}
	if w := do(h, "POST", "/api/v1/status", "", nil, sess); w.Code != http.StatusForbidden {
		t.Errorf("изменяющий запрос без CSRF: %d", w.Code)
	}

	// Без «запомнить» — cookie до закрытия браузера.
	w = do(h, "POST", "/api/login", `{"username":"admin","password":"secret-pass"}`, csrf)
	if c := w.Result().Cookies(); len(c) != 1 || c[0].MaxAge != 0 {
		t.Errorf("сессионная cookie: %+v", c)
	}

	if w := do(h, "POST", "/api/logout", "", csrf, sess); w.Code != http.StatusOK || w.Result().Cookies()[0].MaxAge >= 0 {
		t.Errorf("выход: %d %+v", w.Code, w.Result().Cookies())
	}
}

func TestLoginRateLimit(t *testing.T) {
	_, h := testServer(t)
	bad := `{"username":"admin","password":"wrong"}`
	for i := 0; i <= limitFree; i++ {
		do(h, "POST", "/api/login", bad, csrf)
	}
	w := do(h, "POST", "/api/login", `{"username":"admin","password":"secret-pass"}`, csrf)
	if w.Code != http.StatusTooManyRequests || w.Header().Get("Retry-After") == "" {
		t.Errorf("после серии неудач: %d %s", w.Code, w.Body)
	}
}

func TestStatic(t *testing.T) {
	_, h := testServer(t)
	w := do(h, "GET", "/static/app.js", "", nil)
	if w.Code != http.StatusOK || w.Header().Get("ETag") == "" {
		t.Fatalf("app.js: %d", w.Code)
	}
	if w2 := do(h, "GET", "/static/app.js", "", map[string]string{"If-None-Match": w.Header().Get("ETag")}); w2.Code != http.StatusNotModified {
		t.Errorf("повторный запрос: %d", w2.Code)
	}
	if w := do(h, "GET", "/static/favicon.svg", "", nil); w.Code != http.StatusOK || !strings.HasPrefix(w.Header().Get("Content-Type"), "image/svg+xml") {
		t.Errorf("значок без входа: %d %s", w.Code, w.Header().Get("Content-Type"))
	}
	if w := do(h, "GET", "/static/../web.go", "", nil); w.Code == http.StatusOK {
		t.Error("выход за пределы static")
	}
}
