// Package web — веб-интерфейс routerd (routerd web serve, юнит routerd-web):
// HTTPS, вход по логину и паролю, страницы панели и шлюз к API демона.
// Сам сервис ничего не меняет в системе: все действия выполняет демон по
// запросам через сокет API, а этот сервис лишь проверяет, кто их делает.
package web

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/netip"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/volkserg/rpi5-gorouter/internal/api"
)

//go:embed assets
var assets embed.FS

const (
	// csrfHeader — обязательный заголовок изменяющих запросов: чужая
	// страница не может выставить его без CORS, а CORS сервер не разрешает.
	csrfHeader = "X-Routerd-CSRF"
	// maxBody — предел тела запроса к API (импорт списка целиком).
	maxBody = 8 << 20
	// maxLoginBody — предел тела запроса входа.
	maxLoginBody = 4 << 10
	// secretFile — ключ подписи сессий в StateDir.
	secretFile = "secret.key"
)

// Options — параметры веб-интерфейса.
type Options struct {
	// Listen — адрес и порт; неуказанный адрес ([::]) — все адреса IPv4 и IPv6.
	Listen netip.AddrPort
	// Allow — с каких адресов принимать соединения; nil — с любых.
	Allow     func(netip.Addr) bool
	UsersFile string
	// StateDir — ключ сессий и сертификат (/var/lib/routerd-web).
	StateDir  string
	APISocket string
	// CertIPs, CertNames — адреса и имена в сертификате.
	CertIPs   []netip.Addr
	CertNames []string
	Version   string
	Log       *slog.Logger
}

type server struct {
	o       Options
	users   *userStore
	secret  []byte
	limiter *loginLimiter
	proxy   *httputil.ReverseProxy
	// hashSem ограничивает одновременные проверки пароля (PBKDF2 нагружает
	// процессор): поток попыток входа не займёт все ядра RPi.
	hashSem chan struct{}
	// dummyHash — хеш для проверки несуществующего логина: время ответа не
	// выдаёт, есть ли такой пользователь.
	dummyHash string
	static    http.Handler
	etags     map[string]string
	now       func() time.Time
}

func newServer(o Options) (*server, error) {
	secret, err := loadSecret(filepath.Join(o.StateDir, secretFile))
	if err != nil {
		return nil, fmt.Errorf("ключ сессий: %w", err)
	}
	dummy, err := HashPassword("routerd-dummy-password")
	if err != nil {
		return nil, err
	}
	sub, err := fs.Sub(assets, "assets/static")
	if err != nil {
		return nil, err
	}
	s := &server{
		o:         o,
		users:     &userStore{path: o.UsersFile},
		secret:    secret,
		limiter:   newLoginLimiter(),
		hashSem:   make(chan struct{}, 2),
		dummyHash: dummy,
		static:    http.StripPrefix("/static/", http.FileServerFS(sub)),
		etags:     map[string]string{},
		now:       time.Now,
	}
	_ = fs.WalkDir(sub, ".", func(p string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			data, _ := fs.ReadFile(sub, p)
			sum := sha256.Sum256(data)
			s.etags["/static/"+p] = `"` + hex.EncodeToString(sum[:8]) + `"`
		}
		return nil
	})
	s.proxy = &httputil.ReverseProxy{
		Transport: api.Transport(o.APISocket),
		Rewrite: func(r *httputil.ProxyRequest) {
			r.Out.URL.Scheme, r.Out.URL.Host = "http", "routerd"
			r.Out.URL.Path = strings.TrimPrefix(r.In.URL.Path, "/api")
			r.Out.URL.RawPath = ""
			r.Out.Host = "routerd"
			r.Out.Header.Del("Cookie")
			r.Out.Header.Set(api.UserHeader, r.In.Header.Get(api.UserHeader))
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			o.Log.Warn("API routerd недоступен", "запрос", r.URL.Path, "ошибка", err)
			api.WriteJSON(w, http.StatusBadGateway, api.Error{Error: "routerd не отвечает — демон остановлен или перезапускается"})
		},
	}
	return s, nil
}

func (s *server) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", s.page("index.html", true))
	mux.HandleFunc("GET /login", s.page("login.html", false))
	mux.HandleFunc("GET /static/", s.serveStatic)
	mux.HandleFunc("POST /api/login", s.login)
	mux.HandleFunc("POST /api/logout", s.logout)
	mux.HandleFunc("GET /api/me", s.auth(s.me))
	mux.HandleFunc("/api/v1/", s.auth(s.forward))
	mux.HandleFunc("/api/", func(w http.ResponseWriter, r *http.Request) {
		api.WriteJSON(w, http.StatusNotFound, api.Error{Error: "нет такого метода"})
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/", http.StatusFound)
	})
	return s.secure(mux)
}

// secure — заголовки безопасности и проверка CSRF для изменяющих запросов.
func (s *server) secure(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", "default-src 'self'; img-src 'self' data:; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Cross-Origin-Opener-Policy", "same-origin")
		switch r.Method {
		case http.MethodGet, http.MethodHead:
		default:
			if r.Header.Get(csrfHeader) != "1" || !sameOrigin(r) {
				api.WriteJSON(w, http.StatusForbidden, api.Error{Error: "запрос отклонён (CSRF)"})
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

// sameOrigin — заголовок Origin (если браузер его прислал) совпадает с сайтом.
func sameOrigin(r *http.Request) bool {
	o := r.Header.Get("Origin")
	return o == "" || o == "https://"+r.Host
}

// session — логин из cookie сессии.
func (s *server) session(r *http.Request) (string, bool) {
	c, err := r.Cookie(cookieName)
	if err != nil {
		return "", false
	}
	return checkToken(s.secret, c.Value, s.now(), s.users.get)
}

func (s *server) auth(next func(http.ResponseWriter, *http.Request, string)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user, ok := s.session(r)
		if !ok {
			api.WriteJSON(w, http.StatusUnauthorized, api.Error{Error: "нужен вход"})
			return
		}
		next(w, r, user)
	}
}

// page отдаёт страницу; auth — только после входа (иначе на /login), без
// auth — страница входа (после входа — на панель).
func (s *server) page(name string, auth bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		_, ok := s.session(r)
		if ok != auth {
			target := "/login"
			if ok {
				target = "/"
			}
			http.Redirect(w, r, target, http.StatusFound)
			return
		}
		data, err := assets.ReadFile(path.Join("assets", name))
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		_, _ = w.Write(data)
	}
}

func (s *server) serveStatic(w http.ResponseWriter, r *http.Request) {
	tag, ok := s.etags[r.URL.Path]
	if !ok {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("ETag", tag)
	if r.Header.Get("If-None-Match") == tag {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	s.static.ServeHTTP(w, r)
}

type loginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Remember bool   `json:"remember"`
}

func (s *server) login(w http.ResponseWriter, r *http.Request) {
	ip := clientIP(r)
	now := s.now()
	if wait := s.limiter.blocked(ip, now); wait > 0 {
		sec := int(wait.Seconds()) + 1
		w.Header().Set("Retry-After", strconv.Itoa(sec))
		api.WriteJSON(w, http.StatusTooManyRequests, map[string]any{
			"error": fmt.Sprintf("Слишком много попыток. Подождите %s.", humanWait(sec)), "retry_after": sec})
		return
	}
	var req loginRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxLoginBody)).Decode(&req); err != nil {
		api.WriteJSON(w, http.StatusBadRequest, api.Error{Error: "некорректный запрос"})
		return
	}
	stored, exists := s.users.get(req.Username)
	check := stored
	if !exists {
		check = s.dummyHash
	}
	s.hashSem <- struct{}{}
	match := VerifyPassword(req.Password, check)
	<-s.hashSem
	if !exists || !match {
		s.limiter.fail(ip, now)
		s.o.Log.Warn("неудачный вход", "логин", req.Username, "адрес", ip)
		api.WriteJSON(w, http.StatusUnauthorized, api.Error{Error: "Неверный логин или пароль."})
		return
	}
	s.limiter.ok(ip)
	ttl := sessionTTL
	if req.Remember {
		ttl = rememberTTL
	}
	c := &http.Cookie{
		Name:     cookieName,
		Value:    makeToken(s.secret, req.Username, stored, now.Add(ttl)),
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
	}
	if req.Remember {
		c.MaxAge = int(ttl.Seconds())
	}
	http.SetCookie(w, c)
	s.o.Log.Info("вход", "логин", req.Username, "адрес", ip, "запомнить", req.Remember)
	api.WriteJSON(w, http.StatusOK, map[string]string{"user": req.Username})
}

func (s *server) logout(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{Name: cookieName, Value: "", Path: "/", MaxAge: -1,
		HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode})
	api.WriteJSON(w, http.StatusOK, map[string]string{})
}

func (s *server) me(w http.ResponseWriter, _ *http.Request, user string) {
	api.WriteJSON(w, http.StatusOK, map[string]string{"user": user, "version": s.o.Version})
}

func (s *server) forward(w http.ResponseWriter, r *http.Request, user string) {
	r.Body = http.MaxBytesReader(w, r.Body, maxBody)
	r.Header.Set(api.UserHeader, user)
	s.proxy.ServeHTTP(w, r)
}

func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func humanWait(sec int) string {
	if sec < 60 {
		return fmt.Sprintf("%d с", sec)
	}
	return fmt.Sprintf("%d мин", (sec+59)/60)
}

// allowListener закрывает соединения с адресов, которым нельзя: веб-интерфейс
// слушает все адреса (в том числе IPv6 для имени .local), но принимает
// только устройства LAN.
type allowListener struct {
	net.Listener
	allow func(netip.Addr) bool
	log   *slog.Logger
}

func (l *allowListener) Accept() (net.Conn, error) {
	for {
		c, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		ap, err := netip.ParseAddrPort(c.RemoteAddr().String())
		if err == nil && l.allow(ap.Addr().Unmap()) {
			return c, nil
		}
		l.log.Debug("соединение не из LAN отклонено", "адрес", c.RemoteAddr().String())
		c.Close()
	}
}

// Serve запускает веб-интерфейс и работает до отмены ctx.
func Serve(ctx context.Context, o Options) error {
	s, err := newServer(o)
	if err != nil {
		return err
	}
	cert, issued, err := ensureCert(o.StateDir, o.CertIPs, o.CertNames, time.Now())
	if err != nil {
		return fmt.Errorf("сертификат: %w", err)
	}
	if issued {
		o.Log.Info("выпущен самоподписанный сертификат", "файл", filepath.Join(o.StateDir, certFile),
			"адреса", o.CertIPs, "имена", o.CertNames)
	}
	if s.users.count() == 0 {
		o.Log.Warn("нет пользователей: войти нельзя. Добавьте: sudo routerd web passwd <логин>", "файл", o.UsersFile)
	}
	srv := &http.Server{
		Addr:    o.Listen.String(),
		Handler: s.handler(),
		TLSConfig: &tls.Config{
			MinVersion:   tls.VersionTLS12,
			Certificates: []tls.Certificate{cert},
		},
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       time.Minute,
		IdleTimeout:       2 * time.Minute,
		ErrorLog:          slog.NewLogLogger(o.Log.Handler(), slog.LevelDebug),
	}
	ln, err := net.Listen("tcp", o.Listen.String())
	if err != nil {
		return err
	}
	if o.Allow != nil {
		ln = &allowListener{Listener: ln, allow: o.Allow, log: o.Log}
	}
	errc := make(chan error, 1)
	go func() { errc <- srv.ServeTLS(ln, "", "") }()
	o.Log.Info("веб-интерфейс запущен", "порт", o.Listen.Port(), "адреса", o.CertIPs, "имена", o.CertNames)
	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
		sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := srv.Shutdown(sctx); err != nil && !errors.Is(err, context.DeadlineExceeded) {
			return err
		}
		return nil
	}
}
