// Package api — локальный API демона routerd: HTTP с JSON поверх unix-сокета.
// Им пользуется веб-интерфейс (routerd-web): он проверяет вход пользователя и
// передаёт запросы сюда. Доступ к сокету — у root и группы WebGroup; сам API
// пользователей не проверяет.
package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"net/http"
	"os"
	"os/user"
	"strconv"
	"time"

	"github.com/volkserg/rpi5-gorouter/internal/access"
	"github.com/volkserg/rpi5-gorouter/internal/lists"
)

const (
	// DefaultSocket — сокет API (каталог создаёт systemd: RuntimeDirectory=routerd).
	DefaultSocket = "/run/routerd/api.sock"
	// WebGroup — группа пользователя routerd-web: ей открыт сокет API.
	WebGroup = "routerd-web"
	// UserHeader — логин пользователя веб-интерфейса, от имени которого
	// пришёл запрос (для журнала изменений).
	UserHeader = "X-Routerd-User"
)

// SocketPath — путь к сокету: ROUTERD_API_SOCKET (стенд, тесты) или DefaultSocket.
func SocketPath() string {
	if p := os.Getenv("ROUTERD_API_SOCKET"); p != "" {
		return p
	}
	return DefaultSocket
}

// Status — состояние демона для обзорной страницы.
type Status struct {
	Version   string    `json:"version"`
	StartedAt time.Time `json:"started_at"`
	// Mode — VPN_MODE; Failover — VPN_FAILOVER (closed|open).
	Mode     string `json:"mode"`
	Failover string `json:"failover"`
	// TunnelUp — локальная часть туннеля доступна (порт GOST слушает или
	// поднят интерфейс tun в режиме route).
	TunnelUp bool `json:"tunnel_up"`
	// Bypass — перехват снят: туннель недоступен при VPN_FAILOVER=open.
	Bypass       bool   `json:"bypass"`
	Domains      int    `json:"domains"`
	Nets         int    `json:"nets"`
	Overrides    int    `json:"overrides"`
	LocalClients int    `json:"local_clients"`
	DHCP         bool   `json:"dhcp"`
	RPiIP        string `json:"rpi_ip"`
	LAN          string `json:"lan"`
	// Access — учёт обращений включён; HistoryDays — сутки истории.
	Access      bool `json:"access"`
	HistoryDays int  `json:"history_days"`
}

// Backend — то, что API берёт у демона.
type Backend interface {
	Status() Status
	// Apply применяет изменённые списки (как reload-vpn-domains) и ждёт
	// результата; user и what — для журнала.
	Apply(user, what string) error
	// Access — выборка из истории обращений; false — учёт выключен.
	Access(q access.Query) (access.Result, bool)
	Tools
}

// Error — тело ответа с ошибкой.
type Error struct {
	Error string `json:"error"`
}

// Handler — обработчик запросов API; configDir — каталог конфигов (списки).
func Handler(b Backend, configDir string) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/status", func(w http.ResponseWriter, r *http.Request) {
		WriteJSON(w, http.StatusOK, b.Status())
	})
	l := &listsAPI{b: b, dir: configDir}
	mux.HandleFunc("GET /v1/vpn", l.list)
	mux.HandleFunc("POST /v1/vpn", l.add)
	mux.HandleFunc("DELETE /v1/vpn", l.remove)
	mux.HandleFunc("GET /v1/vpn/file", l.file(l.vpnPath(), lists.VPNFileName))
	mux.HandleFunc("POST /v1/vpn/import", l.importVPN)
	mux.HandleFunc("GET /v1/overrides", l.overrides)
	mux.HandleFunc("PUT /v1/overrides", l.saveOverrides)
	mux.HandleFunc("GET /v1/overrides/file", l.file(l.overridePath(), lists.OverrideFileName))
	mux.HandleFunc("GET /v1/access", func(w http.ResponseWriter, r *http.Request) { accessQuery(w, r, b) })
	toolRoutes(mux, b)
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		WriteJSON(w, http.StatusNotFound, Error{"нет такого метода API: " + r.Method + " " + r.URL.Path})
	})
	return mux
}

// WriteJSON отвечает JSON-документом.
func WriteJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

// Listen создаёт сокет API: прежний файл сокета удаляется, права — 0660,
// группа — WebGroup, если она есть (иначе сокет доступен только root).
func Listen(path string) (net.Listener, error) {
	if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, err
	}
	l, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
	mode := os.FileMode(0o600)
	if g, err := user.LookupGroup(WebGroup); err == nil {
		if gid, err := strconv.Atoi(g.Gid); err == nil && os.Chown(path, -1, gid) == nil {
			mode = 0o660
		}
	}
	if err := os.Chmod(path, mode); err != nil {
		l.Close()
		return nil, err
	}
	return l, nil
}

// Transport — HTTP-транспорт к сокету API (адрес в URL запроса не важен).
func Transport(path string) *http.Transport {
	return &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", path)
		},
		MaxIdleConns:    4,
		IdleConnTimeout: time.Minute,
	}
}

// Client — клиент API для команд routerd.
type Client struct {
	http *http.Client
}

// NewClient — клиент к сокету path.
func NewClient(path string) *Client {
	return &Client{http: &http.Client{Transport: Transport(path), Timeout: 30 * time.Second}}
}

// Get запрашивает path (например, /v1/status) и разбирает ответ в out.
func (c *Client) Get(ctx context.Context, path string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://routerd"+path, nil)
	if err != nil {
		return err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		var e Error
		if json.NewDecoder(resp.Body).Decode(&e) == nil && e.Error != "" {
			return errors.New(e.Error)
		}
		return fmt.Errorf("routerd API: %s", resp.Status)
	}
	return json.NewDecoder(resp.Body).Decode(out)
}
