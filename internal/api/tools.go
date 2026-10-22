package api

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/volkserg/rpi5-gorouter/internal/probe"
)

// Unit — состояние юнита systemd.
type Unit struct {
	Unit      string `json:"unit"`
	Label     string `json:"label"`
	Installed bool   `json:"installed"`
	Active    string `json:"active"`
	Sub       string `json:"sub"`
}

// CheckRequest — проверка ресурса.
type CheckRequest struct {
	Target string `json:"target"`
	Port   uint16 `json:"port"`
}

// CheckResult — доступен ли ресурс напрямую и через туннель.
type CheckResult struct {
	Target    string     `json:"target"`
	Name      string     `json:"name,omitempty"`
	Addrs     []string   `json:"addrs"`
	Addr      string     `json:"addr"`
	Port      uint16     `json:"port"`
	InList    bool       `json:"in_list"`
	ListEntry string     `json:"list_entry,omitempty"`
	Suggest   []string   `json:"suggest"`
	Route     string     `json:"route"` // маршрут устройств LAN к ресурсу сейчас
	Direct    probe.Path `json:"direct"`
	Tunnel    probe.Path `json:"tunnel"`
}

// TunnelCheck — внешний IP напрямую и через туннель.
type TunnelCheck struct {
	Enabled   bool       `json:"enabled"`
	URL       string     `json:"url,omitempty"`
	CheckedAt time.Time  `json:"checked_at"`
	DirectIP  string     `json:"direct_ip,omitempty"`
	TunnelIP  string     `json:"tunnel_ip,omitempty"`
	Direct    probe.Path `json:"direct"`
	Tunnel    probe.Path `json:"tunnel"`
}

// DeviceRow — устройство LAN.
type DeviceRow struct {
	Key      string `json:"key"`
	Name     string `json:"name"`
	Hostname string `json:"hostname,omitempty"`
	IP       string `json:"ip"`
	MAC      string `json:"mac,omitempty"`
	// Kind: lease — аренда DHCP, local — сервис RPi (LOCAL_CLIENTS),
	// seen — адрес без аренды, замеченный в обращениях.
	Kind        string    `json:"kind"`
	Active      bool      `json:"active"`
	Expires     time.Time `json:"expires,omitzero"`
	Connections uint64    `json:"connections"`
	Problems    uint64    `json:"problems"`
	Last        int64     `json:"last,omitempty"`
}

// JournalEntry — запись журнала systemd.
type JournalEntry struct {
	Time     int64  `json:"time"` // мс
	Priority int    `json:"priority"`
	Message  string `json:"message"`
}

// Journal — ответ GET /v1/journal.
type Journal struct {
	Unit    string         `json:"unit"`
	Entries []JournalEntry `json:"entries"`
	Cursor  string         `json:"cursor"`
}

// Tools — проверки, устройства, журнал (часть Backend).
type Tools interface {
	Services(ctx context.Context) ([]Unit, error)
	Check(ctx context.Context, req CheckRequest) (CheckResult, error)
	// TunnelCheck — последний результат; run — проверить заново.
	TunnelCheck(ctx context.Context, run bool) TunnelCheck
	Devices() []DeviceRow
	// Journal — записи журнала юнита (routerd, web, tunnel, pihole,
	// dnscrypt) после cursor (пусто — последние lines).
	Journal(ctx context.Context, unit, cursor string, lines int) (Journal, error)
}

func toolRoutes(mux *http.ServeMux, b Backend) {
	mux.HandleFunc("GET /v1/services", func(w http.ResponseWriter, r *http.Request) {
		us, err := b.Services(r.Context())
		if err != nil {
			WriteJSON(w, http.StatusBadGateway, Error{"systemd: " + err.Error()})
			return
		}
		WriteJSON(w, http.StatusOK, us)
	})
	mux.HandleFunc("POST /v1/check", func(w http.ResponseWriter, r *http.Request) {
		var req CheckRequest
		if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&req); err != nil {
			WriteJSON(w, http.StatusBadRequest, Error{"некорректный запрос"})
			return
		}
		req.Target = strings.TrimSpace(req.Target)
		if req.Port == 0 {
			req.Port = 443
		}
		res, err := b.Check(r.Context(), req)
		if err != nil {
			WriteJSON(w, http.StatusBadRequest, Error{err.Error()})
			return
		}
		WriteJSON(w, http.StatusOK, res)
	})
	mux.HandleFunc("GET /v1/tunnel", func(w http.ResponseWriter, r *http.Request) {
		WriteJSON(w, http.StatusOK, b.TunnelCheck(r.Context(), false))
	})
	mux.HandleFunc("POST /v1/tunnel", func(w http.ResponseWriter, r *http.Request) {
		WriteJSON(w, http.StatusOK, b.TunnelCheck(r.Context(), true))
	})
	mux.HandleFunc("GET /v1/devices", func(w http.ResponseWriter, r *http.Request) {
		WriteJSON(w, http.StatusOK, b.Devices())
	})
	mux.HandleFunc("GET /v1/journal", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		lines, _ := strconv.Atoi(q.Get("lines"))
		if lines <= 0 || lines > 1000 {
			lines = 200
		}
		j, err := b.Journal(r.Context(), q.Get("unit"), q.Get("cursor"), lines)
		if err != nil {
			WriteJSON(w, http.StatusBadRequest, Error{err.Error()})
			return
		}
		WriteJSON(w, http.StatusOK, j)
	})
}
