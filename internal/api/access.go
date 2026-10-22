package api

import (
	"net/http"
	"strconv"
	"time"

	"github.com/volkserg/rpi5-gorouter/internal/access"
)

// maxAccessRows — предел строк в ответе (страница фильтрует дальше сама).
const maxAccessRows = 3000

// accessQuery — GET /v1/access?hours=24&device=&route=&status=&q=.
func accessQuery(w http.ResponseWriter, r *http.Request, b Backend) {
	q := r.URL.Query()
	hours, err := strconv.Atoi(q.Get("hours"))
	if q.Get("hours") == "" {
		hours, err = 24, nil
	}
	if err != nil || hours < 1 || hours > 90*24 {
		WriteJSON(w, http.StatusBadRequest, Error{"hours: от 1 до 2160"})
		return
	}
	res, ok := b.Access(access.Query{
		Since:  time.Duration(hours) * time.Hour,
		Device: q.Get("device"),
		Route:  q.Get("route"),
		Status: q.Get("status"),
		Search: q.Get("q"),
		Limit:  maxAccessRows,
	})
	if !ok {
		WriteJSON(w, http.StatusNotFound, Error{"учёт обращений выключен (ACCESS_HISTORY_DAYS=0)"})
		return
	}
	WriteJSON(w, http.StatusOK, res)
}
