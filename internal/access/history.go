package access

import (
	"compress/gzip"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/volkserg/rpi5-gorouter/internal/fsutil"
)

// История — итоги по ключу «устройство × ресурс × маршрут» за час. Закрытый
// час записывается на диск один раз (hour-<начало>.json.gz), текущий —
// снимком раз в saveEvery (current.json.gz): карта памяти RPi не изнашивается
// записью каждого соединения. Часы старше hourKeep сливаются в сутки
// (day-<начало>.json.gz) — в памяти и на диске.
const (
	hourKeep  = 48 * time.Hour
	saveEvery = 5 * time.Minute
	// maxRows — предел строк в одном периоде: при переполнении новые
	// ресурсы часа не учитываются (защита памяти от сканирования сети).
	maxRows = 50_000
	// maxPorts — сколько разных портов помнить в строке.
	maxPorts = 4
)

type rowKey struct {
	Device   string
	Resource string
	Route    Route
}

type row struct {
	OK, Timeout, Refused, NoData uint32
	Bytes                        uint64
	Last                         int64
	IP                           netip.Addr
	// SNI — имя из TLS ClientHello, если ресурс известен только по адресу.
	SNI    string
	Ports  []uint16
	Protos uint8 // 1 — TCP, 2 — UDP
	// LastOut — исход последнего соединения + 1 (0 — неизвестен: история
	// старых версий).
	LastOut uint8
}

type period struct {
	start   time.Time
	span    time.Duration
	rows    map[rowKey]*row
	devices map[string]Device
	dropped int
}

func newPeriod(start time.Time, span time.Duration) *period {
	return &period{start: start, span: span, rows: map[rowKey]*row{}, devices: map[string]Device{}}
}

func (p *period) end() time.Time { return p.start.Add(p.span) }

func (p *period) get(dev Device, res string, route Route) *row {
	k := rowKey{dev.Key, res, route}
	r := p.rows[k]
	if r == nil {
		if len(p.rows) >= maxRows {
			p.dropped++
			return nil
		}
		r = &row{}
		p.rows[k] = r
	}
	p.devices[dev.Key] = dev
	return r
}

func (r *row) merge(o *row) {
	r.OK += o.OK
	r.Timeout += o.Timeout
	r.Refused += o.Refused
	r.NoData += o.NoData
	r.Bytes += o.Bytes
	if o.Last >= r.Last {
		r.Last = o.Last
		if o.IP.IsValid() {
			r.IP = o.IP
		}
		if o.LastOut != 0 {
			r.LastOut = o.LastOut
		}
	}
	if o.SNI != "" && (r.SNI == "" || o.Last >= r.Last) {
		r.SNI = o.SNI
	}
	for _, p := range o.Ports {
		r.addPort(p)
	}
	r.Protos |= o.Protos
}

func (r *row) addPort(p uint16) {
	if !slices.Contains(r.Ports, p) && len(r.Ports) < maxPorts {
		r.Ports = append(r.Ports, p)
	}
}

func (p *period) merge(o *period) {
	for k, r := range o.rows {
		cur := p.rows[k]
		if cur == nil {
			if len(p.rows) >= maxRows {
				p.dropped++
				continue
			}
			cur = &row{}
			p.rows[k] = cur
		}
		cur.merge(r)
	}
	for k, d := range o.devices {
		p.devices[k] = d
	}
	p.dropped += o.dropped
}

type history struct {
	dir       string
	retention time.Duration
	log       *slog.Logger

	mu       sync.Mutex
	cur      *period
	hours    []*period // закрытые часы, по возрастанию
	days     []*period // сутки старше hourKeep, по возрастанию
	lastSave time.Time
}

func newHistory(dir string, retention time.Duration, log *slog.Logger) *history {
	return &history{dir: dir, retention: retention, log: log}
}

func hourStart(t time.Time) time.Time { return t.Truncate(time.Hour) }

func dayStart(t time.Time) time.Time {
	y, m, d := t.Date()
	return time.Date(y, m, d, 0, 0, 0, 0, t.Location())
}

// current — период текущего часа (закрывает прошедший).
func (h *history) current(now time.Time) *period {
	hs := hourStart(now)
	if h.cur != nil && h.cur.start.Equal(hs) {
		return h.cur
	}
	if h.cur != nil {
		h.closeHour(h.cur)
	}
	h.cur = newPeriod(hs, time.Hour)
	return h.cur
}

func (h *history) closeHour(p *period) {
	if len(p.rows) == 0 {
		return
	}
	h.hours = append(h.hours, p)
	h.save(p, fmt.Sprintf("hour-%d.json.gz", p.start.Unix()))
}

func (h *history) add(dev Device, res, sni string, ip netip.Addr, port uint16, proto uint8, route Route, out Outcome, now time.Time) {
	h.mu.Lock()
	defer h.mu.Unlock()
	r := h.current(now).get(dev, res, route)
	if r == nil {
		return
	}
	switch out {
	case OK:
		r.OK++
	case Timeout:
		r.Timeout++
	case Refused:
		r.Refused++
	case NoData:
		r.NoData++
	}
	r.Last = now.Unix()
	r.IP = ip
	r.LastOut = uint8(out) + 1
	if sni != "" {
		r.SNI = sni
	}
	r.addPort(port)
	if proto == ProtoUDP {
		r.Protos |= 2
	} else {
		r.Protos |= 1
	}
}

func (h *history) addBytes(dev Device, res, sni string, route Route, n uint64, now time.Time) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if r := h.current(now).get(dev, res, route); r != nil {
		r.Bytes += n
		if sni != "" {
			r.SNI = sni
		}
	}
}

// flush — смена часа, сжатие старых часов в сутки, удаление истории старше
// retention и снимок текущего часа (раз в saveEvery или force).
func (h *history) flush(now time.Time, force bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.current(now)

	// Часы старше hourKeep — в сутки; сутки записываются, когда в них не
	// осталось часов моложе hourKeep.
	// Сначала записываются сутки, потом удаляются часы: при сбое между ними
	// час учтётся дважды, но не потеряется.
	cut := now.Add(-hourKeep)
	keep := h.hours[:0]
	touched := map[*period]bool{}
	var merged []*period
	for _, p := range h.hours {
		if p.end().After(cut) {
			keep = append(keep, p)
			continue
		}
		d := h.day(dayStart(p.start))
		d.merge(p)
		touched[d] = true
		merged = append(merged, p)
	}
	h.hours = keep
	for d := range touched {
		h.save(d, fmt.Sprintf("day-%d.json.gz", d.start.Unix()))
	}
	for _, p := range merged {
		h.remove(fmt.Sprintf("hour-%d.json.gz", p.start.Unix()))
	}

	if h.retention > 0 {
		old := now.Add(-h.retention)
		days := h.days[:0]
		for _, d := range h.days {
			if d.end().Before(old) {
				h.remove(fmt.Sprintf("day-%d.json.gz", d.start.Unix()))
				continue
			}
			days = append(days, d)
		}
		h.days = days
	}

	if force || now.Sub(h.lastSave) >= saveEvery {
		h.lastSave = now
		h.save(h.cur, "current.json.gz")
	}
}

func (h *history) day(start time.Time) *period {
	for _, d := range h.days {
		if d.start.Equal(start) {
			return d
		}
	}
	d := newPeriod(start, dayStart(start.Add(36*time.Hour)).Sub(start))
	h.days = append(h.days, d)
	sort.Slice(h.days, func(i, j int) bool { return h.days[i].start.Before(h.days[j].start) })
	return d
}

// --- файлы ------------------------------------------------------------------

type fileRow struct {
	D  string     `json:"d"`
	R  string     `json:"r"`
	T  Route      `json:"t,omitempty"`
	OK uint32     `json:"ok,omitempty"`
	TO uint32     `json:"to,omitempty"`
	RF uint32     `json:"rf,omitempty"`
	ND uint32     `json:"nd,omitempty"`
	B  uint64     `json:"b,omitempty"`
	L  int64      `json:"l"`
	IP netip.Addr `json:"ip"`
	P  []uint16   `json:"p,omitempty"`
	X  uint8      `json:"x,omitempty"`
	S  string     `json:"s,omitempty"`
	LO uint8      `json:"lo,omitempty"`
}

type fileData struct {
	Start   int64             `json:"start"`
	Span    int64             `json:"span"`
	Devices map[string]Device `json:"devices"`
	Rows    []fileRow         `json:"rows"`
	Dropped int               `json:"dropped,omitempty"`
}

func (h *history) save(p *period, name string) {
	if h.dir == "" || p == nil {
		return
	}
	fd := fileData{Start: p.start.Unix(), Span: int64(p.span / time.Second), Devices: p.devices, Dropped: p.dropped}
	for k, r := range p.rows {
		fd.Rows = append(fd.Rows, fileRow{D: k.Device, R: k.Resource, T: k.Route, OK: r.OK, TO: r.Timeout,
			RF: r.Refused, ND: r.NoData, B: r.Bytes, L: r.Last, IP: r.IP, P: r.Ports, X: r.Protos, S: r.SNI, LO: r.LastOut})
	}
	var b strings.Builder
	zw := gzip.NewWriter(&b)
	if err := json.NewEncoder(zw).Encode(fd); err == nil {
		err = zw.Close()
	}
	if err := os.MkdirAll(h.dir, 0o750); err != nil {
		h.log.Warn("история обращений не сохранена", "ошибка", err)
		return
	}
	if err := fsutil.WriteFile(filepath.Join(h.dir, name), []byte(b.String()), 0o640, -1); err != nil {
		h.log.Warn("история обращений не сохранена", "файл", name, "ошибка", err)
	}
}

func (h *history) remove(name string) {
	if h.dir == "" {
		return
	}
	if err := os.Remove(filepath.Join(h.dir, name)); err != nil && !errors.Is(err, fs.ErrNotExist) {
		h.log.Warn("старая история обращений не удалена", "файл", name, "ошибка", err)
	}
}

func readPeriod(path string) (*period, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	zr, err := gzip.NewReader(f)
	if err != nil {
		return nil, err
	}
	var fd fileData
	if err := json.NewDecoder(zr).Decode(&fd); err != nil {
		return nil, err
	}
	p := newPeriod(time.Unix(fd.Start, 0), time.Duration(fd.Span)*time.Second)
	for k, d := range fd.Devices {
		p.devices[k] = d
	}
	p.dropped = fd.Dropped
	for _, r := range fd.Rows {
		p.rows[rowKey{r.D, r.R, r.T}] = &row{OK: r.OK, Timeout: r.TO, Refused: r.RF, NoData: r.ND,
			Bytes: r.B, Last: r.L, IP: r.IP, Ports: r.P, Protos: r.X, SNI: r.S, LastOut: r.LO}
	}
	return p, nil
}

// load читает историю из каталога; испорченный файл пропускается.
func (h *history) load(now time.Time) {
	if h.dir == "" {
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	ents, err := os.ReadDir(h.dir)
	if err != nil {
		if !errors.Is(err, fs.ErrNotExist) {
			h.log.Warn("история обращений не прочитана", "ошибка", err)
		}
		return
	}
	var cur *period
	for _, e := range ents {
		name := e.Name()
		if !strings.HasSuffix(name, ".json.gz") {
			continue
		}
		p, err := readPeriod(filepath.Join(h.dir, name))
		if err != nil {
			h.log.Warn("файл истории обращений пропущен", "файл", name, "ошибка", err)
			continue
		}
		switch {
		case strings.HasPrefix(name, "day-"):
			h.days = append(h.days, p)
		case strings.HasPrefix(name, "hour-"):
			h.hours = append(h.hours, p)
		case name == "current.json.gz":
			cur = p
		}
	}
	// Снимок текущего часа: тот же час — продолжается; прошлый час, ещё не
	// записанный (демон остановлен в прошлом часе), — закрывается.
	if cur != nil && !slices.ContainsFunc(h.hours, func(p *period) bool { return p.start.Equal(cur.start) }) {
		if cur.start.Equal(hourStart(now)) {
			h.cur = cur
		} else if len(cur.rows) > 0 {
			h.hours = append(h.hours, cur)
			h.save(cur, fmt.Sprintf("hour-%d.json.gz", cur.start.Unix()))
		}
	}
	sort.Slice(h.days, func(i, j int) bool { return h.days[i].start.Before(h.days[j].start) })
	sort.Slice(h.hours, func(i, j int) bool { return h.hours[i].start.Before(h.hours[j].start) })
	h.lastSave = now
}
