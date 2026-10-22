package access

import (
	"net/netip"
	"sort"
	"strings"
	"time"
)

// Query — выборка из истории.
type Query struct {
	// Since — за какой период (от текущего момента).
	Since  time.Duration
	Device string // ключ устройства; пусто — все
	Route  string // direct, tunnel или пусто
	// Status: problems — есть таймауты, отказы или «нет данных»; ok — только
	// успешные; пусто — все.
	Status string
	Search string
	Limit  int
}

// Row — итог по ресурсу для устройства.
type Row struct {
	Device   string   `json:"device"`
	Resource string   `json:"resource"`
	IP       string   `json:"ip"`
	Ports    []uint16 `json:"ports"`
	Proto    string   `json:"proto"`
	Route    string   `json:"route"`
	OK       uint32   `json:"ok"`
	Timeout  uint32   `json:"timeout"`
	Refused  uint32   `json:"refused"`
	NoData   uint32   `json:"nodata"`
	Bytes    uint64   `json:"bytes"`
	Last     int64    `json:"last"`
	InList   bool     `json:"in_list"`
	// ListEntry — запись списка VPN, которая покрывает ресурс.
	ListEntry string `json:"list_entry,omitempty"`
}

// Candidate — ресурс, который напрямую не отвечает: кандидат в список VPN.
type Candidate struct {
	Resource string   `json:"resource"`
	IP       string   `json:"ip"`
	Timeout  uint32   `json:"timeout"`
	OK       uint32   `json:"ok"`
	Devices  int      `json:"devices"`
	Last     int64    `json:"last"`
	Suggest  []string `json:"suggest"`
}

// Totals — сводка выборки.
type Totals struct {
	Connections uint64 `json:"connections"`
	OK          uint64 `json:"ok"`
	Problems    uint64 `json:"problems"`
	Tunnel      uint64 `json:"tunnel"`
}

// Result — ответ на Query.
type Result struct {
	Rows       []Row        `json:"rows"`
	Truncated  bool         `json:"truncated"`
	Devices    []DeviceInfo `json:"devices"`
	Candidates []Candidate  `json:"candidates"`
	Totals     Totals       `json:"totals"`
	Since      int64        `json:"since"`
	Retention  int64        `json:"retention"`
}

// DeviceInfo — устройство в выборке.
type DeviceInfo struct {
	Device
	Connections uint64 `json:"connections"`
	Problems    uint64 `json:"problems"`
	Last        int64  `json:"last"`
}

// candidateMin — сколько таймаутов нужно, чтобы ресурс стал кандидатом.
const candidateMin = 2

// Query выбирает итоги за период q.Since.
func (t *Tracker) Query(q Query) Result {
	now := t.o.Now()
	from := now.Add(-q.Since)
	agg, devs := t.hist.collect(from)

	res := Result{Rows: []Row{}, Devices: []DeviceInfo{}, Candidates: []Candidate{},
		Since: from.Unix(), Retention: int64(t.o.Retention / time.Second)}
	devStats := map[string]*DeviceInfo{}
	type candAgg struct {
		c    Candidate
		devs map[string]bool
		ip   netip.Addr
	}
	cands := map[string]*candAgg{}
	search := strings.ToLower(strings.TrimSpace(q.Search))

	for k, r := range agg {
		total := uint64(r.OK + r.Timeout + r.Refused + r.NoData)
		problems := uint64(r.Timeout + r.Refused + r.NoData)
		ds := devStats[k.Device]
		if ds == nil {
			ds = &DeviceInfo{Device: devs[k.Device]}
			devStats[k.Device] = ds
		}
		ds.Connections += total
		ds.Problems += problems
		ds.Last = max(ds.Last, r.Last)

		entry, inList := t.o.InList(nameOf(k.Resource), r.IP)
		if k.Route == Direct && r.Timeout > 0 && !inList {
			ca := cands[k.Resource]
			if ca == nil {
				ca = &candAgg{c: Candidate{Resource: k.Resource}, devs: map[string]bool{}}
				cands[k.Resource] = ca
			}
			ca.c.Timeout += r.Timeout
			ca.c.OK += r.OK
			ca.devs[k.Device] = true
			if r.Last >= ca.c.Last {
				ca.c.Last, ca.ip = r.Last, r.IP
			}
		}

		if q.Device != "" && k.Device != q.Device {
			continue
		}
		if q.Route != "" && k.Route.String() != q.Route {
			continue
		}
		if q.Status == "problems" && problems == 0 || q.Status == "ok" && problems > 0 {
			continue
		}
		if search != "" && !strings.Contains(k.Resource, search) && !strings.Contains(r.IP.String(), search) &&
			!strings.Contains(strings.ToLower(devs[k.Device].Name), search) {
			continue
		}
		res.Totals.Connections += total
		res.Totals.OK += uint64(r.OK)
		res.Totals.Problems += problems
		if k.Route == Tunnel {
			res.Totals.Tunnel += total
		}
		res.Rows = append(res.Rows, Row{
			Device: k.Device, Resource: k.Resource, IP: ipString(r.IP), Ports: r.Ports, Proto: protoName(r.Protos),
			Route: k.Route.String(), OK: r.OK, Timeout: r.Timeout, Refused: r.Refused, NoData: r.NoData,
			Bytes: r.Bytes, Last: r.Last, InList: inList, ListEntry: entry,
		})
	}

	// Сначала проблемные, затем по времени последнего обращения.
	sort.Slice(res.Rows, func(i, j int) bool {
		a, b := res.Rows[i], res.Rows[j]
		pa, pb := a.Timeout+a.Refused+a.NoData > 0, b.Timeout+b.Refused+b.NoData > 0
		if pa != pb && q.Status == "problems" {
			return pa
		}
		if a.Last != b.Last {
			return a.Last > b.Last
		}
		return a.Resource < b.Resource
	})
	if q.Limit > 0 && len(res.Rows) > q.Limit {
		res.Rows, res.Truncated = res.Rows[:q.Limit], true
	}

	for _, ds := range devStats {
		res.Devices = append(res.Devices, *ds)
	}
	sort.Slice(res.Devices, func(i, j int) bool {
		if res.Devices[i].Connections != res.Devices[j].Connections {
			return res.Devices[i].Connections > res.Devices[j].Connections
		}
		return res.Devices[i].Key < res.Devices[j].Key
	})

	for _, ca := range cands {
		c := ca.c
		// Кандидат — таймауты повторяются и это хотя бы половина обращений.
		if c.Timeout < candidateMin || c.Timeout < c.OK {
			continue
		}
		c.Devices = len(ca.devs)
		c.IP = ipString(ca.ip)
		c.Suggest = Suggest(c.Resource)
		res.Candidates = append(res.Candidates, c)
	}
	sort.Slice(res.Candidates, func(i, j int) bool {
		if res.Candidates[i].Timeout != res.Candidates[j].Timeout {
			return res.Candidates[i].Timeout > res.Candidates[j].Timeout
		}
		return res.Candidates[i].Resource < res.Candidates[j].Resource
	})
	return res
}

// nameOf — имя ресурса или пусто, если ресурс известен только по адресу.
func nameOf(res string) string {
	if _, err := netip.ParseAddr(res); err == nil {
		return ""
	}
	return res
}

func ipString(a netip.Addr) string {
	if !a.IsValid() {
		return ""
	}
	return a.String()
}

func protoName(x uint8) string {
	switch x {
	case 1:
		return "tcp"
	case 2:
		return "udp"
	case 3:
		return "tcp+udp"
	}
	return ""
}

// Suggest — что добавить в список для ресурса: сам домен и родительские
// домены (без зоны верхнего уровня и коротких зон вида co.uk); для адреса —
// он сам.
func Suggest(res string) []string {
	if nameOf(res) == "" {
		return []string{res}
	}
	labels := strings.Split(res, ".")
	minLabels := 2
	if n := len(labels); n >= 3 && len(labels[n-1]) == 2 && len(labels[n-2]) <= 3 {
		minLabels = 3 // example.co.uk, example.com.ru
	}
	var out []string
	for i := 0; len(labels)-i >= minLabels; i++ {
		out = append(out, strings.Join(labels[i:], "."))
	}
	if len(out) == 0 {
		out = []string{res}
	}
	return out
}

// collect — сумма периодов, пересекающихся с [from, now].
func (h *history) collect(from time.Time) (map[rowKey]*row, map[string]Device) {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := map[rowKey]*row{}
	devs := map[string]Device{}
	add := func(p *period) {
		if p == nil || !p.end().After(from) {
			return
		}
		for k, r := range p.rows {
			cur := out[k]
			if cur == nil {
				cur = &row{}
				out[k] = cur
			}
			cur.merge(r)
		}
		for k, d := range p.devices {
			devs[k] = d
		}
	}
	for _, d := range h.days {
		add(d)
	}
	for _, p := range h.hours {
		add(p)
	}
	add(h.cur)
	return out, devs
}
