package access

import (
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"
)

var (
	lan     = netip.MustParsePrefix("192.168.3.0/24")
	phone   = netip.MustParseAddr("192.168.3.100")
	laptop  = netip.MustParseAddr("192.168.3.101")
	webIP   = netip.MustParseAddr("203.0.113.10")
	vpnIP   = netip.MustParseAddr("203.0.113.20")
	otherIP = netip.MustParseAddr("198.51.100.77")
)

type clock struct{ t time.Time }

func (c *clock) now() time.Time      { return c.t }
func (c *clock) add(d time.Duration) { c.t = c.t.Add(d) }
func newClock() *clock               { return &clock{time.Date(2026, 10, 22, 10, 0, 5, 0, time.Local)} }

// tcp — запись TCP; устройство отправило запрос (кроме SYN без ответа).
func tcp(src netip.Addr, sport uint16, dst netip.Addr, st uint8, rp, rb uint64) Flow {
	f := Flow{Proto: ProtoTCP, Src: src, SPort: sport, Dst: dst, DPort: 443, TCPState: st,
		OrigPkts: 3, OrigBytes: 700, ReplyPkts: rp, ReplyBytes: rb}
	if st == tcpSynSent {
		f.OrigPkts, f.OrigBytes = 1, 60
	}
	return f
}

func newTestTracker(c *clock, dir string) *Tracker {
	return New(Options{
		Dir:       dir,
		Retention: 7 * 24 * time.Hour,
		Watch:     func(src, dst netip.Addr) bool { return lan.Contains(src) && !lan.Contains(dst) },
		Device: func(a netip.Addr) Device {
			if a == phone {
				return Device{Key: "mac:aa", Name: "phone", IP: a.String(), MAC: "aa"}
			}
			return Device{Key: "ip:" + a.String(), Name: a.String(), IP: a.String()}
		},
		Route: func(_ uint8, dst netip.Addr, _ uint16) Route {
			if dst == vpnIP {
				return Tunnel
			}
			return Direct
		},
		InList: func(name string, ip netip.Addr) (string, bool) {
			if name == "vpn.example" {
				return name, true
			}
			return "", ip == vpnIP
		},
		Now: c.now,
	})
}

func rowOf(t *testing.T, tr *Tracker, dev, res string) Row {
	t.Helper()
	for _, r := range tr.Query(Query{Since: time.Hour}).Rows {
		if r.Device == dev && r.Resource == res {
			return r
		}
	}
	t.Fatalf("нет строки %s × %s", dev, res)
	return Row{}
}

func TestOutcomes(t *testing.T) {
	c := newClock()
	tr := newTestTracker(c, "")
	// Соединение, начатое до запуска, не учитывается.
	tr.Observe([]Flow{tcp(phone, 1000, otherIP, tcpEstablished, 5, 5000)}, true)
	tr.Answer(phone, "site.example", []netip.Addr{webIP}, time.Minute)
	tr.Answer(laptop, "vpn.example", []netip.Addr{vpnIP}, time.Minute)

	snap := []Flow{
		tcp(phone, 1001, webIP, tcpSynSent, 0, 0),                                        // будет таймаут
		tcp(phone, 1002, webIP, tcpEstablished, 4, 5000),                                 // успех напрямую
		tcp(laptop, 2001, vpnIP, tcpEstablished, 2, 120),                                 // туннель: пока без данных
		tcp(laptop, 2002, vpnIP, tcpEstablished, 4, 9000),                                // туннель с данными
		tcp(phone, 1003, otherIP, tcpClose, 1, 40),                                       // RST — отказ
		{Proto: ProtoUDP, Src: phone, SPort: 5000, Dst: webIP, DPort: 3478, OrigPkts: 2}, // UDP без ответа
		tcp(netip.MustParseAddr("10.0.0.5"), 1, webIP, tcpEstablished, 1, 60),            // не LAN
	}
	tr.Observe(snap, true)
	if r := rowOf(t, tr, "mac:aa", "site.example"); r.OK != 1 || r.Timeout != 0 || r.Route != "direct" || r.Ports[0] != 443 {
		t.Errorf("успех напрямую: %+v", r)
	}
	if r := rowOf(t, tr, "ip:192.168.3.101", "vpn.example"); r.OK != 1 || r.NoData != 0 || r.Route != "tunnel" || !r.InList || r.ListEntry != "vpn.example" {
		t.Errorf("туннель с данными: %+v", r)
	}
	if r := rowOf(t, tr, "mac:aa", otherIP.String()); r.Refused != 1 {
		t.Errorf("отказ (ресурс без имени — по адресу): %+v", r)
	}

	c.add(16 * time.Second)
	snap[2] = tcp(laptop, 2001, vpnIP, tcpTimeWait, 3, 160) // закрыто без данных
	tr.Observe(snap, true)
	if r := rowOf(t, tr, "mac:aa", "site.example"); r.Timeout != 1 || r.OK != 1 {
		t.Errorf("таймаут SYN: %+v", r)
	}
	if r := rowOf(t, tr, "ip:192.168.3.101", "vpn.example"); r.NoData != 1 || r.OK != 1 {
		t.Errorf("туннель без данных: %+v", r)
	}

	c.add(15 * time.Second)
	tr.Observe(snap, true)
	if r := rowOf(t, tr, "mac:aa", "site.example"); r.Timeout != 2 || r.Proto != "tcp+udp" {
		t.Errorf("UDP без ответа — таймаут: %+v", r)
	}

	// Повторные снимки не считают соединения второй раз; исчезновение
	// решённого соединения ничего не добавляет, кроме байтов.
	tr.Observe(nil, true)
	if r := rowOf(t, tr, "mac:aa", "site.example"); r.OK != 1 || r.Timeout != 2 {
		t.Errorf("повторный учёт: %+v", r)
	}
	if r := rowOf(t, tr, "ip:192.168.3.101", "vpn.example"); r.Bytes != 160+9000 {
		t.Errorf("байты ответа: %+v", r)
	}
	if n := len(tr.Query(Query{Since: time.Hour}).Rows); n != 3 {
		t.Errorf("строк %d, ожидалось 3 (соединение до запуска и не-LAN не учтены)", n)
	}
}

func TestGoneAndNoAcct(t *testing.T) {
	c := newClock()
	tr := newTestTracker(c, "")
	tr.Observe(nil, false)
	tr.Observe([]Flow{
		tcp(phone, 1, webIP, tcpSynSent, 0, 0),
		tcp(phone, 2, vpnIP, tcpSynRecv, 0, 0),
		{Proto: ProtoUDP, Src: phone, SPort: 3, Dst: webIP, DPort: 53},
	}, false)
	c.add(3 * time.Second)
	tr.Observe(nil, false) // исчезли, не дождавшись решения
	rows := tr.Query(Query{Since: time.Hour}).Rows
	if len(rows) != 2 {
		t.Fatalf("без счётчиков UDP не учитывается: %+v", rows)
	}
	for _, r := range rows {
		if r.Timeout != 1 {
			t.Errorf("исчезло без ответа — таймаут: %+v", r)
		}
	}
}

func TestQueryAndCandidates(t *testing.T) {
	c := newClock()
	tr := newTestTracker(c, "")
	tr.Observe(nil, true)
	tr.Answer(phone, "files.storage.example.com", []netip.Addr{webIP}, time.Minute)
	tr.Answer(laptop, "files.storage.example.com", []netip.Addr{webIP}, time.Minute)
	var port uint16 = 100
	syn := func(src netip.Addr) Flow { port++; return tcp(src, port, webIP, tcpSynSent, 0, 0) }
	tr.Observe([]Flow{syn(phone), syn(phone), syn(laptop)}, true)
	c.add(20 * time.Second)
	tr.Observe(nil, true)
	tr.Observe([]Flow{tcp(laptop, 900, vpnIP, tcpEstablished, 3, 3000)}, true)

	res := tr.Query(Query{Since: time.Hour})
	if len(res.Candidates) != 1 {
		t.Fatalf("кандидаты: %+v", res.Candidates)
	}
	cand := res.Candidates[0]
	if cand.Resource != "files.storage.example.com" || cand.Timeout != 3 || cand.Devices != 2 ||
		!reflect.DeepEqual(cand.Suggest, []string{"files.storage.example.com", "storage.example.com", "example.com"}) {
		t.Errorf("кандидат: %+v", cand)
	}
	if res.Totals.Connections != 4 || res.Totals.Problems != 3 || res.Totals.Tunnel != 1 {
		t.Errorf("сводка: %+v", res.Totals)
	}
	if len(res.Devices) != 2 || res.Devices[0].Key != "ip:192.168.3.101" && res.Devices[0].Connections != 2 {
		t.Errorf("устройства: %+v", res.Devices)
	}
	if r := tr.Query(Query{Since: time.Hour, Route: "tunnel"}).Rows; len(r) != 1 || r[0].Route != "tunnel" {
		t.Errorf("фильтр по маршруту: %+v", r)
	}
	if r := tr.Query(Query{Since: time.Hour, Status: "problems"}).Rows; len(r) != 2 {
		t.Errorf("фильтр «проблемы»: %+v", r)
	}
	if r := tr.Query(Query{Since: time.Hour, Device: "mac:aa"}).Rows; len(r) != 1 || r[0].Timeout != 2 {
		t.Errorf("фильтр по устройству: %+v", r)
	}
	if r := tr.Query(Query{Since: time.Hour, Search: "PHONE"}).Rows; len(r) != 1 {
		t.Errorf("поиск по имени устройства: %+v", r)
	}
	if r := tr.Query(Query{Since: time.Hour, Limit: 1}); len(r.Rows) != 1 || !r.Truncated {
		t.Errorf("предел строк: %+v", r)
	}
	// Ресурс в списке VPN — не кандидат.
	tr.o.InList = func(name string, _ netip.Addr) (string, bool) {
		return "example.com", strings.HasSuffix(name, "example.com")
	}
	if res := tr.Query(Query{Since: time.Hour}); len(res.Candidates) != 0 {
		t.Errorf("ресурс из списка остался кандидатом: %+v", res.Candidates)
	}
}

func TestSuggest(t *testing.T) {
	for in, want := range map[string][]string{
		"a.b.example.com":   {"a.b.example.com", "b.example.com", "example.com"},
		"example.com":       {"example.com"},
		"cdn.example.co.uk": {"cdn.example.co.uk", "example.co.uk"},
		"203.0.113.10":      {"203.0.113.10"},
		"localhost":         {"localhost"},
	} {
		if got := Suggest(in); !reflect.DeepEqual(got, want) {
			t.Errorf("Suggest(%s) = %v, ожидалось %v", in, got, want)
		}
	}
}

func TestHistoryPersistence(t *testing.T) {
	dir := t.TempDir()
	c := newClock()
	tr := newTestTracker(c, dir)
	tr.Observe(nil, true)
	tr.Answer(phone, "site.example", []netip.Addr{webIP}, time.Minute)
	tr.Observe([]Flow{tcp(phone, 1, webIP, tcpEstablished, 4, 5000)}, true)
	tr.Close()

	// Перезапуск в том же часе: текущий час продолжается.
	tr2 := newTestTracker(c, dir)
	tr2.Observe(nil, true)
	tr2.Observe([]Flow{tcp(phone, 2, webIP, tcpEstablished, 4, 5000)}, true)
	if r := rowOf(t, tr2, "mac:aa", webIP.String()); r.OK != 1 {
		// Имя не сохраняется между запусками — второе соединение без имени.
		t.Errorf("после перезапуска: %+v", r)
	}
	if r := rowOf(t, tr2, "mac:aa", "site.example"); r.OK != 1 {
		t.Errorf("история прошлого запуска: %+v", r)
	}

	// Следующий час: прошлый записан отдельным файлом.
	c.add(time.Hour)
	tr2.Tick()
	if _, err := os.Stat(filepath.Join(dir, "hour-"+strconv.FormatInt(hourStart(c.t.Add(-time.Hour)).Unix(), 10)+".json.gz")); err != nil {
		t.Errorf("файл закрытого часа: %v", err)
	}
	tr2.Close()

	// Демон остановлен в прошлом часе и запущен позже: всё на месте.
	c.add(3 * time.Hour)
	tr3 := newTestTracker(c, dir)
	res := tr3.Query(Query{Since: 24 * time.Hour})
	if len(res.Rows) != 2 || res.Totals.OK != 2 {
		t.Errorf("история после перезапуска: %+v", res.Rows)
	}
	if d := res.Devices; len(d) != 1 || d[0].Name != "phone" {
		t.Errorf("имена устройств из истории: %+v", d)
	}

	// Через двое суток часы сливаются в сутки, через неделю — удаляются.
	c.add(49 * time.Hour)
	tr3.Tick()
	files, _ := filepath.Glob(filepath.Join(dir, "*.json.gz"))
	var days, hours int
	for _, f := range files {
		switch {
		case strings.HasPrefix(filepath.Base(f), "day-"):
			days++
		case strings.HasPrefix(filepath.Base(f), "hour-"):
			hours++
		}
	}
	if days != 1 || hours != 0 {
		t.Errorf("сжатие в сутки: суток %d, часов %d (%v)", days, hours, files)
	}
	if res := tr3.Query(Query{Since: 7 * 24 * time.Hour}); res.Totals.OK != 2 {
		t.Errorf("сутки в выборке: %+v", res.Totals)
	}
	if res := tr3.Query(Query{Since: time.Hour}); res.Totals.OK != 0 {
		t.Errorf("старое не попадает в выборку за час: %+v", res.Totals)
	}
	c.add(8 * 24 * time.Hour)
	tr3.Tick()
	if files, _ := filepath.Glob(filepath.Join(dir, "day-*")); len(files) != 0 {
		t.Errorf("история старше срока не удалена: %v", files)
	}
}

func TestGoneEvents(t *testing.T) {
	c := newClock()
	tr := newTestTracker(c, "")
	tr.Gone(tcp(phone, 1, webIP, tcpClose, 1, 40)) // до первого снимка — не учитывается
	tr.Observe(nil, true)
	tr.Answer(phone, "site.example", []netip.Addr{webIP}, time.Minute)
	tr.Answer(phone, "vpn.example", []netip.Addr{vpnIP}, time.Minute)

	// Соединения короче интервала опроса — только по событию удаления.
	rst := tcp(phone, 2, webIP, tcpClose, 1, 40)
	rst.OrigPkts, rst.OrigBytes = 1, 60
	tr.Gone(rst)                                         // RST в ответ на SYN — отказ
	tr.Gone(tcp(phone, 3, webIP, tcpClose, 3, 160))      // установлено, запрос, сброс без ответа
	tr.Gone(tcp(phone, 4, webIP, tcpTimeWait, 6, 30000)) // обычное короткое соединение
	pre := tcp(phone, 5, webIP, tcpTimeWait, 3, 160)     // открыто заранее и закрыто без запроса
	pre.OrigBytes = 180
	tr.Gone(pre)
	tr.Gone(tcp(phone, 6, vpnIP, tcpClose, 3, 160)) // через туннель без данных

	if r := rowOf(t, tr, "mac:aa", "site.example"); r.Refused != 2 || r.OK != 1 || r.Timeout != 0 || r.Bytes != 40+160+30000+160 {
		t.Errorf("короткие соединения: %+v", r)
	}
	if r := rowOf(t, tr, "mac:aa", "vpn.example"); r.NoData != 1 || r.Route != "tunnel" {
		t.Errorf("туннель без данных по событию: %+v", r)
	}

	// Соединение, замеченное опросом, завершается событием с итоговыми
	// счётчиками и не учитывается дважды.
	tr.Observe([]Flow{tcp(phone, 7, webIP, tcpEstablished, 2, 120)}, true)
	tr.Gone(tcp(phone, 7, webIP, tcpTimeWait, 9, 90000))
	tr.Observe(nil, true)
	if r := rowOf(t, tr, "mac:aa", "site.example"); r.OK != 2 || r.Bytes != 40+160+30000+160+90000 {
		t.Errorf("опрос + событие: %+v", r)
	}
}

func TestParseFlow(t *testing.T) {
	// Событие удаления от ядра: tcp 192.168.3.100:40000 → 203.0.113.10:443,
	// TIME_WAIT, счётчики 5/700 и 4/5000.
	attr := func(typ uint16, data []byte) []byte {
		l := 4 + len(data)
		b := []byte{byte(l), byte(l >> 8), byte(typ), byte(typ >> 8)}
		b = append(b, data...)
		for len(b)%4 != 0 {
			b = append(b, 0)
		}
		return b
	}
	nested := func(typ uint16, parts ...[]byte) []byte {
		var d []byte
		for _, p := range parts {
			d = append(d, p...)
		}
		return attr(typ|0x8000, d)
	}
	be16 := func(v uint16) []byte { return []byte{byte(v >> 8), byte(v)} }
	be64 := func(v uint64) []byte {
		b := make([]byte, 8)
		for i := range b {
			b[i] = byte(v >> (56 - 8*i))
		}
		return b
	}
	msg := []byte{2, 0, 0, 0} // nfgenmsg: AF_INET
	msg = append(msg, nested(ctaTupleOrig,
		nested(ctaTupleIP, attr(ctaIPv4Src, []byte{192, 168, 3, 100}), attr(ctaIPv4Dst, []byte{203, 0, 113, 10})),
		nested(ctaTupleProto, attr(ctaProtoNum, []byte{6}), attr(ctaProtoSrc, be16(40000)), attr(ctaProtoDst, be16(443))))...)
	msg = append(msg, nested(ctaTupleReply,
		nested(ctaTupleIP, attr(ctaIPv4Src, []byte{203, 0, 113, 10}), attr(ctaIPv4Dst, []byte{192, 168, 3, 100})))...)
	msg = append(msg, attr(3, []byte{0, 0, 0, 0xe})...)
	msg = append(msg, nested(ctaProtoinfo, nested(ctaProtoinfoTCP, attr(ctaProtoinfoTCPState, []byte{tcpTimeWait})))...)
	msg = append(msg, nested(ctaCountersOrig, attr(ctaCountersPackets, be64(5)), attr(ctaCountersBytes, be64(700)))...)
	msg = append(msg, nested(ctaCountersReply, attr(ctaCountersPackets, be64(4)), attr(ctaCountersBytes, be64(5000)))...)

	f, err := parseFlow(msg)
	if err != nil {
		t.Fatal(err)
	}
	want := Flow{Proto: ProtoTCP, Src: phone, Dst: webIP, SPort: 40000, DPort: 443, TCPState: tcpTimeWait,
		OrigPkts: 5, OrigBytes: 700, ReplyPkts: 4, ReplyBytes: 5000}
	if f != want {
		t.Errorf("разбор:\n%+v\nожидалось\n%+v", f, want)
	}
	if _, err := parseFlow([]byte{2, 0}); err == nil {
		t.Error("короткое сообщение принято")
	}
}
