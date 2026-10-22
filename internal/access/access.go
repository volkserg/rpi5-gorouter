// Package access — учёт обращений устройств LAN: по записям conntrack
// определяет исход каждого соединения (успех, таймаут, отказ, «туннель без
// данных») и маршрут (напрямую или через туннель), по DNS-ответам routerd —
// имя ресурса, по арендам DHCP — устройство. Итоги копятся в почасовой
// истории на диске (history.go).
//
// Записи conntrack опрашиваются раз в несколько секунд (ранние решения:
// успех, таймаут SYN), а события удаления записей дают итог каждого
// соединения, в том числе короче интервала опроса (Gone).
package access

import (
	"log/slog"
	"net/netip"
	"sync"
	"time"
)

// Протоколы (номера IP).
const (
	ProtoTCP = 6
	ProtoUDP = 17
)

// Состояния TCP в conntrack (nf_conntrack_tcp.h).
const (
	tcpSynSent     = 1
	tcpSynRecv     = 2
	tcpEstablished = 3
	tcpFinWait     = 4
	tcpCloseWait   = 5
	tcpLastAck     = 6
	tcpTimeWait    = 7
	tcpClose       = 8
)

const (
	// tcpGiveUp — SYN без ответа дольше этого считается таймаутом (клиент
	// повторяет SYN ещё долго, но сервер уже явно не отвечает).
	tcpGiveUp = 15 * time.Second
	// udpGiveUp — UDP без единого ответа.
	udpGiveUp = 30 * time.Second
	// headerBytes — на пакет ответа без данных (IPv4 + TCP с опциями —
	// 52–60 байт): ответ больше этого в среднем — пришли данные.
	headerBytes = 80
)

// Route — маршрут соединения.
type Route uint8

const (
	Direct Route = iota
	Tunnel
)

func (r Route) String() string {
	if r == Tunnel {
		return "tunnel"
	}
	return "direct"
}

// Outcome — исход соединения.
type Outcome uint8

const (
	OK Outcome = iota
	// Timeout — ответа не было: напрямую ресурс недоступен.
	Timeout
	// Refused — отказ (RST в ответ на SYN) или сброс: соединение
	// установлено, устройство отправило данные, но ответа не было.
	Refused
	// NoData — соединение через туннель закрылось без единого байта
	// ответа: удалённая сторона туннеля не достучалась до ресурса.
	NoData
)

// Flow — запись conntrack в момент опроса (направление «оригинал» — от
// устройства).
type Flow struct {
	Proto      uint8
	Src, Dst   netip.Addr
	SPort      uint16
	DPort      uint16
	TCPState   uint8
	OrigPkts   uint64
	OrigBytes  uint64
	ReplyPkts  uint64
	ReplyBytes uint64
}

// Device — устройство LAN.
type Device struct {
	// Key — постоянный ключ: mac:…, local:<имя> или ip:<адрес>.
	Key  string `json:"key"`
	Name string `json:"name"`
	IP   string `json:"ip"`
	MAC  string `json:"mac,omitempty"`
}

// Options — откуда трекер берёт сведения о сети.
type Options struct {
	// Dir — каталог истории; пусто — история только в памяти.
	Dir string
	// Retention — сколько хранить историю.
	Retention time.Duration
	// Watch — учитывать ли соединение (от устройства LAN к внешнему адресу).
	Watch func(src, dst netip.Addr) bool
	// Device — устройство по адресу.
	Device func(netip.Addr) Device
	// Route — маршрут нового соединения.
	Route func(proto uint8, dst netip.Addr, dport uint16) Route
	// InList — ресурс (имя или адрес) сейчас в списке VPN; entry — запись
	// списка, которая его покрывает (домен, родительский домен, IP или
	// подсеть), пусто — если она неизвестна (адрес попал в туннель по DNS).
	InList func(name string, ip netip.Addr) (entry string, ok bool)
	Log    *slog.Logger
	Now    func() time.Time
}

type flowKey struct {
	proto        uint8
	src, dst     netip.Addr
	sport, dport uint16
}

type flowState struct {
	first   time.Time
	route   Route
	device  Device
	name    string
	est     bool
	decided bool
	last    Flow
	acct    bool
}

// Tracker — учёт обращений.
type Tracker struct {
	o     Options
	names *names
	hist  *history

	mu      sync.Mutex
	flows   map[flowKey]*flowState
	started bool
}

// New создаёт трекер и загружает историю из o.Dir.
func New(o Options) *Tracker {
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.Log == nil {
		o.Log = slog.New(slog.DiscardHandler)
	}
	if o.InList == nil {
		o.InList = func(string, netip.Addr) (string, bool) { return "", false }
	}
	t := &Tracker{o: o, names: newNames(), flows: map[flowKey]*flowState{}}
	t.hist = newHistory(o.Dir, o.Retention, o.Log)
	t.hist.load(o.Now())
	return t
}

// Answer запоминает DNS-ответ устройству: по нему соединения к адресам
// получают имя ресурса.
func (t *Tracker) Answer(client netip.Addr, name string, addrs []netip.Addr, ttl time.Duration) {
	t.names.add(client, name, addrs, ttl, t.o.Now())
}

// Observe принимает снимок таблицы conntrack. acct — ядро считает пакеты и
// байты (nf_conntrack_acct=1); без счётчиков UDP не учитывается, а «туннель
// без данных» не отличается от успеха.
func (t *Tracker) Observe(flows []Flow, acct bool) {
	now := t.o.Now()
	t.mu.Lock()
	defer t.mu.Unlock()

	// Первый снимок — соединения, начатые до запуска: их исход уже не
	// определить честно, они не учитываются.
	first := !t.started
	t.started = true

	seen := make(map[flowKey]bool, len(flows))
	for i := range flows {
		f := &flows[i]
		if (f.Proto != ProtoTCP && f.Proto != ProtoUDP) || !t.o.Watch(f.Src, f.Dst) {
			continue
		}
		k := keyOf(f)
		seen[k] = true
		st := t.flows[k]
		if st == nil {
			st = t.newState(f, now)
			st.decided = first
			t.flows[k] = st
		}
		t.update(st, f, acct)
		if !st.decided {
			t.decide(st, classify(st, f, now, acct), now)
		}
	}
	// Исчезнувшие без события удаления (событие потеряно) — итог по
	// последнему снимку.
	for k, st := range t.flows {
		if !seen[k] {
			t.finish(k, st, &st.last, now)
		}
	}
	t.names.prune(now)
}

// Gone — событие удаления записи conntrack с итоговыми счётчиками.
func (t *Tracker) Gone(f Flow) {
	if (f.Proto != ProtoTCP && f.Proto != ProtoUDP) || !t.o.Watch(f.Src, f.Dst) {
		return
	}
	now := t.o.Now()
	t.mu.Lock()
	defer t.mu.Unlock()
	if !t.started {
		return
	}
	k := keyOf(&f)
	st := t.flows[k]
	if st == nil {
		// Соединение короче интервала опроса.
		st = t.newState(&f, now)
	}
	t.update(st, &f, f.OrigPkts > 0)
	t.finish(k, st, &f, now)
}

func keyOf(f *Flow) flowKey { return flowKey{f.Proto, f.Src, f.Dst, f.SPort, f.DPort} }

func (t *Tracker) newState(f *Flow, now time.Time) *flowState {
	return &flowState{
		first:  now,
		route:  t.o.Route(f.Proto, f.Dst, f.DPort),
		device: t.o.Device(f.Src),
		name:   t.names.lookup(f.Src, f.Dst, now),
	}
}

func (t *Tracker) update(st *flowState, f *Flow, acct bool) {
	st.last, st.acct = *f, acct
	if f.Proto == ProtoTCP && (f.TCPState >= tcpEstablished && f.TCPState <= tcpTimeWait || acct && handshake(f)) {
		st.est = true
	}
}

// finish — итог соединения, которого больше нет в таблице, и его байты.
func (t *Tracker) finish(k flowKey, st *flowState, f *Flow, now time.Time) {
	if !st.decided {
		t.decide(st, final(st, f, st.acct), now)
	}
	if st.device.Key != "" && f.ReplyBytes > 0 {
		t.hist.addBytes(st.device, st.resource(k.dst), st.route, f.ReplyBytes, now)
	}
	delete(t.flows, k)
}

func (st *flowState) resource(dst netip.Addr) string {
	if st.name != "" {
		return st.name
	}
	return dst.String()
}

// verdict — решение по соединению.
type verdict struct {
	out Outcome
	// act: wait — исход ещё не ясен; count — учесть out; skip — не учитывать
	// (соединение открыто и закрыто без данных: например, браузер открыл его
	// заранее и не воспользовался).
	act uint8
}

const (
	wait uint8 = iota
	count
	skip
)

func (t *Tracker) decide(st *flowState, v verdict, now time.Time) {
	if v.act == wait {
		return
	}
	st.decided = true
	if v.act == count {
		f := &st.last
		t.hist.add(st.device, st.resource(f.Dst), f.Dst, f.DPort, f.Proto, st.route, v.out, now)
	}
}

// classify — исход соединения, которое ещё в таблице.
func classify(st *flowState, f *Flow, now time.Time, acct bool) verdict {
	age := now.Sub(st.first)
	switch f.Proto {
	case ProtoTCP:
		if !acct {
			// Без счётчиков — только по состоянию.
			switch {
			case st.est:
				return verdict{OK, count}
			case f.TCPState == tcpClose:
				return verdict{Refused, count}
			case f.TCPState == tcpSynSent && age >= tcpGiveUp:
				return verdict{Timeout, count}
			}
			return verdict{}
		}
		switch {
		case hasData(f):
			return verdict{OK, count}
		case f.TCPState >= tcpFinWait && f.TCPState <= tcpClose:
			return final(st, f, acct)
		case !st.est && f.TCPState == tcpSynSent && age >= tcpGiveUp:
			return verdict{Timeout, count}
		}
	case ProtoUDP:
		switch {
		case !acct:
		case f.ReplyPkts > 0:
			return verdict{OK, count}
		case age >= udpGiveUp:
			return verdict{Timeout, count}
		}
	}
	return verdict{}
}

// final — итог закрытого или исчезнувшего соединения (f — последние счётчики).
func final(st *flowState, f *Flow, acct bool) verdict {
	switch f.Proto {
	case ProtoTCP:
		switch {
		case !acct && st.est:
			return verdict{OK, count}
		case !acct && f.TCPState == tcpClose:
			return verdict{Refused, count}
		case !acct:
			return verdict{Timeout, count}
		case hasData(f):
			return verdict{OK, count}
		case st.est && !clientData(f):
			return verdict{act: skip}
		case st.est && st.route == Tunnel:
			// Устройство всегда соединяется с локальным GOST: данных нет —
			// удалённая сторона туннеля не достучалась до ресурса.
			return verdict{NoData, count}
		case st.est:
			return verdict{Refused, count}
		case f.ReplyPkts > 0:
			return verdict{Refused, count}
		default:
			return verdict{Timeout, count}
		}
	case ProtoUDP:
		switch {
		case !acct:
		case f.ReplyPkts > 0:
			return verdict{OK, count}
		default:
			return verdict{Timeout, count}
		}
	}
	return verdict{act: skip}
}

// hasData — в ответе были данные, а не только заголовки.
func hasData(f *Flow) bool { return f.ReplyBytes > f.ReplyPkts*headerBytes }

// clientData — устройство отправило данные (запрос), а не только рукопожатие.
func clientData(f *Flow) bool { return f.OrigBytes > f.OrigPkts*headerBytes }

// handshake — рукопожатие TCP состоялось (запись видна уже закрытой): с
// обеих сторон больше одного пакета. RST в ответ на SYN — по одному.
func handshake(f *Flow) bool {
	return f.TCPState != tcpSynSent && f.TCPState != tcpSynRecv && f.OrigPkts >= 2 && f.ReplyPkts >= 2
}

// SetRetention меняет срок хранения истории (перечитывание router.conf).
func (t *Tracker) SetRetention(d time.Duration) {
	t.hist.mu.Lock()
	defer t.hist.mu.Unlock()
	t.hist.retention = d
	t.o.Retention = d
}

// Close сохраняет историю (остановка демона).
func (t *Tracker) Close() { t.hist.flush(t.o.Now(), true) }

// Tick — раз в минуту: смена часа, сохранение текущего часа, чистка.
func (t *Tracker) Tick() { t.hist.flush(t.o.Now(), false) }

// --- имена ресурсов по DNS-ответам ----------------------------------------

const (
	// nameMinTTL — сколько помнить имя адреса: устройства держат адреса в
	// своих кэшах и соединяются с ними дольше TTL ответа.
	nameMinTTL = 6 * time.Hour
	// maxNames — предел записей «устройство × адрес».
	maxNames = 200_000
)

type nameEntry struct {
	name string
	exp  time.Time
}

type names struct {
	mu        sync.Mutex
	perClient map[netip.Addr]map[netip.Addr]nameEntry
	global    map[netip.Addr]nameEntry
	n         int
	lastPrune time.Time
}

func newNames() *names {
	return &names{perClient: map[netip.Addr]map[netip.Addr]nameEntry{}, global: map[netip.Addr]nameEntry{}}
}

func (n *names) add(client netip.Addr, name string, addrs []netip.Addr, ttl time.Duration, now time.Time) {
	e := nameEntry{name: name, exp: now.Add(max(ttl, nameMinTTL))}
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.n >= maxNames {
		n.pruneLocked(now, true)
	}
	m := n.perClient[client]
	if m == nil {
		m = map[netip.Addr]nameEntry{}
		n.perClient[client] = m
	}
	for _, a := range addrs {
		if _, ok := m[a]; !ok {
			n.n++
		}
		m[a] = e
		n.global[a] = e
	}
}

// lookup — имя, под которым устройство узнало адрес; если оно его не
// спрашивало (свой резолвер, старый кэш) — имя из ответа другому устройству.
func (n *names) lookup(client, dst netip.Addr, now time.Time) string {
	n.mu.Lock()
	defer n.mu.Unlock()
	if e, ok := n.perClient[client][dst]; ok && e.exp.After(now) {
		return e.name
	}
	if e, ok := n.global[dst]; ok && e.exp.After(now) {
		return e.name
	}
	return ""
}

func (n *names) prune(now time.Time) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if now.Sub(n.lastPrune) >= time.Minute {
		n.pruneLocked(now, false)
	}
}

// pruneLocked убирает истёкшие записи; full — при переполнении ещё и все
// записи устройств (останутся общие).
func (n *names) pruneLocked(now time.Time, full bool) {
	n.lastPrune = now
	for c, m := range n.perClient {
		for a, e := range m {
			if full || !e.exp.After(now) {
				delete(m, a)
				n.n--
			}
		}
		if len(m) == 0 {
			delete(n.perClient, c)
		}
	}
	for a, e := range n.global {
		if !e.exp.After(now) {
			delete(n.global, a)
		}
	}
}
