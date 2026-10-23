// Package sni — имя сайта из TLS ClientHello (расширение server_name):
// устройство, которое соединяется по IP без запроса к DNS routerd, почти
// всегда называет сайт в первом пакете TLS открытым текстом. Пакеты
// присылает ядро (правило nftables с log group, см. firewall.ApplySNILog);
// ClientHello больше одного сегмента TCP собирается (Assembler).
package sni

import (
	"encoding/binary"
	"errors"
	"net/netip"
	"strings"
	"sync"
	"time"
)

var (
	// ErrMore — ClientHello ещё не пришёл целиком.
	ErrMore = errors.New("нужны следующие сегменты")
	// ErrNotHello — данные не начало TLS ClientHello.
	ErrNotHello = errors.New("не TLS ClientHello")
	// ErrNoName — ClientHello без server_name (или с зашифрованным, ECH).
	ErrNoName = errors.New("нет server_name")
)

// maxHello — предел ClientHello (с постквантовым ключом — около 2 КБ).
const maxHello = 16 << 10

// IsHelloStart — данные начинаются с записи TLS handshake/ClientHello.
func IsHelloStart(b []byte) bool {
	return len(b) >= 6 && b[0] == 0x16 && b[1] == 0x03 && b[5] == 0x01
}

// Parse — имя из ClientHello в начале потока TLS b (одна или несколько
// записей handshake).
func Parse(b []byte) (string, error) {
	if !IsHelloStart(b) {
		if len(b) < 6 {
			return "", ErrMore
		}
		return "", ErrNotHello
	}
	// Сообщение handshake может занимать несколько записей TLS.
	var msg []byte
	for len(b) >= 5 {
		if b[0] != 0x16 {
			return "", ErrNotHello
		}
		n := int(binary.BigEndian.Uint16(b[3:5]))
		if len(b) < 5+n {
			msg = append(msg, b[5:]...)
			b = nil
			break
		}
		msg = append(msg, b[5:5+n]...)
		b = b[5+n:]
		if len(msg) >= 4 && len(msg) >= 4+int(uint32(msg[1])<<16|uint32(msg[2])<<8|uint32(msg[3])) {
			break
		}
	}
	if len(msg) < 4 {
		return "", ErrMore
	}
	n := int(uint32(msg[1])<<16 | uint32(msg[2])<<8 | uint32(msg[3]))
	if n > maxHello {
		return "", ErrNotHello
	}
	if len(msg) < 4+n {
		return "", ErrMore
	}
	return helloName(msg[4 : 4+n])
}

// helloName — server_name из тела ClientHello.
func helloName(h []byte) (string, error) {
	r := reader{b: h}
	r.skip(2 + 32)       // версия, random
	r.skip(int(r.u8()))  // session id
	r.skip(int(r.u16())) // cipher suites
	r.skip(int(r.u8()))  // compression
	ext := r.bytes(int(r.u16()))
	if r.bad {
		return "", ErrNotHello
	}
	er := reader{b: ext}
	for len(er.b) > 0 && !er.bad {
		typ, data := er.u16(), er.bytes(int(er.u16()))
		if typ != 0 { // server_name
			continue
		}
		dr := reader{b: data}
		list := reader{b: dr.bytes(int(dr.u16()))}
		for len(list.b) > 0 && !list.bad {
			kind, name := list.u8(), list.bytes(int(list.u16()))
			if kind == 0 && !list.bad {
				return clean(string(name))
			}
		}
	}
	return "", ErrNoName
}

// clean — имя хоста в нижнем регистре; IP-адрес и мусор — не имя.
func clean(s string) (string, error) {
	s = strings.TrimSuffix(strings.ToLower(s), ".")
	if s == "" || len(s) > 253 || !strings.Contains(s, ".") {
		return "", ErrNoName
	}
	if _, err := netip.ParseAddr(s); err == nil {
		return "", ErrNoName
	}
	for _, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '.' || c == '_') {
			return "", ErrNoName
		}
	}
	return s, nil
}

type reader struct {
	b   []byte
	bad bool
}

func (r *reader) bytes(n int) []byte {
	if r.bad || n > len(r.b) {
		r.bad = true
		r.b = nil
		return nil
	}
	out := r.b[:n]
	r.b = r.b[n:]
	return out
}

func (r *reader) skip(n int) { r.bytes(n) }

func (r *reader) u8() uint8 {
	if b := r.bytes(1); b != nil {
		return b[0]
	}
	return 0
}

func (r *reader) u16() uint16 {
	if b := r.bytes(2); b != nil {
		return binary.BigEndian.Uint16(b)
	}
	return 0
}

// Conn — соединение TCP (от устройства).
type Conn struct {
	Src, Dst     netip.Addr
	SPort, DPort uint16
}

// Segment — сегмент TCP с данными от устройства.
type Segment struct {
	Conn
	Seq     uint32
	Payload []byte
}

const (
	// maxPending — сколько недособранных ClientHello держать.
	maxPending = 1024
	// pendingTTL — сколько ждать следующего сегмента.
	pendingTTL = 5 * time.Second
)

type pending struct {
	next  uint32
	data  []byte
	start time.Time
}

// Assembler собирает ClientHello из сегментов TCP.
type Assembler struct {
	mu   sync.Mutex
	pend map[Conn]*pending
	now  func() time.Time
}

// NewAssembler — сборщик; now — часы (nil — time.Now).
func NewAssembler(now func() time.Time) *Assembler {
	if now == nil {
		now = time.Now
	}
	return &Assembler{pend: map[Conn]*pending{}, now: now}
}

// Add принимает сегмент; имя — когда ClientHello собран и в нём есть
// server_name. Сегменты не по порядку и повторы пропускаются: следующий
// нужный придёт повторной передачей или имя останется неизвестным.
func (a *Assembler) Add(s Segment) (string, bool) {
	if len(s.Payload) == 0 {
		return "", false
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	now := a.now()
	p := a.pend[s.Conn]
	switch {
	case p == nil && IsHelloStart(s.Payload):
		name, err := Parse(s.Payload)
		if err != ErrMore {
			return name, err == nil
		}
		if len(a.pend) >= maxPending {
			a.expire(now, true)
		}
		a.pend[s.Conn] = &pending{next: s.Seq + uint32(len(s.Payload)), data: append([]byte(nil), s.Payload...), start: now}
		return "", false
	case p == nil || s.Seq != p.next:
		return "", false
	}
	p.data = append(p.data, s.Payload...)
	p.next += uint32(len(s.Payload))
	name, err := Parse(p.data)
	if err == ErrMore && len(p.data) < maxHello+64 {
		return "", false
	}
	delete(a.pend, s.Conn)
	return name, err == nil
}

// Expire убирает недособранное дольше pendingTTL.
func (a *Assembler) Expire() {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.expire(a.now(), false)
}

func (a *Assembler) expire(now time.Time, all bool) {
	for k, p := range a.pend {
		if all || now.Sub(p.start) > pendingTTL {
			delete(a.pend, k)
		}
	}
}

// ParseIPv4TCP — сегмент из пакета IPv4 (как его присылает NFLOG).
func ParseIPv4TCP(pkt []byte) (Segment, bool) {
	var s Segment
	if len(pkt) < 20 || pkt[0]>>4 != 4 || pkt[9] != 6 {
		return s, false
	}
	ihl := int(pkt[0]&0x0f) * 4
	total := int(binary.BigEndian.Uint16(pkt[2:4]))
	if binary.BigEndian.Uint16(pkt[6:8])&0x1fff != 0 || ihl < 20 || len(pkt) < ihl+20 {
		return s, false // фрагмент или обрезанный заголовок
	}
	if total < len(pkt) && total >= ihl+20 {
		pkt = pkt[:total]
	}
	tcp := pkt[ihl:]
	off := int(tcp[12]>>4) * 4
	if off < 20 || len(tcp) < off {
		return s, false
	}
	s.Src = netip.AddrFrom4([4]byte(pkt[12:16]))
	s.Dst = netip.AddrFrom4([4]byte(pkt[16:20]))
	s.SPort = binary.BigEndian.Uint16(tcp[0:2])
	s.DPort = binary.BigEndian.Uint16(tcp[2:4])
	s.Seq = binary.BigEndian.Uint32(tcp[4:8])
	s.Payload = tcp[off:]
	return s, true
}
