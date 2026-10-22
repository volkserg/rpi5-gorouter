//go:build linux

package firewall

import (
	"log/slog"
	"net/netip"
	"sync"
	"time"

	"github.com/google/nftables"
)

// maxElementTimeout — верхняя граница срока жизни адреса в vpn_dynamic
// (защита от аномально больших TTL).
const maxElementTimeout = 7 * 24 * time.Hour

// Dynamic добавляет в vpn_dynamic адреса из DNS-ответов со сроком жизни
// max(TTL, floor) и продлевает его при повторных ответах.
type Dynamic struct {
	mu      sync.Mutex
	conn    *nftables.Conn
	floor   time.Duration
	expires map[netip.Addr]time.Time
	log     *slog.Logger
	now     func() time.Time
}

// NewDynamic создаёт обновлятель со своим netlink-соединением: DNS-запросы
// обрабатываются параллельно с перезагрузкой правил.
func NewDynamic(floor time.Duration, log *slog.Logger) (*Dynamic, error) {
	c, err := nftables.New()
	if err != nil {
		return nil, err
	}
	return newDynamic(c, floor, log), nil
}

func newDynamic(c *nftables.Conn, floor time.Duration, log *slog.Logger) *Dynamic {
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	return &Dynamic{conn: c, floor: floor, expires: map[netip.Addr]time.Time{}, log: log, now: time.Now}
}

// SetFloor задаёт минимальный срок жизни (VPN_DYNAMIC_TIMEOUT).
func (d *Dynamic) SetFloor(floor time.Duration) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.floor = floor
}

// Reset забывает известные адреса — после пересоздания таблицы set пуст.
func (d *Dynamic) Reset() {
	d.mu.Lock()
	defer d.mu.Unlock()
	clear(d.expires)
}

// Learn добавляет адреса. Адрес, срок которого истекает не скоро
// (позже половины нового срока), не трогается — лишних транзакций нет.
func (d *Dynamic) Learn(addrs []netip.Addr, ttl time.Duration) {
	d.mu.Lock()
	defer d.mu.Unlock()

	timeout := max(ttl, d.floor)
	timeout = min(timeout, maxElementTimeout)
	timeout = timeout.Truncate(time.Second)
	now := d.now()

	var els []nftables.SetElement
	for _, a := range addrs {
		if !a.Is4() {
			continue
		}
		if exp, ok := d.expires[a]; ok && exp.After(now.Add(timeout/2)) {
			continue
		}
		els = append(els, nftables.SetElement{Key: a.AsSlice(), Timeout: timeout})
	}
	if len(els) == 0 {
		return
	}

	set := &nftables.Set{Table: table(), Name: SetDynamic, KeyType: nftables.TypeIPAddr, HasTimeout: true}
	// Продление срока одной транзакцией: добавить (если адреса нет — чтобы
	// удаление не упало), удалить, добавить с новым сроком. Обновление
	// таймаута существующего элемента умеют не все ядра.
	_ = d.conn.SetAddElements(set, els)
	_ = d.conn.SetDeleteElements(set, els)
	_ = d.conn.SetAddElements(set, els)
	if err := d.conn.Flush(); err != nil {
		d.log.Warn("не удалось добавить адреса в vpn_dynamic", "ошибка", err)
		return
	}
	for _, el := range els {
		a, _ := netip.AddrFromSlice(el.Key)
		d.expires[a] = now.Add(timeout)
	}
	d.prune(now)
}

// Has — адрес сейчас в vpn_dynamic (по сроку, выставленному routerd).
func (d *Dynamic) Has(a netip.Addr) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	exp, ok := d.expires[a]
	return ok && exp.After(d.now())
}

// Forget убирает адреса из vpn_dynamic (домен удалён из списка).
func (d *Dynamic) Forget(addrs []netip.Addr) {
	d.mu.Lock()
	defer d.mu.Unlock()

	var els []nftables.SetElement
	for _, a := range addrs {
		if a.Is4() {
			els = append(els, nftables.SetElement{Key: a.AsSlice(), Timeout: time.Second})
		}
	}
	if len(els) == 0 {
		return
	}
	set := &nftables.Set{Table: table(), Name: SetDynamic, KeyType: nftables.TypeIPAddr, HasTimeout: true}
	// Добавить и удалить одной транзакцией: удаление отсутствующего адреса
	// (истёк сам) иначе отменило бы всю транзакцию.
	_ = d.conn.SetAddElements(set, els)
	_ = d.conn.SetDeleteElements(set, els)
	if err := d.conn.Flush(); err != nil {
		d.log.Warn("не удалось убрать адреса из vpn_dynamic", "ошибка", err)
		return
	}
	for _, a := range addrs {
		delete(d.expires, a)
	}
}

// prune убирает из памяти давно истёкшие адреса (ядро удалило их само).
func (d *Dynamic) prune(now time.Time) {
	if len(d.expires) < 1024 {
		return
	}
	for a, exp := range d.expires {
		if exp.Before(now) {
			delete(d.expires, a)
		}
	}
}
