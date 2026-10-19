package dnsproxy

import (
	"net/netip"
	"sync"
	"time"

	"github.com/volkserg/rpi5-gorouter/internal/domain"
)

// defaultRecentMax — сколько имён помнит кэш недавних ответов (~200 байт на
// имя). Записи живут не дольше TTL ответа, поэтому в домашней сети потолок
// почти не достигается; он лишь ограничивает рост.
const defaultRecentMax = 20000

// recent — недавние ответы на A-запросы (любые домены, не только из
// списка): имя → адреса до истечения TTL. Нужен, чтобы изменение списка
// работало сразу: клиент держит адрес в своём DNS-кэше и повторно не
// спросит, а routerd по кэшу добавит (или уберёт) адреса в vpn_dynamic сам.
type recent struct {
	mu  sync.Mutex
	max int
	seq uint64
	m   map[string]recentEntry
	now func() time.Time
}

type recentEntry struct {
	addrs   []netip.Addr
	expires time.Time
	seq     uint64 // порядок записи — для вытеснения самой старой
}

func newRecent(max int) *recent {
	return &recent{max: max, m: map[string]recentEntry{}, now: time.Now}
}

// add запоминает ответ; имя — нормализованное.
func (r *recent) add(name string, addrs []netip.Addr, ttl time.Duration) {
	if len(addrs) == 0 || ttl <= 0 {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	now := r.now()
	if _, ok := r.m[name]; !ok && len(r.m) >= r.max {
		r.evict(now)
	}
	r.seq++
	r.m[name] = recentEntry{addrs: addrs, expires: now.Add(ttl), seq: r.seq}
}

// evict освобождает место: сначала истёкшие записи, затем самая старая.
func (r *recent) evict(now time.Time) {
	for n, e := range r.m {
		if !e.expires.After(now) {
			delete(r.m, n)
		}
	}
	if len(r.m) < r.max {
		return
	}
	oldest, seq := "", uint64(0)
	for n, e := range r.m {
		if oldest == "" || e.seq < seq {
			oldest, seq = n, e.seq
		}
	}
	delete(r.m, oldest)
}

// diff сверяет кэш со сменой списка old → cur: адреса имён, которые только
// что попали в список (learn, с оставшимся TTL), и адреса имён, которые из
// него ушли (forget). Адрес, который нужен и имени, оставшемуся в списке
// (общий CDN), не забывается.
func (r *recent) diff(old, cur *domain.Matcher[struct{}]) (learn []recentEntry, forget []netip.Addr) {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := r.now()
	keep := map[netip.Addr]bool{}
	var gone []netip.Addr
	for n, e := range r.m {
		if !e.expires.After(now) {
			delete(r.m, n)
			continue
		}
		_, _, inOld := old.Lookup(n)
		_, _, inCur := cur.Lookup(n)
		switch {
		case inCur:
			for _, a := range e.addrs {
				keep[a] = true
			}
			if !inOld {
				learn = append(learn, recentEntry{addrs: e.addrs, expires: e.expires})
			}
		case inOld:
			gone = append(gone, e.addrs...)
		}
	}
	seen := map[netip.Addr]bool{}
	for _, a := range gone {
		if !keep[a] && !seen[a] {
			seen[a] = true
			forget = append(forget, a)
		}
	}
	return learn, forget
}

// matching — все записи, подходящие под список (после пересоздания таблицы
// nftables vpn_dynamic пуст, и выученное восстанавливается из кэша).
func (r *recent) matching(cur *domain.Matcher[struct{}]) []recentEntry {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := r.now()
	var out []recentEntry
	for n, e := range r.m {
		if !e.expires.After(now) {
			continue
		}
		if _, _, ok := cur.Lookup(n); ok {
			out = append(out, e)
		}
	}
	return out
}
