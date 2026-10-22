package web

import (
	"sync"
	"time"
)

const (
	// limitFree — сколько неудачных попыток входа подряд прощается.
	limitFree = 5
	// limitBase, limitMax — пауза после limitFree неудач: удваивается с
	// каждой следующей неудачей, но не больше limitMax.
	limitBase = time.Minute
	limitMax  = 15 * time.Minute
	// limitForget — через сколько без попыток счётчик сбрасывается.
	limitForget = time.Hour
)

// loginLimiter ограничивает подбор пароля: неудачи считаются по адресу
// клиента; после limitFree неудач вход с этого адреса блокируется на время.
type loginLimiter struct {
	mu sync.Mutex
	m  map[string]*attempts
}

type attempts struct {
	fails int
	last  time.Time
	until time.Time
}

func newLoginLimiter() *loginLimiter { return &loginLimiter{m: map[string]*attempts{}} }

// blocked — сколько ещё ждать адресу ip (0 — можно пробовать).
func (l *loginLimiter) blocked(ip string, now time.Time) time.Duration {
	l.mu.Lock()
	defer l.mu.Unlock()
	if a := l.m[ip]; a != nil && now.Before(a.until) {
		return a.until.Sub(now)
	}
	return 0
}

// fail отмечает неудачную попытку.
func (l *loginLimiter) fail(ip string, now time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.gc(now)
	a := l.m[ip]
	if a == nil {
		a = &attempts{}
		l.m[ip] = a
	}
	a.fails++
	a.last = now
	if n := a.fails - limitFree; n > 0 {
		d := limitBase << min(n-1, 4)
		a.until = now.Add(min(d, limitMax))
	}
}

// ok сбрасывает счётчик после успешного входа.
func (l *loginLimiter) ok(ip string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.m, ip)
}

// gc убирает давно не пытавшиеся адреса — таблица не растёт без предела.
func (l *loginLimiter) gc(now time.Time) {
	for ip, a := range l.m {
		if now.Sub(a.last) > limitForget && now.After(a.until) {
			delete(l.m, ip)
		}
	}
}
