package probe

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strings"
	"syscall"
	"testing"
	"time"
)

// pipeDial — «сервер» в памяти: serve получает серверную сторону соединения.
func pipeDial(serve func(net.Conn)) Dial {
	return func(context.Context, netip.AddrPort) (net.Conn, error) {
		c, s := net.Pipe()
		go func() { defer s.Close(); serve(s) }()
		return c, nil
	}
}

var site = netip.MustParseAddrPort("203.0.113.10:80")

func TestResourceHTTP(t *testing.T) {
	p := Resource(context.Background(), pipeDial(func(s net.Conn) {
		buf := make([]byte, 512)
		n, _ := s.Read(buf)
		if !strings.HasPrefix(string(buf[:n]), "GET / HTTP/1.1\r\nHost: site.example\r\n") {
			t.Errorf("запрос: %q", buf[:n])
		}
		s.Write([]byte("HTTP/1.1 200 OK\r\n\r\n"))
	}), "site.example", site)
	if !p.OK || p.Status != 200 || p.Detail != "HTTP 200" {
		t.Errorf("HTTP: %+v", p)
	}
}

func TestResourceHTTPStatus(t *testing.T) {
	answer := func(line string) Dial {
		return pipeDial(func(s net.Conn) {
			buf := make([]byte, 512)
			s.Read(buf)
			s.Write([]byte(line + "\r\nContent-Length: 0\r\n\r\n"))
		})
	}
	for line, want := range map[string]struct {
		ok     bool
		kind   string
		status int
	}{
		"HTTP/1.1 403 Forbidden":                     {false, "http", 403},
		"HTTP/1.1 451 Unavailable For Legal Reasons": {false, "http", 451},
		"HTTP/1.1 301 Moved Permanently":             {true, "", 301},
		"HTTP/1.1 503 Service Unavailable":           {true, "", 503},
		"SSH-2.0-OpenSSH_9.6":                        {true, "", 0},
	} {
		p := Resource(context.Background(), answer(line), "site.example", site)
		if p.OK != want.ok || p.Kind != want.kind || p.Status != want.status {
			t.Errorf("%s: %+v", line, p)
		}
	}
}

func TestResourceFailures(t *testing.T) {
	refused := func(context.Context, netip.AddrPort) (net.Conn, error) {
		return nil, &net.OpError{Op: "dial", Err: syscall.ECONNREFUSED}
	}
	if p := Resource(context.Background(), refused, "", site); p.OK || p.Kind != "refused" {
		t.Errorf("отказ: %+v", p)
	}
	timeout := func(ctx context.Context, _ netip.AddrPort) (net.Conn, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if p := Resource(ctx, timeout, "", site); p.OK || p.Kind != "timeout" {
		t.Errorf("таймаут: %+v", p)
	}
	// Соединение есть, но после ClientHello его закрывают — обрыв TLS.
	reset := pipeDial(func(s net.Conn) {
		buf := make([]byte, 4096)
		s.Read(buf)
	})
	if p := Resource(context.Background(), reset, "blocked.example", netip.MustParseAddrPort("203.0.113.10:443")); p.OK || p.Kind != "reset" || !strings.HasPrefix(p.Error, "TLS") {
		t.Errorf("обрыв TLS: %+v", p)
	}
	other := func(context.Context, netip.AddrPort) (net.Conn, error) { return nil, errors.New("что-то") }
	if p := Resource(context.Background(), other, "", site); p.OK || p.Kind != "other" || p.Error != "соединение: что-то" {
		t.Errorf("прочее: %+v", p)
	}
}
