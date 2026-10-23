// Package probe — пробные соединения routerd: доступен ли ресурс напрямую
// и через туннель, какой внешний адрес у RPi и у выхода туннеля. Как
// соединение попадает в туннель, решает переданная функция Dial (демон
// помечает сокет — firewall.ProbeMark).
package probe

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// Dial — соединение TCP с адресом.
type Dial func(ctx context.Context, addr netip.AddrPort) (net.Conn, error)

// Timeout — предел одной проверки.
const Timeout = 6 * time.Second

// Path — итог проверки одним путём (напрямую или через туннель).
type Path struct {
	OK bool `json:"ok"`
	// Kind — вид неудачи: timeout, refused, reset, tls, http (сервер
	// ответил отказом в доступе: 403 или 451), other.
	Kind string `json:"kind,omitempty"`
	// Status — код ответа HTTP (0 — ответа не было).
	Status  int    `json:"status,omitempty"`
	Error   string `json:"error,omitempty"`
	Detail  string `json:"detail,omitempty"`
	Connect int64  `json:"connect_ms"`
	Total   int64  `json:"total_ms"`
	// Cert — сертификат сервера (порт 443; есть и при неудаче после
	// рукопожатия): на кого выписан — подсказка, чей это адрес.
	Cert *Cert `json:"cert,omitempty"`
}

// Cert — сведения из сертификата сервера.
type Cert struct {
	Subject string   `json:"subject,omitempty"` // CN
	Org     string   `json:"org,omitempty"`     // организация владельца (у OV/EV)
	Names   []string `json:"names,omitempty"`   // SAN
	Issuer  string   `json:"issuer,omitempty"`
}

// maxCertNames — сколько имён из SAN показывать.
const maxCertNames = 12

func certOf(c *x509.Certificate) *Cert {
	out := &Cert{Subject: c.Subject.CommonName, Issuer: c.Issuer.CommonName}
	if len(c.Subject.Organization) > 0 {
		out.Org = c.Subject.Organization[0]
	}
	if len(c.Issuer.Organization) > 0 {
		out.Issuer = c.Issuer.Organization[0]
	}
	for _, n := range c.DNSNames {
		if len(out.Names) == maxCertNames {
			break
		}
		out.Names = append(out.Names, strings.ToLower(n))
	}
	return out
}

// Resource проверяет ресурс: TCP-соединение с addr, для порта 443 —
// TLS-рукопожатие с SNI name (так видно и обрыв после начала TLS), затем
// запрос GET / и код ответа. 403 и 451 — неудача вида http: сервер
// доступен, но отказывает в доступе (часто — по адресу клиента).
func Resource(ctx context.Context, dial Dial, name string, addr netip.AddrPort) Path {
	ctx, cancel := context.WithTimeout(ctx, Timeout)
	defer cancel()
	start := time.Now()
	conn, err := dial(ctx, addr)
	if err != nil {
		return fail(err, "соединение", start)
	}
	defer conn.Close()
	p := Path{Connect: ms(time.Since(start))}
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	}
	host := name
	if host == "" {
		host = addr.Addr().String()
	}
	var tlsInfo string
	if addr.Port() == 443 {
		// Только HTTP/1.1: код ответа читается из первой строки.
		cfg := &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"http/1.1"}}
		if name != "" {
			cfg.ServerName = name
		}
		cfg.VerifyConnection = func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) > 0 {
				p.Cert = certOf(cs.PeerCertificates[0])
			}
			return nil
		}
		tc := tls.Client(conn, cfg)
		if err := tc.HandshakeContext(ctx); err != nil {
			r := fail(err, "TLS", start)
			r.Connect, r.Cert = p.Connect, p.Cert
			if r.Kind == "other" {
				r.Kind = "tls"
			}
			return r
		}
		tlsInfo = tls.VersionName(tc.ConnectionState().Version)
		conn = tc
	}
	if _, err := fmt.Fprintf(conn, "GET / HTTP/1.1\r\nHost: %s\r\nUser-Agent: %s\r\nAccept: */*\r\nConnection: close\r\n\r\n", host, userAgent); err != nil {
		r := fail(err, "запрос", start)
		r.Connect, r.Cert = p.Connect, p.Cert
		return r
	}
	line, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil && line == "" {
		r := fail(err, "ответ", start)
		r.Connect, r.Cert = p.Connect, p.Cert
		return r
	}
	p.Total = ms(time.Since(start))
	p.Status = statusCode(line)
	p.Detail = strings.TrimSpace(line)
	if p.Status > 0 {
		p.Detail = "HTTP " + strconv.Itoa(p.Status)
	}
	if tlsInfo != "" {
		p.Detail = tlsInfo + ", " + p.Detail
	}
	switch p.Status {
	case http.StatusForbidden, http.StatusUnavailableForLegalReasons:
		p.Kind = "http"
		p.Error = fmt.Sprintf("сервер отказал в доступе (HTTP %d)", p.Status)
		return p
	}
	p.OK = true
	return p
}

// userAgent — без него многие серверы отвечают 403 любому запросу.
const userAgent = "Mozilla/5.0 (compatible; routerd-check)"

// statusCode — код из строки статуса «HTTP/1.1 403 Forbidden», 0 — не HTTP.
func statusCode(line string) int {
	f := strings.Fields(line)
	if len(f) < 2 || !strings.HasPrefix(f[0], "HTTP/") {
		return 0
	}
	n, err := strconv.Atoi(f[1])
	if err != nil || n < 100 || n > 599 {
		return 0
	}
	return n
}

// ExitIP запрашивает url (ответ — адрес текстом, как у api.ipify.org) через
// dial и возвращает адрес и время ответа.
func ExitIP(ctx context.Context, dial Dial, url string) (ip string, p Path) {
	ctx, cancel := context.WithTimeout(ctx, Timeout+4*time.Second)
	defer cancel()
	start := time.Now()
	var connected time.Duration
	tr := &http.Transport{
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(address)
			if err != nil {
				return nil, err
			}
			ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip4", host)
			if err != nil || len(ips) == 0 {
				return nil, fmt.Errorf("адрес %s не найден: %w", host, err)
			}
			pn, _ := net.LookupPort("tcp", port)
			c, err := dial(ctx, netip.AddrPortFrom(ips[0].Unmap(), uint16(pn)))
			if err == nil {
				connected = time.Since(start)
			}
			return c, err
		},
		DisableKeepAlives: true,
	}
	defer tr.CloseIdleConnections()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", Path{Kind: "other", Error: err.Error()}
	}
	req.Header.Set("User-Agent", userAgent)
	resp, err := (&http.Client{Transport: tr}).Do(req)
	if err != nil {
		r := fail(err, "запрос", start)
		r.Connect = ms(connected)
		return "", r
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 256))
	p = Path{Connect: ms(connected), Total: ms(time.Since(start)), Detail: resp.Status}
	a, err := netip.ParseAddr(strings.TrimSpace(string(body)))
	if resp.StatusCode != http.StatusOK || err != nil {
		p.Kind, p.Error = "other", "ответ не адрес: "+resp.Status
		return "", p
	}
	p.OK = true
	return a.String(), p
}

func ms(d time.Duration) int64 { return d.Milliseconds() }

// fail — неудача с понятным текстом и видом.
func fail(err error, stage string, start time.Time) Path {
	p := Path{Total: ms(time.Since(start)), Kind: "other"}
	var ne net.Error
	switch {
	case errors.Is(err, context.DeadlineExceeded) || errors.As(err, &ne) && ne.Timeout():
		p.Kind, p.Error = "timeout", stage+": нет ответа (таймаут)"
	case errors.Is(err, syscall.ECONNREFUSED):
		p.Kind, p.Error = "refused", stage+": отказ (порт закрыт)"
	case errors.Is(err, syscall.ECONNRESET) || errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF):
		p.Kind, p.Error = "reset", stage+": соединение сброшено"
	case errors.Is(err, syscall.EHOSTUNREACH) || errors.Is(err, syscall.ENETUNREACH):
		p.Kind, p.Error = "other", stage+": адрес недоступен"
	default:
		p.Error = stage + ": " + err.Error()
	}
	return p
}
