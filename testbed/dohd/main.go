// Command dohd — DNS-over-HTTPS сервер стенда (RFC 8484): принимает запросы
// dnscrypt-proxy и пересылает их обычным DNS в авторитетный сервер тестовых
// зон. Только для стенда, в routerd не входит.
//
//	dohd -listen 203.0.113.55:443 -cert doh.crt -key doh.key -upstream 203.0.113.54:53
//	dohd -stamp -ca ca.crt -addr 203.0.113.55 -host doh.test   # печатает sdns:// для dnscrypt-proxy
package main

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/miekg/dns"
)

func main() {
	var (
		listen   = flag.String("listen", ":443", "адрес HTTPS")
		cert     = flag.String("cert", "", "сертификат сервера (PEM)")
		key      = flag.String("key", "", "ключ сервера (PEM)")
		upstream = flag.String("upstream", "127.0.0.1:53", "DNS, куда пересылать запросы")
		stamp    = flag.Bool("stamp", false, "напечатать DNS stamp и выйти")
		ca       = flag.String("ca", "", "для -stamp: сертификат, хэш которого закрепить (PEM)")
		addr     = flag.String("addr", "", "для -stamp: IP-адрес сервера")
		host     = flag.String("host", "", "для -stamp: имя сервера (SNI)")
	)
	flag.Parse()

	if *stamp {
		s, err := dohStamp(*ca, *addr, *host, "/dns-query")
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println(s)
		return
	}

	c := &dns.Client{Net: "udp", Timeout: 3 * time.Second}
	http.HandleFunc("/dns-query", func(w http.ResponseWriter, r *http.Request) {
		var wire []byte
		var err error
		switch r.Method {
		case http.MethodPost:
			wire, err = io.ReadAll(io.LimitReader(r.Body, 65535))
		case http.MethodGet:
			wire, err = base64.RawURLEncoding.DecodeString(r.URL.Query().Get("dns"))
		default:
			http.Error(w, "method", http.StatusMethodNotAllowed)
			return
		}
		req := new(dns.Msg)
		if err == nil {
			err = req.Unpack(wire)
		}
		if err != nil || len(req.Question) == 0 {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		q := req.Question[0]
		log.Printf("doh query %s %s from %s", q.Name, dns.TypeToString[q.Qtype], r.RemoteAddr)
		resp, _, err := c.Exchange(req, *upstream)
		if err != nil {
			http.Error(w, "upstream", http.StatusBadGateway)
			return
		}
		out, err := resp.Pack()
		if err != nil {
			http.Error(w, "pack", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/dns-message")
		_, _ = w.Write(out)
	})
	log.Printf("dohd: https://%s/dns-query → %s", *listen, *upstream)
	log.Fatal(http.ListenAndServeTLS(*listen, *cert, *key, nil))
}

// dohStamp строит sdns:// для DoH-сервера (формат DNS Stamps): свойства
// DNSSEC|NoLog|NoFilter, адрес, SHA-256 TBS закреплённого сертификата, имя, путь.
func dohStamp(caPath, addr, host, path string) (string, error) {
	if caPath == "" || addr == "" || host == "" {
		return "", errors.New("нужны -ca, -addr и -host")
	}
	pemData, err := os.ReadFile(caPath)
	if err != nil {
		return "", err
	}
	block, _ := pem.Decode(pemData)
	if block == nil {
		return "", errors.New("в -ca нет PEM-сертификата")
	}
	crt, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return "", err
	}
	hash := sha256.Sum256(crt.RawTBSCertificate)

	b := []byte{0x02}                     // протокол: DoH
	b = append(b, 7, 0, 0, 0, 0, 0, 0, 0) // DNSSEC | NoLog | NoFilter
	b = appendLP(b, addr)                 // адрес (порт 443 по умолчанию)
	b = append(b, byte(len(hash)))        // хэши: один элемент
	b = append(b, hash[:]...)
	b = appendLP(b, host)
	b = appendLP(b, path)
	return "sdns://" + base64.RawURLEncoding.EncodeToString(b), nil
}

func appendLP(b []byte, s string) []byte {
	return append(append(b, byte(len(s))), s...)
}
