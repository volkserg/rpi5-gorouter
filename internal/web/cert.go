package web

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"time"

	"github.com/volkserg/rpi5-gorouter/internal/fsutil"
)

const (
	certFile = "tls.crt"
	keyFile  = "tls.key"
	// certValidity — срок самоподписанного сертификата.
	certValidity = 10 * 365 * 24 * time.Hour
)

// ensureCert загружает самоподписанный сертификат из dir или выпускает
// новый: если его нет, он истекает в ближайший месяц или не содержит
// нужных адресов и имён (например, сменился RPI5_IP). Новый сертификат —
// снова предупреждение браузера, поэтому без нужды он не перевыпускается.
func ensureCert(dir string, ips []netip.Addr, names []string, now time.Time) (tls.Certificate, bool, error) {
	cp, kp := filepath.Join(dir, certFile), filepath.Join(dir, keyFile)
	if c, err := tls.LoadX509KeyPair(cp, kp); err == nil && certCovers(c.Leaf, ips, names, now) {
		return c, false, nil
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, false, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		return tls.Certificate{}, false, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "routerd", Organization: []string{"routerd"}},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(certValidity),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              names,
	}
	for _, a := range ips {
		tmpl.IPAddresses = append(tmpl.IPAddresses, net.IP(a.AsSlice()))
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, false, err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return tls.Certificate{}, false, err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return tls.Certificate{}, false, err
	}
	if err := fsutil.WriteFile(kp, keyPEM, 0o600, -1); err != nil {
		return tls.Certificate{}, false, err
	}
	if err := fsutil.WriteFile(cp, certPEM, 0o644, -1); err != nil {
		return tls.Certificate{}, false, err
	}
	c, err := tls.X509KeyPair(certPEM, keyPEM)
	return c, true, err
}

func certCovers(c *x509.Certificate, ips []netip.Addr, names []string, now time.Time) bool {
	if c == nil || now.Add(30*24*time.Hour).After(c.NotAfter) {
		return false
	}
	for _, a := range ips {
		if !slices.ContainsFunc(c.IPAddresses, func(ip net.IP) bool { return ip.Equal(net.IP(a.AsSlice())) }) {
			return false
		}
	}
	for _, n := range names {
		if !slices.Contains(c.DNSNames, n) {
			return false
		}
	}
	return true
}
