package sni

import (
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"
)

// recConn записывает то, что клиент TLS отправил, и обрывает чтение.
type recConn struct {
	net.Conn
	buf bytes.Buffer
}

func (c *recConn) Write(b []byte) (int, error)      { return c.buf.Write(b) }
func (c *recConn) Read([]byte) (int, error)         { return 0, errors.New("конец") }
func (c *recConn) Close() error                     { return nil }
func (c *recConn) SetDeadline(time.Time) error      { return nil }
func (c *recConn) SetReadDeadline(time.Time) error  { return nil }
func (c *recConn) SetWriteDeadline(time.Time) error { return nil }

// hello — настоящий ClientHello crypto/tls (с ключом X25519MLKEM768 — больше
// одного сегмента TCP).
func hello(t *testing.T, name string) []byte {
	t.Helper()
	c := &recConn{}
	_ = tls.Client(c, &tls.Config{ServerName: name, InsecureSkipVerify: true}).Handshake()
	if c.buf.Len() == 0 {
		t.Fatal("ClientHello не записан")
	}
	return c.buf.Bytes()
}

func TestParse(t *testing.T) {
	h := hello(t, "Files.Example.COM")
	if got, err := Parse(h); err != nil || got != "files.example.com" {
		t.Fatalf("Parse = %q, %v", got, err)
	}
	if _, err := Parse(h[:len(h)-10]); err != ErrMore {
		t.Fatalf("неполный ClientHello: %v", err)
	}
	if _, err := Parse([]byte("GET / HTTP/1.1\r\n")); err != ErrNotHello {
		t.Fatalf("HTTP: %v", err)
	}
	// По IP crypto/tls server_name не отправляет.
	if _, err := Parse(hello(t, "203.0.113.10")); err != ErrNoName {
		t.Fatalf("без имени: %v", err)
	}
}

func TestAssembler(t *testing.T) {
	h := hello(t, "api.example.net")
	if len(h) < 1400 {
		t.Logf("ClientHello %d байт — помещается в сегмент", len(h))
	}
	c := Conn{Src: netip.MustParseAddr("192.168.3.100"), Dst: netip.MustParseAddr("203.0.113.10"), SPort: 50000, DPort: 443}
	a := NewAssembler(nil)
	const isn = 1000
	parts := [][]byte{h[:600], h[600:1200], h[1200:]}
	seq := uint32(isn)
	var seqs []uint32
	for _, p := range parts {
		seqs = append(seqs, seq)
		seq += uint32(len(p))
	}
	if _, ok := a.Add(Segment{Conn: c, Seq: seqs[0], Payload: parts[0]}); ok {
		t.Fatal("имя по первому сегменту")
	}
	// Не по порядку — пропускается, затем приходит нужный.
	if _, ok := a.Add(Segment{Conn: c, Seq: seqs[2], Payload: parts[2]}); ok {
		t.Fatal("сегмент не по порядку принят")
	}
	a.Add(Segment{Conn: c, Seq: seqs[1], Payload: parts[1]})
	name, ok := a.Add(Segment{Conn: c, Seq: seqs[2], Payload: parts[2]})
	if !ok || name != "api.example.net" {
		t.Fatalf("сборка: %q %v", name, ok)
	}
	if len(a.pend) != 0 {
		t.Fatalf("недособранное осталось: %d", len(a.pend))
	}
	// Не TLS — не запоминается.
	if _, ok := a.Add(Segment{Conn: c, Seq: 1, Payload: []byte("SSH-2.0-OpenSSH")}); ok || len(a.pend) != 0 {
		t.Fatal("не TLS")
	}
}

func TestParseIPv4TCP(t *testing.T) {
	payload := []byte("hello")
	pkt := make([]byte, 20+20+len(payload))
	pkt[0] = 0x45
	binary.BigEndian.PutUint16(pkt[2:4], uint16(len(pkt)))
	pkt[9] = 6
	copy(pkt[12:16], []byte{192, 168, 3, 100})
	copy(pkt[16:20], []byte{203, 0, 113, 10})
	binary.BigEndian.PutUint16(pkt[20:22], 50000)
	binary.BigEndian.PutUint16(pkt[22:24], 443)
	binary.BigEndian.PutUint32(pkt[24:28], 77)
	pkt[32] = 5 << 4
	copy(pkt[40:], payload)
	s, ok := ParseIPv4TCP(pkt)
	if !ok || s.Src.String() != "192.168.3.100" || s.Dst.String() != "203.0.113.10" || s.DPort != 443 || s.Seq != 77 || string(s.Payload) != "hello" {
		t.Fatalf("ParseIPv4TCP = %+v, %v", s, ok)
	}
	if _, ok := ParseIPv4TCP(pkt[:30]); ok {
		t.Fatal("обрезанный пакет принят")
	}
}
