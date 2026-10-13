package dhcp

import (
	"encoding/json"
	"errors"
	"io/fs"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// DefaultStateDir — каталог состояния routerd (StateDirectory=routerd).
const DefaultStateDir = "/var/lib/routerd"

// LeaseFile — имя файла аренд в каталоге состояния.
const LeaseFile = "leases.json"

type leaseFile struct {
	Version int     `json:"version"`
	Leases  []Lease `json:"leases"`
}

// LoadLeases читает аренды; отсутствующий файл — пустой список.
func LoadLeases(path string) ([]Lease, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var f leaseFile
	if err := json.Unmarshal(data, &f); err != nil {
		return nil, err
	}
	return f.Leases, nil
}

// SaveLeases атомарно записывает аренды (временный файл → fsync → rename).
func SaveLeases(path string, leases []Lease) error {
	data, err := json.MarshalIndent(leaseFile{Version: 1, Leases: leases}, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(append(data, '\n')); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmp.Name(), 0o644); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

// Zone — локальная DNS-зона из аренд (имя.lan ↔ адрес), для DNS-прокси.
type Zone struct {
	pool   *Pool
	domain string
	now    func() time.Time
}

// NewZone — зона domain по арендам пула.
func NewZone(p *Pool, domain string) *Zone {
	return &Zone{pool: p, domain: strings.ToLower(strings.TrimSuffix(domain, ".")), now: time.Now}
}

// Domain — имя зоны (lan).
func (z *Zone) Domain() string { return z.domain }

// LookupName возвращает адрес действующей аренды с именем label.
func (z *Zone) LookupName(label string) (netip.Addr, bool) {
	z.pool.mu.Lock()
	defer z.pool.mu.Unlock()
	now := z.now()
	for _, l := range z.pool.byIP {
		if l.Name == label && l.State == StateBound && l.Expires.After(now) {
			return l.IP, true
		}
	}
	return netip.Addr{}, false
}

// LookupAddr возвращает имя (без зоны) действующей аренды адреса.
func (z *Zone) LookupAddr(a netip.Addr) (string, bool) {
	z.pool.mu.Lock()
	defer z.pool.mu.Unlock()
	if l := z.pool.byIP[a]; l != nil && l.Name != "" && l.State == StateBound && l.Expires.After(z.now()) {
		return l.Name, true
	}
	return "", false
}
