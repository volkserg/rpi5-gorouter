// Package iplabels — чей это адрес: имена IP-адресов, к которым устройства
// обращаются без DNS. Проверка адреса запоминает имя сама (из сертификата,
// PTR или оператора), в веб-интерфейсе его можно поправить. Хранятся в
// JSON в каталоге состояния routerd.
package iplabels

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/volkserg/rpi5-gorouter/internal/fsutil"
)

// FileName — файл имён в каталоге состояния.
const FileName = "ip_labels.json"

const (
	// MaxLen — предел длины имени в символах.
	MaxLen = 60
	// MaxEntries — предел записей: при переполнении забываются самые старые
	// автоматические.
	MaxEntries = 4096
)

// Источники имени.
const (
	SourceUser = "user" // задано в веб-интерфейсе
	SourceCert = "cert" // сертификат сервера
	SourcePTR  = "ptr"  // обратная запись DNS
	SourceAS   = "as"   // оператор сети (автономная система)
)

// Label — имя адреса.
type Label struct {
	Name   string `json:"name"`
	Source string `json:"source"`
	At     int64  `json:"at"` // когда запомнено (Unix)
}

// Store — имена адресов.
type Store struct {
	path string
	now  func() time.Time
	mu   sync.Mutex
	m    map[netip.Addr]Label
}

// Open читает имена из dir; отсутствующий или испорченный файл — пустой
// набор (ошибка — для журнала). Пустой dir — только в памяти.
func Open(dir string) (*Store, error) {
	s := &Store{now: time.Now, m: map[netip.Addr]Label{}}
	if dir == "" {
		return s, nil
	}
	s.path = filepath.Join(dir, FileName)
	data, err := os.ReadFile(s.path)
	if errors.Is(err, fs.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return s, err
	}
	if err := json.Unmarshal(data, &s.m); err != nil {
		s.m = map[netip.Addr]Label{}
		return s, fmt.Errorf("%s: %w", s.path, err)
	}
	return s, nil
}

// Get — имя адреса.
func (s *Store) Get(ip netip.Addr) (Label, bool) {
	if s == nil {
		return Label{}, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	l, ok := s.m[ip]
	return l, ok
}

// Len — сколько адресов запомнено.
func (s *Store) Len() int {
	if s == nil {
		return 0
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.m)
}

// Auto запоминает имя из проверки адреса; заданное вручную не меняет.
func (s *Store) Auto(ip netip.Addr, name, source string) (Label, error) {
	name = strings.TrimSpace(name)
	if name == "" || source == SourceUser {
		return Label{}, errors.New("пустое имя")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if cur, ok := s.m[ip]; ok && cur.Source == SourceUser {
		return cur, nil
	}
	l := Label{Name: truncate(name), Source: source, At: s.now().Unix()}
	return l, s.update(func(m map[netip.Addr]Label) { m[ip] = l })
}

// Set задаёт имя вручную; пустое — забыть адрес.
func (s *Store) Set(ip netip.Addr, name string) error {
	if !ip.IsValid() {
		return errors.New("некорректный адрес")
	}
	name = strings.TrimSpace(name)
	if utf8.RuneCountInString(name) > MaxLen {
		return fmt.Errorf("имя длиннее %d символов", MaxLen)
	}
	if strings.IndexFunc(name, unicode.IsControl) >= 0 {
		return errors.New("имя с управляющими символами")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.update(func(m map[netip.Addr]Label) {
		if name == "" {
			delete(m, ip)
		} else {
			m[ip] = Label{Name: name, Source: SourceUser, At: s.now().Unix()}
		}
	})
}

// Reset забывает все адреса; n — сколько было.
func (s *Store) Reset() (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := len(s.m)
	return n, s.update(func(m map[netip.Addr]Label) { clear(m) })
}

// update меняет копию набора, записывает файл и только затем публикует.
func (s *Store) update(f func(map[netip.Addr]Label)) error {
	next := make(map[netip.Addr]Label, len(s.m)+1)
	for k, v := range s.m {
		next[k] = v
	}
	f(next)
	if len(next) > MaxEntries {
		evict(next, len(next)-MaxEntries)
	}
	if s.path != "" {
		data, err := json.MarshalIndent(next, "", "  ")
		if err != nil {
			return err
		}
		if err := os.MkdirAll(filepath.Dir(s.path), 0o755); err != nil {
			return err
		}
		if err := fsutil.WriteFile(s.path, append(data, '\n'), 0o644, -1); err != nil {
			return err
		}
	}
	s.m = next
	return nil
}

// evict убирает n самых старых автоматических записей.
func evict(m map[netip.Addr]Label, n int) {
	var auto []netip.Addr
	for ip, l := range m {
		if l.Source != SourceUser {
			auto = append(auto, ip)
		}
	}
	sort.Slice(auto, func(i, j int) bool { return m[auto[i]].At < m[auto[j]].At })
	for _, ip := range auto[:min(n, len(auto))] {
		delete(m, ip)
	}
}

func truncate(s string) string {
	if utf8.RuneCountInString(s) <= MaxLen {
		return s
	}
	return string([]rune(s)[:MaxLen])
}

// Guess — лучшее имя по результатам проверки: первое имя сертификата (без
// «*.»), иначе PTR, иначе оператор сети.
func Guess(certNames []string, certSubject, ptr, asName string) (name, source string) {
	for _, n := range append(append([]string(nil), certNames...), certSubject) {
		if n = strings.TrimPrefix(strings.ToLower(strings.TrimSpace(n)), "*."); strings.Contains(n, ".") {
			return n, SourceCert
		}
	}
	if ptr != "" {
		return ptr, SourcePTR
	}
	if asName != "" {
		return asName, SourceAS
	}
	return "", ""
}
