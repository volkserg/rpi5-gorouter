// Package devnames — имена устройств, заданные в веб-интерфейсе: ключ
// устройства (mac:…, ip:…, local:…) → имя. Хранятся в JSON в каталоге
// состояния routerd и показываются вместо имени из аренды DHCP.
package devnames

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"unicode"
	"unicode/utf8"

	"github.com/volkserg/rpi5-gorouter/internal/fsutil"
)

// FileName — файл имён в каталоге состояния.
const FileName = "device_names.json"

// MaxLen — предел длины имени в символах.
const MaxLen = 40

// Store — имена устройств.
type Store struct {
	path string
	mu   sync.Mutex
	m    map[string]string
}

// Open читает имена из dir; отсутствующий или испорченный файл — пустой
// набор (ошибка — для журнала).
func Open(dir string) (*Store, error) {
	s := &Store{path: filepath.Join(dir, FileName), m: map[string]string{}}
	data, err := os.ReadFile(s.path)
	if errors.Is(err, fs.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return s, err
	}
	if err := json.Unmarshal(data, &s.m); err != nil {
		s.m = map[string]string{}
		return s, fmt.Errorf("%s: %w", s.path, err)
	}
	return s, nil
}

// Get — имя устройства, пусто — не задано.
func (s *Store) Get(key string) string {
	if s == nil {
		return ""
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.m[key]
}

// Set задаёт имя; пустое — сбросить к имени из аренды.
func (s *Store) Set(key, name string) error {
	name = strings.TrimSpace(name)
	if key == "" || len(key) > 64 {
		return errors.New("некорректный ключ устройства")
	}
	if utf8.RuneCountInString(name) > MaxLen {
		return fmt.Errorf("имя длиннее %d символов", MaxLen)
	}
	if strings.IndexFunc(name, unicode.IsControl) >= 0 {
		return errors.New("имя с управляющими символами")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	next := make(map[string]string, len(s.m)+1)
	for k, v := range s.m {
		next[k] = v
	}
	if name == "" {
		delete(next, key)
	} else {
		next[key] = name
	}
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
	s.m = next
	return nil
}
