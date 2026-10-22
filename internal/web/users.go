package web

import (
	"bufio"
	"bytes"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/user"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/volkserg/rpi5-gorouter/internal/api"
	"github.com/volkserg/rpi5-gorouter/internal/fsutil"
)

// UsersFileName — файл пользователей веб-интерфейса в каталоге конфигов:
// строки «логин:хеш». Владелец root, группа routerd-web, права 0640.
const UsersFileName = "web_users"

// pbkdf2Iter — число итераций PBKDF2-SHA256 (рекомендация OWASP); на RPi 5
// проверка пароля занимает доли секунды.
const pbkdf2Iter = 600_000

// MinPasswordLen — минимальная длина пароля.
const MinPasswordLen = 8

var loginRe = regexp.MustCompile(`^[A-Za-z0-9._@-]{1,64}$`)

// ValidLogin проверяет логин: латиница, цифры и . _ @ -, до 64 символов.
func ValidLogin(name string) error {
	if !loginRe.MatchString(name) {
		return errors.New("логин: латиница, цифры и . _ @ -, до 64 символов")
	}
	return nil
}

var b64 = base64.RawURLEncoding

// HashPassword — «pbkdf2-sha256$итерации$соль$хеш».
func HashPassword(password string) (string, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	dk, err := pbkdf2.Key(sha256.New, password, salt, pbkdf2Iter, 32)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("pbkdf2-sha256$%d$%s$%s", pbkdf2Iter, b64.EncodeToString(salt), b64.EncodeToString(dk)), nil
}

// VerifyPassword сверяет пароль с хешем за постоянное время.
func VerifyPassword(password, stored string) bool {
	parts := strings.Split(stored, "$")
	if len(parts) != 4 || parts[0] != "pbkdf2-sha256" {
		return false
	}
	iter, err := strconv.Atoi(parts[1])
	if err != nil || iter < 1 || iter > 10_000_000 {
		return false
	}
	salt, err1 := b64.DecodeString(parts[2])
	want, err2 := b64.DecodeString(parts[3])
	if err1 != nil || err2 != nil || len(want) == 0 {
		return false
	}
	got, err := pbkdf2.Key(sha256.New, password, salt, iter, len(want))
	return err == nil && subtle.ConstantTimeCompare(got, want) == 1
}

// ReadUsers читает файл пользователей; отсутствующий файл — пустой список.
func ReadUsers(path string) (map[string]string, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return map[string]string{}, nil
	}
	if err != nil {
		return nil, err
	}
	users := map[string]string{}
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if name, hash, ok := strings.Cut(line, ":"); ok {
			users[name] = hash
		}
	}
	return users, sc.Err()
}

// WriteUsers атомарно записывает файл с правами 0640; gid >= 0 — группа
// файла (WebGID: сервис веб-интерфейса читает файл, но не меняет).
func WriteUsers(path string, users map[string]string, gid int) error {
	names := make([]string, 0, len(users))
	for n := range users {
		names = append(names, n)
	}
	sort.Strings(names)
	var b bytes.Buffer
	b.WriteString("# Пользователи веб-интерфейса routerd: routerd web passwd|deluser|users\n")
	for _, n := range names {
		fmt.Fprintf(&b, "%s:%s\n", n, users[n])
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return fsutil.WriteFile(path, b.Bytes(), 0o640, gid)
}

// WebGID — gid группы routerd-web, -1 — группы нет.
func WebGID() int {
	if g, err := user.LookupGroup(api.WebGroup); err == nil {
		if gid, err := strconv.Atoi(g.Gid); err == nil {
			return gid
		}
	}
	return -1
}

// userStore — пользователи с перечитыванием файла при изменении: новый
// пароль действует без перезапуска сервиса.
type userStore struct {
	path string
	mu   sync.Mutex
	mod  time.Time
	size int64
	m    map[string]string
}

func (s *userStore) get(name string) (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	st, err := os.Stat(s.path)
	if err != nil {
		s.m, s.mod, s.size = nil, time.Time{}, 0
		return "", false
	}
	if s.m == nil || !st.ModTime().Equal(s.mod) || st.Size() != s.size {
		m, err := ReadUsers(s.path)
		if err != nil {
			return "", false
		}
		s.m, s.mod, s.size = m, st.ModTime(), st.Size()
	}
	h, ok := s.m[name]
	return h, ok
}

func (s *userStore) count() int {
	s.get("")
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.m)
}
