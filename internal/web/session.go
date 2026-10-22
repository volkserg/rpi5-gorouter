package web

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io/fs"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/volkserg/rpi5-gorouter/internal/fsutil"
)

const (
	// cookieName — cookie сессии.
	cookieName = "routerd_session"
	// sessionTTL — сессия без «запомнить устройство»: cookie живёт до
	// закрытия браузера, но не дольше этого срока.
	sessionTTL = 12 * time.Hour
	// rememberTTL — сессия с «запомнить устройство».
	rememberTTL = 30 * 24 * time.Hour
)

// loadSecret читает ключ подписи сессий или создаёт новый (права 0600).
// Новый ключ (удалён файл) завершает все сессии.
func loadSecret(path string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err == nil {
		if key := bytes.TrimSpace(data); len(key) >= 32 {
			return key, nil
		}
	} else if !errors.Is(err, fs.ErrNotExist) {
		return nil, err
	}
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return nil, err
	}
	key := []byte(hex.EncodeToString(raw))
	if err := fsutil.WriteFile(path, append(key, '\n'), 0o600, -1); err != nil {
		return nil, err
	}
	return key, nil
}

// Сессия — подписанная HMAC cookie «логин.срок.подпись», на сервере ничего
// не хранится. В подпись входит хеш пароля: смена пароля или удаление
// пользователя сразу завершает все его сессии.
func sign(secret []byte, user string, exp int64, pwhash string) string {
	m := hmac.New(sha256.New, secret)
	m.Write([]byte(user + "|" + strconv.FormatInt(exp, 10) + "|" + pwhash))
	return b64.EncodeToString(m.Sum(nil))
}

func makeToken(secret []byte, user, pwhash string, exp time.Time) string {
	e := exp.Unix()
	return b64.EncodeToString([]byte(user)) + "." + strconv.FormatInt(e, 10) + "." + sign(secret, user, e, pwhash)
}

// checkToken возвращает логин из действительной cookie.
func checkToken(secret []byte, token string, now time.Time, lookup func(string) (string, bool)) (string, bool) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return "", false
	}
	raw, err := b64.DecodeString(parts[0])
	if err != nil {
		return "", false
	}
	user := string(raw)
	exp, err := strconv.ParseInt(parts[1], 10, 64)
	if err != nil || now.Unix() >= exp {
		return "", false
	}
	pwhash, ok := lookup(user)
	if !ok {
		return "", false
	}
	if !hmac.Equal([]byte(parts[2]), []byte(sign(secret, user, exp, pwhash))) {
		return "", false
	}
	return user, true
}
