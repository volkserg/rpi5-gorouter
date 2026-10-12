// Package domain — нормализация и проверка доменных имён и сопоставление
// имени со списком доменов по правилам dnsmasq (ipset=/nftset=/server=):
// запись example.com покрывает сам домен и все его поддомены.
package domain

import (
	"errors"
	"fmt"
	"strings"
)

// Normalize приводит имя к виду для сравнения: нижний регистр ASCII,
// без завершающей точки. Корректность не проверяется — см. Validate.
func Normalize(name string) string {
	name = strings.TrimSuffix(name, ".")
	for i := 0; i < len(name); i++ {
		if c := name[i]; c >= 'A' && c <= 'Z' {
			return strings.ToLower(name)
		}
	}
	return name
}

// Validate проверяет имя (уже нормализованное) на соответствие правилам DNS:
// метки 1–63 символа из [a-z0-9-_], без дефиса по краям, всего до 253 символов.
// Одиночная метка (например, TLD) допустима — dnsmasq это тоже разрешает.
func Validate(name string) error {
	if name == "" {
		return errors.New("пустое имя")
	}
	if len(name) > 253 {
		return errors.New("имя длиннее 253 символов")
	}
	for label := range strings.SplitSeq(name, ".") {
		if label == "" {
			return errors.New("пустая метка (две точки подряд или точка в начале)")
		}
		if len(label) > 63 {
			return fmt.Errorf("метка %q длиннее 63 символов", label)
		}
		if label[0] == '-' || label[len(label)-1] == '-' {
			return fmt.Errorf("метка %q начинается или заканчивается дефисом", label)
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			switch {
			case c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '-', c == '_':
			case c >= 0x80:
				return errors.New("не-ASCII символы: укажите домен в punycode (xn--...)")
			case c == '*':
				return errors.New("маски не нужны: запись домена уже покрывает все поддомены")
			default:
				return fmt.Errorf("недопустимый символ %q", c)
			}
		}
	}
	return nil
}

// Matcher сопоставляет имя с набором доменов по суффиксу на границе меток.
// При нескольких совпадениях выигрывает самый длинный (самый конкретный)
// домен — так dnsmasq выбирает server=/domain/.
type Matcher[V any] struct {
	m map[string]V
}

// NewMatcher создаёт пустой Matcher.
func NewMatcher[V any]() *Matcher[V] {
	return &Matcher[V]{m: make(map[string]V)}
}

// Set связывает домен со значением, заменяя прежнее.
func (m *Matcher[V]) Set(domain string, v V) {
	m.m[Normalize(domain)] = v
}

// Get возвращает значение, связанное ровно с этим доменом.
func (m *Matcher[V]) Get(domain string) (V, bool) {
	v, ok := m.m[Normalize(domain)]
	return v, ok
}

// Len — число доменов.
func (m *Matcher[V]) Len() int { return len(m.m) }

// Lookup ищет самый длинный домен из набора, покрывающий name.
// Возвращает значение, найденный домен и признак совпадения.
func (m *Matcher[V]) Lookup(name string) (V, string, bool) {
	name = Normalize(name)
	for {
		if v, ok := m.m[name]; ok {
			return v, name, true
		}
		i := strings.IndexByte(name, '.')
		if i < 0 {
			var zero V
			return zero, "", false
		}
		name = name[i+1:]
	}
}
