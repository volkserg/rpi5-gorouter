package config

import (
	"bufio"
	"fmt"
	"io"
	"strings"
)

// Assignment — одна строка KEY=VALUE из router.conf.
type Assignment struct {
	Key   string
	Value string
	Line  int
}

// ParseAssignments разбирает файл в формате присваиваний shell (файл можно
// подключить через `source`), но только в безопасном подмножестве: KEY=VALUE,
// необязательный `export`, одинарные и двойные кавычки, комментарии `#`.
// Подстановки ($VAR, `cmd`) и команды не поддерживаются — для них
// возвращается ошибка с номером строки, а не значение, отличное от того,
// что получил бы shell.
func ParseAssignments(r io.Reader) ([]Assignment, error) {
	var out []Assignment
	sc := bufio.NewScanner(r)
	for n := 1; sc.Scan(); n++ {
		line := strings.TrimSpace(sc.Text())
		if line == "" || line[0] == '#' {
			continue
		}
		if rest, ok := strings.CutPrefix(line, "export"); ok && rest != "" && (rest[0] == ' ' || rest[0] == '\t') {
			line = strings.TrimSpace(rest)
		}
		key, raw, ok := strings.Cut(line, "=")
		if !ok {
			return nil, fmt.Errorf("строка %d: ожидается KEY=VALUE: %q", n, line)
		}
		if !validKey(key) {
			return nil, fmt.Errorf("строка %d: недопустимое имя переменной %q", n, key)
		}
		val, err := parseValue(raw)
		if err != nil {
			return nil, fmt.Errorf("строка %d (%s): %w", n, key, err)
		}
		out = append(out, Assignment{Key: key, Value: val, Line: n})
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func validKey(k string) bool {
	if k == "" {
		return false
	}
	for i, c := range k {
		switch {
		case c == '_', c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z':
		case c >= '0' && c <= '9' && i > 0:
		default:
			return false
		}
	}
	return true
}

// parseValue повторяет правила shell для правой части присваивания:
// конкатенация незакавыченных и закавыченных фрагментов до первого
// пробела, после которого допустим только комментарий.
func parseValue(s string) (string, error) {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch c {
		case ' ', '\t':
			rest := strings.TrimSpace(s[i:])
			if rest != "" && rest[0] != '#' {
				return "", fmt.Errorf("пробел в значении — заключите значение в кавычки")
			}
			return b.String(), nil
		case '\'':
			end := strings.IndexByte(s[i+1:], '\'')
			if end < 0 {
				return "", fmt.Errorf("незакрытая одинарная кавычка")
			}
			b.WriteString(s[i+1 : i+1+end])
			i += end + 1
		case '"':
			i++
			for ; i < len(s) && s[i] != '"'; i++ {
				switch s[i] {
				case '$', '`':
					return "", fmt.Errorf("подстановки ($, `) не поддерживаются")
				case '\\':
					if i+1 < len(s) && strings.IndexByte("\"\\$`", s[i+1]) >= 0 {
						i++
					}
				}
				b.WriteByte(s[i])
			}
			if i >= len(s) {
				return "", fmt.Errorf("незакрытая двойная кавычка")
			}
		case '$', '`', ';', '&', '|', '<', '>', '(', ')':
			return "", fmt.Errorf("символ %q не поддерживается (подстановки и команды запрещены)", c)
		case '\\':
			if i+1 < len(s) {
				i++
			}
			b.WriteByte(s[i])
		default:
			b.WriteByte(c)
		}
	}
	return b.String(), nil
}
