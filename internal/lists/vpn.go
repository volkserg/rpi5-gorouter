package lists

import (
	"bufio"
	"bytes"
	"io"
	"strings"
)

// VPNFileName — имя списка VPN-записей в каталоге конфигов.
const VPNFileName = "vpn_domains.txt"

// Line — строка файла списка. Для комментариев и пустых строк Entry и Err
// равны nil; для битых записей заполнен Err.
type Line struct {
	Num   int
	Text  string // исходный текст строки без перевода строки
	Entry *Entry
	Err   error
}

// VPNList — содержимое vpn_domains.txt с сохранением комментариев и порядка.
type VPNList struct {
	Lines []Line
}

// ParseVPN разбирает vpn_domains.txt.
//
// Правила:
//   - пустые строки и строки, начинающиеся с '#' (после пробелов), — комментарии;
//   - пробелы по краям обрезаются;
//   - хвостовой комментарий « # …» отбрасывается;
//   - запись с пробелами внутри — ошибка.
func ParseVPN(r io.Reader) (*VPNList, error) {
	l := &VPNList{}
	sc := bufio.NewScanner(r)
	for n := 1; sc.Scan(); n++ {
		text := sc.Text()
		line := Line{Num: n, Text: text}
		if s := entryText(text); s != "" {
			e, err := ParseEntry(s)
			if err != nil {
				line.Err = err
			} else {
				line.Entry = &e
			}
		}
		l.Lines = append(l.Lines, line)
	}
	return l, sc.Err()
}

// entryText выделяет значимую часть строки или "" для комментария/пустой строки.
func entryText(text string) string {
	s := strings.TrimSpace(text)
	if s == "" || s[0] == '#' {
		return ""
	}
	if i := strings.IndexAny(s, " \t"); i >= 0 {
		if rest := strings.TrimSpace(s[i:]); rest[0] == '#' {
			return s[:i]
		}
		// Пробел внутри записи — пусть ParseEntry вернёт осмысленную ошибку.
	}
	return s
}

// Entries возвращает корректные записи в порядке файла, без повторов.
func (l *VPNList) Entries() []Entry {
	var out []Entry
	seen := make(map[string]bool)
	for _, ln := range l.Lines {
		if ln.Entry != nil && !seen[ln.Entry.String()] {
			seen[ln.Entry.String()] = true
			out = append(out, *ln.Entry)
		}
	}
	return out
}

// Invalid возвращает строки с ошибками разбора.
func (l *VPNList) Invalid() []Line {
	var out []Line
	for _, ln := range l.Lines {
		if ln.Err != nil {
			out = append(out, ln)
		}
	}
	return out
}

// Contains сообщает, есть ли запись в списке (сравнение по смыслу, см. Entry.Equal).
func (l *VPNList) Contains(e Entry) bool {
	for _, ln := range l.Lines {
		if ln.Entry != nil && ln.Entry.Equal(e) {
			return true
		}
	}
	return false
}

// Add дописывает запись в конец списка в канонической форме.
// Возвращает false, если такая запись уже есть.
func (l *VPNList) Add(e Entry) bool {
	if l.Contains(e) {
		return false
	}
	l.Lines = append(l.Lines, Line{Text: e.String(), Entry: &e})
	return true
}

// Remove удаляет все строки с этой записью и возвращает их число.
// Комментарии и прочие строки не затрагиваются.
func (l *VPNList) Remove(e Entry) int {
	kept := l.Lines[:0]
	removed := 0
	for _, ln := range l.Lines {
		if ln.Entry != nil && ln.Entry.Equal(e) {
			removed++
			continue
		}
		kept = append(kept, ln)
	}
	l.Lines = kept
	return removed
}

// MergeResult — итог массовой загрузки (load-vpn-domains / load-vpn-ips).
type MergeResult struct {
	Total   int     // записей нужного типа в источнике
	Added   []Entry // добавленные
	Skipped int     // уже были в списке (в том числе повторы внутри источника)
	Foreign []Entry // записи другого типа — пропущены
	Invalid []Line  // строки источника с ошибками
}

// Merge добавляет из src записи типа kind. Записи другого типа и битые
// строки не добавляются, а возвращаются в результате для вывода пользователю.
func (l *VPNList) Merge(src *VPNList, kind Kind) MergeResult {
	res := MergeResult{Invalid: src.Invalid()}
	// Индекс вместо Contains: источник может содержать тысячи записей.
	have := make(map[string]bool)
	for _, e := range l.Entries() {
		have[e.String()] = true
	}
	for _, ln := range src.Lines {
		if ln.Entry == nil {
			continue
		}
		e := *ln.Entry
		if e.Kind != kind {
			res.Foreign = append(res.Foreign, e)
			continue
		}
		res.Total++
		if have[e.String()] {
			res.Skipped++
			continue
		}
		have[e.String()] = true
		l.Lines = append(l.Lines, Line{Text: e.String(), Entry: &e})
		res.Added = append(res.Added, e)
	}
	return res
}

// Bytes сериализует список; файл всегда заканчивается переводом строки,
// чтобы дописанная в конец запись не склеилась с последней строкой.
func (l *VPNList) Bytes() []byte {
	var b bytes.Buffer
	for _, ln := range l.Lines {
		b.WriteString(ln.Text)
		b.WriteByte('\n')
	}
	return b.Bytes()
}
