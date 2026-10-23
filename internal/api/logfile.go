package api

import (
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// maxLogRead — сколько байт файла журнала читать за раз.
const maxLogRead = 1 << 20

// TailLog читает файл журнала (например, FTL.log Pi-hole: свой журнал он
// пишет в файл, а не в journald). Без cursor — последние lines строк, с
// cursor — строки, дописанные после него. Курсор — «inode:смещение»; файл
// заменён ротацией (другой inode или короче смещения) — читается сначала.
func TailLog(path, cursor string, lines int, loc *time.Location) (Journal, error) {
	f, err := os.Open(path)
	if err != nil {
		return Journal{}, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return Journal{}, err
	}
	var ino uint64
	if sys, ok := st.Sys().(*syscall.Stat_t); ok {
		ino = uint64(sys.Ino)
	}
	size := st.Size()
	from, tail := int64(0), true
	if c, ok := parseLogCursor(cursor); ok && c.ino == ino && c.off <= size {
		from, tail = c.off, false
	}
	if tail {
		from = max(0, size-256<<10)
	}
	if size-from > maxLogRead {
		from = size - maxLogRead
	}
	buf := make([]byte, size-from)
	if _, err := f.ReadAt(buf, from); err != nil && !errors.Is(err, io.EOF) {
		return Journal{}, err
	}
	// Последняя строка без перевода строки ещё дописывается — до следующего раза.
	end := strings.LastIndexByte(string(buf), '\n') + 1
	text := string(buf[:end])
	if tail && from > 0 {
		if i := strings.IndexByte(text, '\n'); i >= 0 {
			text = text[i+1:] // первая строка — обрезанная
		}
	}
	ls := strings.Split(strings.TrimSuffix(text, "\n"), "\n")
	if text == "" {
		ls = nil
	}
	if tail && len(ls) > lines {
		ls = ls[len(ls)-lines:]
	}
	j := Journal{Unit: path, Entries: []JournalEntry{},
		Cursor: fmt.Sprintf("%d:%d", ino, from+int64(end))}
	var last int64
	for _, l := range ls {
		if l == "" {
			continue
		}
		e := parseFTLLine(l, loc)
		if e.Time == 0 {
			e.Time = last // продолжение предыдущей записи
		}
		last = e.Time
		j.Entries = append(j.Entries, e)
	}
	return j, nil
}

type logCursor struct {
	ino uint64
	off int64
}

func parseLogCursor(s string) (logCursor, bool) {
	a, b, ok := strings.Cut(s, ":")
	if !ok {
		return logCursor{}, false
	}
	ino, err1 := strconv.ParseUint(a, 10, 64)
	off, err2 := strconv.ParseInt(b, 10, 64)
	if err1 != nil || err2 != nil || off < 0 {
		return logCursor{}, false
	}
	return logCursor{ino, off}, true
}

// ftlLine — «2026-10-23 06:18:56.123 [1234M] INFO: сообщение».
var ftlLine = regexp.MustCompile(`^(\d{4}-\d\d-\d\d \d\d:\d\d:\d\d)(?:\.\d+)? \[[^\]]*\] ([A-Z]+): ?(.*)$`)

var ftlPriority = map[string]int{"DEBUG": 7, "INFO": 6, "NOTICE": 5, "WARNING": 4, "WARN": 4, "ERR": 3, "ERROR": 3, "CRIT": 2, "CRITICAL": 2}

func parseFTLLine(l string, loc *time.Location) JournalEntry {
	m := ftlLine.FindStringSubmatch(l)
	if m == nil {
		return JournalEntry{Priority: 6, Message: l}
	}
	e := JournalEntry{Priority: 6, Message: m[3]}
	if p, ok := ftlPriority[m[2]]; ok {
		e.Priority = p
	}
	if t, err := time.ParseInLocation("2006-01-02 15:04:05", m[1], loc); err == nil {
		e.Time = t.UnixMilli()
	}
	return e
}
