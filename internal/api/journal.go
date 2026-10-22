package api

import (
	"bufio"
	"bytes"
	"encoding/json"
	"strconv"
	"strings"
)

// ParseJournal разбирает вывод journalctl -o json (запись на строку).
// cursor — прежний курсор: он остаётся, если новых записей нет.
func ParseJournal(unit, cursor string, out []byte) Journal {
	j := Journal{Unit: unit, Entries: []JournalEntry{}, Cursor: cursor}
	sc := bufio.NewScanner(bytes.NewReader(out))
	sc.Buffer(make([]byte, 64<<10), 4<<20)
	for sc.Scan() {
		var m map[string]json.RawMessage
		if json.Unmarshal(sc.Bytes(), &m) != nil {
			continue
		}
		e := JournalEntry{Priority: 6, Message: journalString(m["MESSAGE"])}
		if us, err := strconv.ParseInt(journalString(m["__REALTIME_TIMESTAMP"]), 10, 64); err == nil {
			e.Time = us / 1000
		}
		if p, err := strconv.Atoi(journalString(m["PRIORITY"])); err == nil {
			e.Priority = p
		}
		j.Entries = append(j.Entries, e)
		if cur := journalString(m["__CURSOR"]); cur != "" {
			j.Cursor = cur
		}
	}
	return j
}

// journalString — значение поля: строка или массив байтов (journalctl так
// выводит значения с непечатными символами или не в UTF-8); null — пусто.
func journalString(raw json.RawMessage) string {
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return s
	}
	var nums []int
	if json.Unmarshal(raw, &nums) == nil {
		b := make([]byte, 0, len(nums))
		for _, n := range nums {
			b = append(b, byte(n))
		}
		return strings.ToValidUTF8(string(b), "�")
	}
	return ""
}
