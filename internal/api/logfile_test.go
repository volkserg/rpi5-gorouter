package api

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestTailLog(t *testing.T) {
	path := filepath.Join(t.TempDir(), "FTL.log")
	write := func(s string, flag int) {
		f, err := os.OpenFile(path, flag|os.O_WRONLY|os.O_CREATE, 0o644)
		if err != nil {
			t.Fatal(err)
		}
		f.WriteString(s)
		f.Close()
	}
	write("2026-10-23 06:18:56.123 [1234M] INFO: FTL started\n"+
		"2026-10-23 06:18:57.000 [1234M] WARNING: Long-term load is high\n"+
		"   продолжение предупреждения\n", os.O_TRUNC)
	j, err := TailLog(path, "", 2, time.UTC)
	if err != nil {
		t.Fatal(err)
	}
	if len(j.Entries) != 2 || j.Entries[0].Priority != 4 || j.Entries[0].Message != "Long-term load is high" {
		t.Fatalf("последние 2: %+v", j.Entries)
	}
	if j.Entries[1].Time != j.Entries[0].Time || j.Entries[1].Message != "   продолжение предупреждения" {
		t.Errorf("продолжение строки: %+v", j.Entries[1])
	}

	// Дописано: полная строка и начало следующей.
	write("2026-10-23 06:19:00.000 [1234M] ERR: upstream failed\n2026-10-23 06:19", os.O_APPEND)
	j2, err := TailLog(path, j.Cursor, 100, time.UTC)
	if err != nil || len(j2.Entries) != 1 || j2.Entries[0].Priority != 3 || j2.Entries[0].Message != "upstream failed" {
		t.Fatalf("после курсора: %+v %v", j2.Entries, err)
	}
	if want := time.Date(2026, 10, 23, 6, 19, 0, 0, time.UTC).UnixMilli(); j2.Entries[0].Time != want {
		t.Errorf("время: %d", j2.Entries[0].Time)
	}
	// Незаконченная строка — в следующий раз.
	write(":01.000 [1234M] INFO: done\n", os.O_APPEND)
	j3, _ := TailLog(path, j2.Cursor, 100, time.UTC)
	if len(j3.Entries) != 1 || j3.Entries[0].Message != "done" {
		t.Errorf("дописанная строка: %+v", j3.Entries)
	}
	// Ротация: файл короче смещения — читается заново.
	write("2026-10-23 07:00:00.000 [1] INFO: new file\n", os.O_TRUNC)
	j4, _ := TailLog(path, j3.Cursor, 100, time.UTC)
	if len(j4.Entries) != 1 || j4.Entries[0].Message != "new file" {
		t.Errorf("после ротации: %+v", j4.Entries)
	}
	if _, err := TailLog(filepath.Join(t.TempDir(), "нет"), "", 10, time.UTC); err == nil {
		t.Error("нет файла: ожидалась ошибка")
	}
}
