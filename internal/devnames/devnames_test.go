package devnames

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestStore(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil || s.Get("mac:aa") != "" {
		t.Fatalf("пустой: %v", err)
	}
	if err := s.Set("mac:aa", "  Ноутбук  "); err != nil {
		t.Fatal(err)
	}
	if s.Get("mac:aa") != "Ноутбук" {
		t.Errorf("имя: %q", s.Get("mac:aa"))
	}
	s2, err := Open(dir)
	if err != nil || s2.Get("mac:aa") != "Ноутбук" {
		t.Errorf("после перечитывания: %q %v", s2.Get("mac:aa"), err)
	}
	if err := s2.Set("mac:aa", ""); err != nil || s2.Get("mac:aa") != "" {
		t.Errorf("сброс: %v", err)
	}
	for _, bad := range []string{strings.Repeat("я", MaxLen+1), "a\nb"} {
		if s.Set("mac:aa", bad) == nil {
			t.Errorf("%q принято", bad)
		}
	}
	if s.Set("", "x") == nil {
		t.Error("пустой ключ принят")
	}
	if err := os.WriteFile(filepath.Join(dir, FileName), []byte("{"), 0o644); err != nil {
		t.Fatal(err)
	}
	if s3, err := Open(dir); err == nil || s3.Get("mac:aa") != "" {
		t.Error("испорченный файл: ожидалась ошибка и пустой набор")
	}
	var nilStore *Store
	if nilStore.Get("x") != "" {
		t.Error("nil")
	}
}
