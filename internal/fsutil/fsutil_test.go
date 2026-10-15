package fsutil

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRename(t *testing.T) {
	dir := t.TempDir()
	tmp, path := filepath.Join(dir, ".f.tmp"), filepath.Join(dir, "f")
	if err := os.WriteFile(path, []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(tmp, []byte("new"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := Rename(tmp, path); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(path); string(b) != "new" {
		t.Errorf("содержимое: %q", b)
	}
	if _, err := os.Stat(tmp); !os.IsNotExist(err) {
		t.Error("временный файл остался")
	}
}
