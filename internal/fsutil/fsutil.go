// Package fsutil — замена файлов, переживающая внезапное отключение питания.
package fsutil

import (
	"os"
	"path/filepath"
)

// Rename атомарно заменяет path файлом tmp (уже записанным и сброшенным на
// диск через Sync) и сбрасывает на диск каталог: без этого новая запись
// каталога может не пережить отключение питания — после включения остался
// бы прежний файл или не осталось бы никакого.
func Rename(tmp, path string) error {
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	return SyncDir(filepath.Dir(path))
}

// SyncDir сбрасывает на диск содержимое каталога dir.
func SyncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}
