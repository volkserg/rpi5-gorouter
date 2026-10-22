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

// WriteFile атомарно заменяет path содержимым data с правами perm; gid >= 0
// задаёт группу файла (до замены — без промежутка с чужими правами).
func WriteFile(path string, data []byte, perm os.FileMode, gid int) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name()) // после успешного rename — no-op
	err = tmp.Chmod(perm)
	if err == nil && gid >= 0 {
		err = tmp.Chown(-1, gid)
	}
	if err == nil {
		_, err = tmp.Write(data)
	}
	if err == nil {
		err = tmp.Sync()
	}
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return err
	}
	return Rename(tmp.Name(), path)
}
