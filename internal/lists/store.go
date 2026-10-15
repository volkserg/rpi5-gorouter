package lists

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
)

// ReadVPN читает vpn_domains.txt. Отсутствующий файл — не ошибка, а пустой
// список (exists=false).
func ReadVPN(path string) (l *VPNList, exists bool, err error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return &VPNList{}, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	l, err = ParseVPN(bytes.NewReader(data))
	return l, true, err
}

// ReadOverrides читает dns_override.txt; отсутствующий файл — пустой список.
func ReadOverrides(path string) ([]Override, []LineError, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil, nil
	}
	if err != nil {
		return nil, nil, err
	}
	return ParseOverrides(bytes.NewReader(data))
}

// UpdateVPN читает список под эксклюзивной блокировкой, вызывает fn и,
// если fn вернула changed=true, атомарно записывает результат
// (временный файл в том же каталоге → fsync → rename). Блокировка защищает
// от одновременных правок из CLI и демона.
func UpdateVPN(path string, fn func(*VPNList) (changed bool, err error)) error {
	unlock, err := lockFile(path)
	if err != nil {
		return err
	}
	defer unlock()

	l, _, err := ReadVPN(path)
	if err != nil {
		return err
	}
	changed, err := fn(l)
	if err != nil || !changed {
		return err
	}
	return writeAtomic(path, l.Bytes())
}

// lockFile берёт flock на служебный файл рядом со списком. Сам список
// блокировать нельзя: rename подменяет inode, и блокировка теряет смысл.
func lockFile(path string) (func(), error) {
	lp := filepath.Join(filepath.Dir(path), "."+filepath.Base(path)+".lock")
	f, err := os.OpenFile(lp, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("блокировка %s: %w", path, err)
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		f.Close()
		return nil, fmt.Errorf("блокировка %s: %w", path, err)
	}
	return func() {
		_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
		f.Close()
	}, nil
}

// writeAtomic заменяет файл целиком, сохраняя права существующего файла.
func writeAtomic(path string, data []byte) error {
	mode := fs.FileMode(0o644)
	if st, err := os.Stat(path); err == nil {
		mode = st.Mode().Perm()
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name()) // после успешного rename — no-op
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}
