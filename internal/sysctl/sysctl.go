// Package sysctl выставляет параметры ядра записью в /proc/sys (вместо
// sysctl -w). Для net.* достаточно CAP_NET_ADMIN в сетевом namespace.
package sysctl

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Setting — параметр и требуемое значение.
type Setting struct {
	Key   string // в точечной нотации: net.ipv4.ip_forward
	Value string
}

// Router — параметры шлюза с одним интерфейсом iface.
//
// send_redirects ядро объединяет по OR для all и интерфейса, поэтому его
// нужно выключить в обоих местах: иначе RPi рассылает клиентам ICMP redirect
// «идите напрямую на роутер» (так было в bash-версии).
func Router(iface string) []Setting {
	return []Setting{
		{"net.ipv4.ip_forward", "1"},
		{"net.ipv4.conf.all.proxy_arp", "0"},
		{"net.ipv4.conf.all.rp_filter", "1"},
		{"net.ipv4.conf.all.accept_redirects", "0"},
		{"net.ipv4.conf.all.send_redirects", "0"},
		{"net.ipv4.conf." + iface + ".send_redirects", "0"},
		{"net.ipv4.conf." + iface + ".accept_redirects", "0"},
	}
}

// Apply записывает значения, которые отличаются от текущих. Если запись
// невозможна, но значение уже нужное (например, /proc/sys только для
// чтения в контейнере), это не ошибка. Возвращает изменённые ключи.
func Apply(procRoot string, settings []Setting) (changed []string, err error) {
	var errs []error
	for _, s := range settings {
		path := filepath.Join(procRoot, "sys", strings.ReplaceAll(s.Key, ".", "/"))
		cur, rerr := os.ReadFile(path)
		if rerr == nil && strings.TrimSpace(string(cur)) == s.Value {
			continue
		}
		if werr := os.WriteFile(path, []byte(s.Value+"\n"), 0o644); werr != nil {
			errs = append(errs, fmt.Errorf("%s=%s: %w", s.Key, s.Value, werr))
			continue
		}
		changed = append(changed, s.Key)
	}
	return changed, errors.Join(errs...)
}
