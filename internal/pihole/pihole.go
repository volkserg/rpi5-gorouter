// Package pihole сверяет в pihole.toml ключи, от которых зависит цепочка DNS
// routerd, и точечно правит их (остальной файл не трогается). Pi-hole API не
// используется: правка делается при остановленном FTL — он перезаписывает
// файл сам, пока работает.
package pihole

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"syscall"

	"github.com/BurntSushi/toml"
)

// DefaultPath — конфиг Pi-hole v6.
const DefaultPath = "/etc/pihole/pihole.toml"

// Desired — значения ключей секции [dns], которыми владеет routerd.
type Desired struct {
	Port      int      // dns.port — порт Pi-hole в цепочке (5353)
	Upstreams []string // dns.upstreams — dnscrypt-proxy (127.0.0.1#5053)
	ECS       bool     // dns.EDNS0ECS — клиент из EDNS Client Subnet
	// RevServer — запись dns.revServers, по которой Pi-hole спрашивает имена
	// клиентов LAN у routerd; пусто — routerd записей не добавляет. Чужие
	// записи для других подсетей сохраняются.
	RevServer string
	// LAN — подсеть, запись для которой в revServers принадлежит routerd.
	LAN netip.Prefix
}

// RevServerEntry — запись revServers: «включено, подсеть, сервер, домен».
func RevServerEntry(lan netip.Prefix, server netip.AddrPort, domain string) string {
	return fmt.Sprintf("true,%s,%s#%d,%s", lan, server.Addr(), server.Port(), domain)
}

// Drift — расхождение одного ключа.
type Drift struct {
	Key        string
	Have, Want string
	value      string // значение в синтаксисе TOML для записи
}

func (d Drift) String() string { return fmt.Sprintf("dns.%s: %s → %s", d.Key, d.Have, d.Want) }

// Check читает конфиг и возвращает расхождения с Desired.
func Check(path string, want Desired) ([]Drift, error) {
	var cfg struct {
		DNS map[string]any `toml:"dns"`
	}
	if _, err := toml.DecodeFile(path, &cfg); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	var drifts []Drift
	add := func(key, have, wantS, value string) {
		if have != wantS {
			drifts = append(drifts, Drift{Key: key, Have: have, Want: wantS, value: value})
		}
	}

	add("port", show(cfg.DNS["port"]), strconv.Itoa(want.Port), strconv.Itoa(want.Port))
	add("upstreams", show(cfg.DNS["upstreams"]), show(want.Upstreams), tomlArray(want.Upstreams))
	add("EDNS0ECS", show(cfg.DNS["EDNS0ECS"]), strconv.FormatBool(want.ECS), strconv.FormatBool(want.ECS))

	have := strings_(cfg.DNS["revServers"])
	wantRev := mergeRevServers(have, want.LAN, want.RevServer)
	add("revServers", show(have), show(wantRev), tomlArray(wantRev))
	return drifts, nil
}

// mergeRevServers оставляет чужие записи, заменяя запись для нашей подсети.
func mergeRevServers(have []string, lan netip.Prefix, ours string) []string {
	out := []string{}
	for _, e := range have {
		if f := strings.Split(e, ","); len(f) >= 2 && f[1] == lan.String() {
			continue
		}
		out = append(out, e)
	}
	if ours != "" {
		out = append(out, ours)
	}
	return out
}

// Apply переписывает в файле ключи из drifts, сохраняя владельца и права.
func Apply(path string, drifts []Drift) error {
	if len(drifts) == 0 {
		return nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	lines := strings.Split(string(data), "\n")
	for _, d := range drifts {
		lines, err = setKey(lines, "dns", d.Key, d.value)
		if err != nil {
			return err
		}
	}
	return writeLike(path, []byte(strings.Join(lines, "\n")))
}

var headerRe = regexp.MustCompile(`^\s*\[\s*([A-Za-z0-9_.]+)\s*\]\s*(#.*)?$`)

// setKey заменяет (или добавляет) key = value в секции section. Многострочный
// массив (как пишет FTL: «key = [» … «]») заменяется целиком одной строкой.
func setKey(lines []string, section, key, value string) ([]string, error) {
	start, end := -1, len(lines)
	for i, l := range lines {
		m := headerRe.FindStringSubmatch(l)
		if m == nil {
			continue
		}
		if start >= 0 {
			end = i
			break
		}
		if m[1] == section {
			start = i
		}
	}
	if start < 0 {
		return nil, fmt.Errorf("нет секции [%s]", section)
	}
	keyRe := regexp.MustCompile(`^(\s*)` + regexp.QuoteMeta(key) + `\s*=\s*(.*)$`)
	for i := start + 1; i < end; i++ {
		m := keyRe.FindStringSubmatch(lines[i])
		if m == nil {
			continue
		}
		last := i
		if v := strings.TrimSpace(m[2]); strings.HasPrefix(v, "[") && !strings.Contains(stripComment(v), "]") {
			for last = i + 1; last < end && !strings.HasPrefix(strings.TrimSpace(lines[last]), "]"); last++ {
			}
			if last == end {
				return nil, fmt.Errorf("незакрытый массив %s.%s", section, key)
			}
		}
		repl := m[1] + key + " = " + value + " ### CHANGED by routerd"
		return slices.Concat(lines[:i], []string{repl}, lines[last+1:]), nil
	}
	ins := "  " + key + " = " + value + " ### CHANGED by routerd"
	return slices.Concat(lines[:start+1], []string{ins}, lines[start+1:]), nil
}

func stripComment(v string) string {
	if i := strings.Index(v, "#"); i >= 0 && !strings.Contains(v[:i], `"`) {
		return v[:i]
	}
	return v
}

// writeLike атомарно заменяет файл, сохраняя права и владельца (pihole:pihole).
func writeLike(path string, data []byte) error {
	st, err := os.Stat(path)
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(data); err != nil {
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
	if err := os.Chmod(tmp.Name(), st.Mode().Perm()); err != nil {
		return err
	}
	if sys, ok := st.Sys().(*syscall.Stat_t); ok {
		if err := os.Chown(tmp.Name(), int(sys.Uid), int(sys.Gid)); err != nil {
			return err
		}
	}
	return os.Rename(tmp.Name(), path)
}

func tomlArray(ss []string) string {
	if len(ss) == 0 {
		return "[]"
	}
	parts := make([]string, len(ss))
	for i, s := range ss {
		b, _ := json.Marshal(s) // строки JSON совместимы с базовыми строками TOML
		parts[i] = string(b)
	}
	return "[ " + strings.Join(parts, ", ") + " ]"
}

func strings_(v any) []string {
	arr, _ := v.([]any)
	out := []string{}
	for _, x := range arr {
		if s, ok := x.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

// show — значение для сравнения и вывода.
func show(v any) string {
	switch x := v.(type) {
	case nil:
		return "(нет)"
	case []any:
		return show(strings_(x))
	case []string:
		var b bytes.Buffer
		_ = json.NewEncoder(&b).Encode(x)
		return strings.TrimSpace(b.String())
	}
	return fmt.Sprint(v)
}
