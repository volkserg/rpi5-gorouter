package api

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/volkserg/rpi5-gorouter/internal/config"
	"github.com/volkserg/rpi5-gorouter/internal/lists"
)

// maxListBody — предел загружаемого файла списка.
const maxListBody = 8 << 20

// Entry — запись списка VPN.
type Entry struct {
	Value string `json:"value"`
	// Kind — domain или net (IP-адрес или подсеть).
	Kind string `json:"kind"`
}

// BadLine — строка файла, которая не будет применена.
type BadLine struct {
	Line  int    `json:"line"`
	Text  string `json:"text"`
	Error string `json:"error"`
}

// VPNList — ответ GET /v1/vpn.
type VPNList struct {
	Entries []Entry   `json:"entries"`
	Invalid []BadLine `json:"invalid"`
	Domains int       `json:"domains"`
	Nets    int       `json:"nets"`
}

// Change — результат добавления или удаления записи.
type Change struct {
	Entry   Entry `json:"entry"`
	Changed bool  `json:"changed"`
	// Normalized — запись сохранена не в том виде, как введена
	// (регистр, маска подсети).
	Normalized bool `json:"normalized"`
}

// ImportResult — разница между текущим списком и загружаемым файлом.
type ImportResult struct {
	Mode    string    `json:"mode"`
	Added   []Entry   `json:"added"`
	Removed []Entry   `json:"removed"`
	Kept    int       `json:"kept"`
	Invalid []BadLine `json:"invalid"`
	// Conflicts — записи, которые применять нельзя (пересечение с
	// подсетями локальных сервисов); с ними импорт не выполняется.
	Conflicts []BadLine `json:"conflicts"`
	Applied   bool      `json:"applied"`
}

// Overrides — ответ GET /v1/overrides.
type Overrides struct {
	Text    string     `json:"text"`
	Rules   []Override `json:"rules"`
	Invalid []BadLine  `json:"invalid"`
}

// Override — правило dns_override.txt.
type Override struct {
	Domain string `json:"domain"`
	Server string `json:"server"`
}

func entryOf(e lists.Entry) Entry {
	kind := "domain"
	if e.Kind == lists.KindNet {
		kind = "net"
	}
	return Entry{Value: e.String(), Kind: kind}
}

func badLines(ls []lists.Line) []BadLine {
	out := []BadLine{}
	for _, l := range ls {
		out = append(out, BadLine{Line: l.Num, Text: l.Text, Error: l.Err.Error()})
	}
	return out
}

// listsAPI — методы списков: правка файлов в каталоге конфигов и
// применение через демон.
type listsAPI struct {
	b   Backend
	dir string
}

func (a *listsAPI) vpnPath() string      { return filepath.Join(a.dir, lists.VPNFileName) }
func (a *listsAPI) overridePath() string { return filepath.Join(a.dir, lists.OverrideFileName) }

// localConflicts — подсети из списка, пересекающиеся с подсетями локальных
// сервисов (как check-config): трафик сервиса к его шлюзу ушёл бы в туннель.
func (a *listsAPI) localConflicts(l *lists.VPNList) []BadLine {
	out := []BadLine{}
	cfg, _, err := config.Load(config.Path(a.dir))
	if err != nil {
		return out
	}
	for _, ln := range l.Lines {
		if ln.Entry == nil || ln.Entry.Kind != lists.KindNet {
			continue
		}
		for _, lc := range cfg.LocalClients {
			if ln.Entry.Prefix.Overlaps(lc.Net) {
				out = append(out, BadLine{Line: ln.Num, Text: ln.Entry.String(),
					Error: fmt.Sprintf("пересекается с подсетью локального сервиса %s (%s, LOCAL_CLIENTS)", lc.Name, lc.Net)})
			}
		}
	}
	return out
}

// apply применяет изменённые списки; ошибка — ответ 500 с её текстом.
func (a *listsAPI) apply(w http.ResponseWriter, r *http.Request, what string) bool {
	if err := a.b.Apply(r.Header.Get(UserHeader), what); err != nil {
		WriteJSON(w, http.StatusInternalServerError, Error{"файл сохранён, но не применён: " + err.Error()})
		return false
	}
	return true
}

func (a *listsAPI) list(w http.ResponseWriter, _ *http.Request) {
	l, _, err := lists.ReadVPN(a.vpnPath())
	if err != nil {
		WriteJSON(w, http.StatusInternalServerError, Error{err.Error()})
		return
	}
	out := VPNList{Entries: []Entry{}, Invalid: badLines(l.Invalid())}
	for _, e := range l.Entries() {
		out.Entries = append(out.Entries, entryOf(e))
		if e.Kind == lists.KindDomain {
			out.Domains++
		} else {
			out.Nets++
		}
	}
	WriteJSON(w, http.StatusOK, out)
}

type valueRequest struct {
	Value string `json:"value"`
}

func (a *listsAPI) add(w http.ResponseWriter, r *http.Request) {
	var req valueRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&req); err != nil {
		WriteJSON(w, http.StatusBadRequest, Error{"некорректный запрос"})
		return
	}
	a.change(w, r, strings.TrimSpace(req.Value), true)
}

func (a *listsAPI) remove(w http.ResponseWriter, r *http.Request) {
	a.change(w, r, strings.TrimSpace(r.URL.Query().Get("value")), false)
}

func (a *listsAPI) change(w http.ResponseWriter, r *http.Request, value string, add bool) {
	e, err := lists.ParseEntry(value)
	if err != nil {
		WriteJSON(w, http.StatusBadRequest, Error{err.Error()})
		return
	}
	if add {
		one := &lists.VPNList{Lines: []lists.Line{{Num: 1, Text: e.String(), Entry: &e}}}
		if c := a.localConflicts(one); len(c) > 0 {
			WriteJSON(w, http.StatusBadRequest, Error{e.String() + ": " + c[0].Error})
			return
		}
	}
	var changed bool
	err = lists.UpdateVPN(a.vpnPath(), func(l *lists.VPNList) (bool, error) {
		if add {
			changed = l.Add(e)
		} else {
			changed = l.Remove(e) > 0
		}
		return changed, nil
	})
	if err != nil {
		WriteJSON(w, http.StatusInternalServerError, Error{err.Error()})
		return
	}
	what := "добавлено в список VPN: " + e.String()
	if !add {
		what = "удалено из списка VPN: " + e.String()
	}
	if changed && !a.apply(w, r, what) {
		return
	}
	WriteJSON(w, http.StatusOK, Change{Entry: entryOf(e), Changed: changed, Normalized: e.String() != value})
}

// file отдаёт файл списка как есть (с комментариями) для скачивания.
func (a *listsAPI) file(path, name string) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		data, err := os.ReadFile(path)
		if err != nil && !errors.Is(err, fs.ErrNotExist) {
			WriteJSON(w, http.StatusInternalServerError, Error{err.Error()})
			return
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="`+name+`"`)
		w.Header().Set("Cache-Control", "no-store")
		_, _ = w.Write(data)
	}
}

// importVPN — POST /v1/vpn/import?mode=merge|replace[&apply=1]: без apply
// только показывает разницу. merge добавляет новые записи (битые строки
// пропускаются), replace заменяет файл целиком (только без битых строк).
func (a *listsAPI) importVPN(w http.ResponseWriter, r *http.Request) {
	mode := r.URL.Query().Get("mode")
	if mode != "merge" && mode != "replace" {
		WriteJSON(w, http.StatusBadRequest, Error{"mode: merge или replace"})
		return
	}
	data, err := io.ReadAll(io.LimitReader(r.Body, maxListBody+1))
	if err != nil || len(data) > maxListBody {
		WriteJSON(w, http.StatusBadRequest, Error{"файл не прочитан или больше 8 МБ"})
		return
	}
	src, err := lists.ParseVPN(bytes.NewReader(data))
	if err != nil {
		WriteJSON(w, http.StatusBadRequest, Error{err.Error()})
		return
	}
	cur, _, err := lists.ReadVPN(a.vpnPath())
	if err != nil {
		WriteJSON(w, http.StatusInternalServerError, Error{err.Error()})
		return
	}
	res := ImportResult{Mode: mode, Added: []Entry{}, Removed: []Entry{},
		Invalid: badLines(src.Invalid()), Conflicts: a.localConflicts(src)}
	have := map[string]bool{}
	for _, e := range cur.Entries() {
		have[e.String()] = true
	}
	want := map[string]bool{}
	for _, e := range src.Entries() {
		want[e.String()] = true
		if have[e.String()] {
			res.Kept++
		} else {
			res.Added = append(res.Added, entryOf(e))
		}
	}
	if mode == "replace" {
		for _, e := range cur.Entries() {
			if !want[e.String()] {
				res.Removed = append(res.Removed, entryOf(e))
			}
		}
	}

	if r.URL.Query().Get("apply") != "1" {
		WriteJSON(w, http.StatusOK, res)
		return
	}
	switch {
	case len(res.Conflicts) > 0:
		WriteJSON(w, http.StatusUnprocessableEntity, res)
		return
	case mode == "replace" && len(res.Invalid) > 0:
		WriteJSON(w, http.StatusUnprocessableEntity, res)
		return
	case len(res.Added) == 0 && len(res.Removed) == 0:
		WriteJSON(w, http.StatusOK, res)
		return
	}
	if mode == "replace" {
		err = lists.ReplaceFile(a.vpnPath(), src.Bytes())
	} else {
		err = lists.UpdateVPN(a.vpnPath(), func(l *lists.VPNList) (bool, error) {
			n := 0
			for _, k := range []lists.Kind{lists.KindDomain, lists.KindNet} {
				n += len(l.Merge(src, k).Added)
			}
			return n > 0, nil
		})
	}
	if err != nil {
		WriteJSON(w, http.StatusInternalServerError, Error{err.Error()})
		return
	}
	what := fmt.Sprintf("список VPN импортирован (%s): добавлено %d, удалено %d", mode, len(res.Added), len(res.Removed))
	if !a.apply(w, r, what) {
		return
	}
	res.Applied = true
	WriteJSON(w, http.StatusOK, res)
}

func (a *listsAPI) overrides(w http.ResponseWriter, _ *http.Request) {
	data, err := os.ReadFile(a.overridePath())
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		WriteJSON(w, http.StatusInternalServerError, Error{err.Error()})
		return
	}
	WriteJSON(w, http.StatusOK, parseOverrides(data))
}

func parseOverrides(data []byte) Overrides {
	out := Overrides{Text: string(data), Rules: []Override{}, Invalid: []BadLine{}}
	rules, bad, _ := lists.ParseOverrides(bytes.NewReader(data))
	for _, o := range rules {
		out.Rules = append(out.Rules, Override{Domain: o.Domain, Server: o.Upstream.String()})
	}
	for _, b := range bad {
		out.Invalid = append(out.Invalid, BadLine{Line: b.Line, Text: b.Text, Error: b.Err.Error()})
	}
	return out
}

// saveOverrides — PUT /v1/overrides[?check=1]: текст файла целиком.
// С ошибками файл не сохраняется (422 и разобранный результат).
func (a *listsAPI) saveOverrides(w http.ResponseWriter, r *http.Request) {
	data, err := io.ReadAll(io.LimitReader(r.Body, maxListBody+1))
	if err != nil || len(data) > maxListBody {
		WriteJSON(w, http.StatusBadRequest, Error{"файл не прочитан или больше 8 МБ"})
		return
	}
	if len(data) > 0 && data[len(data)-1] != '\n' {
		data = append(data, '\n')
	}
	res := parseOverrides(data)
	if len(res.Invalid) > 0 {
		WriteJSON(w, http.StatusUnprocessableEntity, res)
		return
	}
	if r.URL.Query().Get("check") == "1" {
		WriteJSON(w, http.StatusOK, res)
		return
	}
	if err := lists.ReplaceFile(a.overridePath(), data); err != nil {
		WriteJSON(w, http.StatusInternalServerError, Error{err.Error()})
		return
	}
	if !a.apply(w, r, fmt.Sprintf("dns_override.txt сохранён: правил %d", len(res.Rules))) {
		return
	}
	WriteJSON(w, http.StatusOK, res)
}
