package cli

import (
	"context"
	"os"
	"time"

	"github.com/volkserg/rpi5-gorouter/internal/lists"
	"github.com/volkserg/rpi5-gorouter/internal/services"
)

// opTimeout — предел ожидания заданий systemd.
const opTimeout = 90 * time.Second

func (x *ctx) requireRoot() bool {
	if x.IsRoot != nil && x.IsRoot() {
		return true
	}
	x.errf("Ошибка: требуется root!")
	return false
}

// withManager подключается к systemd и вызывает fn.
func (x *ctx) withManager(fn func(context.Context, services.Manager) int) int {
	ctx, cancel := context.WithTimeout(context.Background(), opTimeout)
	defer cancel()
	m, err := x.Services(ctx)
	if err != nil {
		x.errf("Ошибка: %v", err)
		return 1
	}
	defer m.Close()
	return fn(ctx, m)
}

// applyLists просит routerd перечитать списки (SIGHUP через ReloadUnit).
// applied=false — routerd не запущен, список применится при старте.
func (x *ctx) applyLists() (code int, applied bool) {
	code = x.withManager(func(ctx context.Context, m services.Manager) int {
		st, err := m.States(ctx, services.UnitRouterd)
		if err != nil {
			x.errf("Ошибка: %v", err)
			return 1
		}
		if len(st) == 0 || !st[0].Running() {
			x.notef("routerd не запущен — изменения применятся при запуске (router_service_ctl start).")
			return 0
		}
		if err := m.Reload(ctx, services.UnitRouterd); err != nil {
			x.errf("Ошибка применения списка: %v", err)
			return 1
		}
		applied = true
		return 0
	})
	return code, applied
}

// parseArg разбирает аргумент команды и проверяет его тип.
func (x *ctx) parseArg(args []string, cmd, usageArg, what string, want lists.Kind) (lists.Entry, bool) {
	if len(args) == 0 || args[0] == "" {
		x.errf("Ошибка: укажите %s", what)
		x.out("Использование: router_service_ctl %s %s", cmd, usageArg)
		return lists.Entry{}, false
	}
	e, err := lists.ParseEntry(args[0])
	if err != nil {
		x.errf("Ошибка: %v", err)
		return lists.Entry{}, false
	}
	if e.Kind != want {
		if want == lists.KindDomain {
			x.errf("Ошибка: '%s' является IP/CIDR. Используйте '%s' для IP-адресов.", args[0], ipCmd(cmd))
		} else {
			x.errf("Ошибка: '%s' не является валидным IP-адресом или CIDR", args[0])
		}
		return lists.Entry{}, false
	}
	return e, true
}

func ipCmd(domainCmd string) string {
	if domainCmd == "remove-vpn-domain" {
		return "remove-vpn-ip"
	}
	return "add-vpn-ip"
}

// changeList добавляет или удаляет запись и применяет список.
func (x *ctx) changeList(args []string, cmd string, kind lists.Kind, add bool) int {
	usageArg, what, label := "<domain>", "домен", "Домен"
	if kind == lists.KindNet {
		usageArg, what, label = "<ip|cidr>", "IP-адрес или CIDR", "IP/CIDR"
	}
	e, ok := x.parseArg(args, cmd, usageArg, what, kind)
	if !ok || !x.requireRoot() {
		return 1
	}

	var changed bool
	err := lists.UpdateVPN(x.vpnFile(), func(l *lists.VPNList) (bool, error) {
		if add {
			changed = l.Add(e)
		} else {
			changed = l.Remove(e) > 0
		}
		return changed, nil
	})
	if err != nil {
		x.errf("Ошибка: %v", err)
		return 1
	}

	name := e.String()
	normalized := ""
	if name != args[0] {
		normalized = " (записан как " + name + ")"
	}
	switch {
	case add && !changed:
		x.notef("%s '%s' уже в списке.", label, name)
		return 0
	case !add && !changed:
		x.notef("%s '%s' не найден в списке.", label, name)
		return 0
	case add:
		x.okf("%s '%s' добавлен в список VPN.%s", label, name, normalized)
	default:
		x.okf("%s '%s' удалён из списка VPN.", label, name)
	}
	code, _ := x.applyLists()
	return code
}

func cmdAddDomain(x *ctx, a []string) int {
	return x.changeList(a, "add-vpn-domain", lists.KindDomain, true)
}
func cmdRemoveDomain(x *ctx, a []string) int {
	return x.changeList(a, "remove-vpn-domain", lists.KindDomain, false)
}
func cmdAddIP(x *ctx, a []string) int { return x.changeList(a, "add-vpn-ip", lists.KindNet, true) }
func cmdRemoveIP(x *ctx, a []string) int {
	return x.changeList(a, "remove-vpn-ip", lists.KindNet, false)
}

// loadList — load-vpn-domains / load-vpn-ips: массовое добавление из файла.
func (x *ctx) loadList(args []string, cmd string, kind lists.Kind) int {
	if len(args) == 0 || args[0] == "" {
		x.errf("Ошибка: укажите путь к файлу")
		x.out("Использование: router_service_ctl %s <file>", cmd)
		return 1
	}
	path := args[0]
	if st, err := os.Stat(path); err != nil || st.IsDir() {
		x.errf("Ошибка: файл '%s' не найден", path)
		return 1
	}
	src, _, err := lists.ReadVPN(path)
	if err != nil {
		x.errf("Ошибка: файл '%s' не читается: %v", path, err)
		return 1
	}
	if !x.requireRoot() {
		return 1
	}

	var res lists.MergeResult
	err = lists.UpdateVPN(x.vpnFile(), func(l *lists.VPNList) (bool, error) {
		res = l.Merge(src, kind)
		return len(res.Added) > 0, nil
	})
	if err != nil {
		x.errf("Ошибка: %v", err)
		return 1
	}

	for _, e := range res.Foreign {
		if kind == lists.KindDomain {
			x.notef("Пропущено (IP/CIDR, используйте load-vpn-ips): %s", e)
		} else {
			x.notef("Пропущено (не IP/CIDR): %s", e)
		}
	}
	for _, ln := range res.Invalid {
		x.notef("Пропущено (строка %d): %v", ln.Num, ln.Err)
	}
	if kind == lists.KindDomain {
		x.okf("Обработано доменов: %d", res.Total)
		x.okf("Добавлено доменов: %d", len(res.Added))
	} else {
		x.okf("Обработано IP/CIDR: %d", res.Total)
		x.okf("Добавлено: %d", len(res.Added))
	}
	if res.Skipped > 0 {
		x.notef("Пропущено (уже есть): %d", res.Skipped)
	}
	if len(res.Added) == 0 {
		x.notef("Новых записей нет, перезагрузка не требуется.")
		return 0
	}
	code, _ := x.applyLists()
	return code
}

func cmdLoadDomains(x *ctx, a []string) int {
	return x.loadList(a, "load-vpn-domains", lists.KindDomain)
}
func cmdLoadIPs(x *ctx, a []string) int { return x.loadList(a, "load-vpn-ips", lists.KindNet) }

func cmdReload(x *ctx, _ []string) int {
	if !x.requireRoot() {
		return 1
	}
	x.okf("Перезагрузка списка VPN-доменов и IP...")
	code, applied := x.applyLists()
	if applied {
		x.okf("Список VPN-доменов и IP перезагружен.")
	}
	return code
}
