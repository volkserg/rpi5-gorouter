package cli

import (
	"context"
	"net/netip"
	"time"

	"github.com/volkserg/rpi5-gorouter/internal/netcfg"
)

// networkRollback — сколько ждать подтверждения apply-network.
const networkRollback = 60 * time.Second

// cmdApplyNetwork — статический адрес RPi из router.conf через NetworkManager
// (по аналогии с nmcli con mod + con up), под защитой checkpoint.
func cmdApplyNetwork(x *ctx, args []string) int {
	mode := "apply"
	if len(args) > 0 {
		switch args[0] {
		case "--dry-run", "--confirm", "--rollback":
			mode = args[0]
		default:
			x.errf("Неизвестный параметр: %s", args[0])
			x.out("Использование: %s apply-network [--dry-run|--confirm|--rollback]", x.Prog)
			return 1
		}
	}
	if mode != "--dry-run" && !x.requireRoot() {
		return 1
	}
	cfg, ok := x.loadConfig()
	if !ok {
		return 1
	}
	nm, closeNM, err := x.NM()
	if err != nil {
		x.errf("Ошибка: NetworkManager: %v", err)
		return 1
	}
	defer closeNM()
	ctx, cancel := context.WithTimeout(context.Background(), opTimeout)
	defer cancel()

	params := netcfg.Params{
		Iface:    cfg.Iface,
		ConnName: cfg.NMConn,
		Address:  netip.PrefixFrom(cfg.RPi5IP, cfg.LANSubnet.Bits()),
		Gateway:  cfg.RouterIP,
		DNS:      cfg.DNS,
	}
	switch mode {
	case "--confirm":
		n, err := netcfg.Confirm(ctx, nm, params)
		switch {
		case err != nil:
			x.errf("Ошибка подтверждения: %v", err)
			return 1
		case n == 0:
			x.notef("Неподтверждённых изменений сети нет.")
		default:
			x.okf("Изменения сети подтверждены и записаны на диск.")
		}
		return 0
	case "--rollback":
		n, err := netcfg.Rollback(ctx, nm, cfg.Iface)
		switch {
		case err != nil:
			x.errf("Ошибка отката: %v", err)
			return 1
		case n == 0:
			x.notef("Неподтверждённых изменений сети нет — откатывать нечего.")
		default:
			x.okf("Прежние настройки сети возвращены.")
		}
		return 0
	}

	plan, err := netcfg.Prepare(ctx, nm, params)
	if err != nil {
		x.errf("Ошибка: %v", err)
		return 1
	}
	x.out("Подключение NetworkManager: %s (%s)", plan.ConnID, cfg.Iface)
	if len(plan.Changes) == 0 {
		x.okf("Сеть уже соответствует router.conf.")
		return 0
	}
	for _, c := range plan.Changes {
		x.out("  %s: %s → %s", c.Key, c.Have, c.Want)
	}
	if mode == "--dry-run" {
		x.notef("(dry-run: ничего не изменено)")
		return 0
	}

	if _, err := netcfg.Apply(ctx, nm, plan, networkRollback); err != nil {
		x.errf("Ошибка: %v", err)
		return 1
	}
	x.okf("Сеть применена: %s/%d, шлюз %s.", cfg.RPi5IP, cfg.LANSubnet.Bits(), cfg.RouterIP)
	x.notef("Проверьте доступ к RPi (например, SSH на %s) и в течение %d с подтвердите:", cfg.RPi5IP, int(networkRollback.Seconds()))
	x.notef("  sudo %s apply-network --confirm", x.Prog)
	x.notef("Без подтверждения NetworkManager сам вернёт прежние настройки; до подтверждения")
	x.notef("они только в памяти — после перезагрузки RPi поднимется с прежними.")
	// Новый адрес RPi нужен DNS и DHCP routerd.
	code, _ := x.applyLists()
	return code
}
