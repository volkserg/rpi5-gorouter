# rpi5-gorouter

`routerd` — router_service для Raspberry Pi 5 на Go: DHCP, DNS-прокси с
наполнением nft-set, NAT и выборочная маршрутизация трафика к заданным доменам
и подсетям через VPN-туннель (например, к корпоративной сети) на одном порту `eth0`.
Замена bash-версии без вызова внешних утилит в рабочем режиме.

Статус: **этап 6** — демон `routerd run`: sysctl, правила nftables и policy
routing через netlink, три режима отправки трафика в туннель (`redirect`,
`tproxy`, `route`) с `VPN_FAILOVER`; встроенный DNS-прокси на :53 (вместо
dnsmasq) — адреса доменов из списка попадают в nft-set со сроком
max(TTL, `VPN_DYNAMIC_TIMEOUT`), ECS в Pi-hole, фильтр AAAA, override-upstream;
DHCP-сервер (вместо Kea) с арендами в `/var/lib/routerd/leases.json` и
именами клиентов в зоне `*.lan`; сверка ключей цепочки DNS в `pihole.toml`;
`apply-network` через NetworkManager по D-Bus с автооткатом. Все команды
`router_service_ctl` перенесены; `install.sh` и автодополнение bash/zsh.
Архитектура, решения и план — в [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Сборка

```bash
make test        # юнит-тесты (работают и на macOS)
make build-rpi   # bin/routerd-linux-arm64
make dist        # dist/routerd-<версия>-linux-arm64.tar.gz для установки
```

## Установка

Raspberry Pi OS / Debian 13 (arm64), systemd, NetworkManager:

```bash
scp dist/routerd-*-linux-arm64.tar.gz pi@rpi:
ssh pi@rpi 'tar -xzf routerd-*-linux-arm64.tar.gz && cd routerd-*-linux-arm64 && sudo ./install.sh'
```

`install.sh` ставит недостающее — dnscrypt-proxy (apt), Pi-hole (официальный
установщик, сразу на порту 5353), GOST (последний релиз с GitHub, проверка
sha256) — и сам routerd: бинарник, symlink `router_service_ctl`,
`routerd.service` (с автозапуском), автодополнение bash/zsh. Дальше —
`check-config`, `apply-network --dry-run` и запуск стека.

Повторный запуск — обновление: бинарник и `routerd.service` заменяются,
конфиги в `/usr/local/etc/router_service` и `gost-run.service` — нет (при
первой установке это примеры из `deploy/`). Параметры:

| Параметр | |
|---|---|
| `--force` | заменить конфиги примерами, прежние — в `*.bak.<время>` (`gost-run.service` не трогается никогда) |
| `--no-start` | только установить |
| `--skip-deps` | не ставить Pi-hole, dnscrypt-proxy и GOST |
| `ROUTERD_BIN=<путь>` | бинарник не из `bin/` рядом со скриптом |

Конфиг dnscrypt-proxy остаётся вашим: установщик только направляет
`dnscrypt-proxy.socket` на `DNSCRYPT_ADDR` (drop-in `routerd.conf`), если он
слушает другой адрес. Если `/usr/local/bin/router_service_ctl` — обычный файл
(другая установка, например bash-версия router_service), установщик
останавливается и ничего не меняет.

После установки:
1. Указать свой сервер в `gost-run.service` (`sudo systemctl edit --full gost-run`)
   под `VPN_MODE` — варианты слушателя в комментарии юнита.
2. Выключить DHCP на домашнем роутере (если `DHCP_ENABLED=yes`).
3. Если `apply-network --dry-run` показал изменения — `sudo router_service_ctl
   apply-network`, проверить доступ и `--confirm`.

Все ключи `router.conf` с описанием и значениями по умолчанию —
[deploy/config/router.conf](deploy/config/router.conf).

## Использование

```bash
routerd ctl help
routerd ctl status
routerd ctl check-config
sudo routerd ctl start
sudo routerd ctl apply-network --dry-run   # что изменится в NetworkManager
sudo routerd ctl apply-network             # применить; затем в течение 60 с:
sudo routerd ctl apply-network --confirm   # иначе NetworkManager откатит сам
```

Порядок запуска: `dnscrypt-proxy.socket` → `dnscrypt-proxy` → `pihole-FTL` →
`routerd` → `gost-run`. `stop` останавливает `gost-run` и `routerd`; Pi-hole и
dnscrypt-proxy продолжают работать. `logs` — единственное место, где routerd
вызывает внешнюю программу (`journalctl`).

Каталог конфигов — `/usr/local/etc/router_service`; для стенда и отладки
переопределяется переменной `ROUTERD_CONFIG_DIR`. Юниты systemd — в `deploy/systemd/`.
Автодополнение генерирует сам бинарник: `routerd completion bash|zsh`.

## Тестовый стенд

Network namespace в Linux-VM (OrbStack, Debian 13 arm64), без Docker —
см. `testbed/lab.sh`:

```bash
make build-rpi build-lab   # build-lab: dohd и dhcpprobe для стенда
orb -m routerd-lab sudo ./testbed/lab.sh bootstrap      # один раз: пакеты, GOST
orb -m routerd-lab sudo ./testbed/lab.sh bootstrap-dns  # один раз: Pi-hole, dnscrypt-proxy
orb -m routerd-lab sudo ./testbed/lab.sh check-kernel   # ядро VM против эталона RPi
orb -m routerd-lab sudo ./testbed/lab.sh up
orb -m routerd-lab sudo ./testbed/lab.sh install        # через install.sh --skip-deps
orb -m routerd-lab sudo ./testbed/lab.sh test           # текущий режим
orb -m routerd-lab sudo ./testbed/lab.sh test-all       # redirect, tproxy, route
orb -m routerd-lab sudo ./testbed/lab.sh test-install   # повторный запуск, --force, отказы
orb -m routerd-lab sudo ./testbed/lab.sh mode tproxy open
```

DNS на стенде — как на бою: routerd → Pi-hole (:5353) → dnscrypt-proxy
(:5053, socket activation) → DoH-сервер стенда (`testbed/dohd`, сертификат
от собственного CA стенда) → авторитетный DNS тестовых зон `*.example`.

Интеграционные тесты nftables (root, в отдельном netns):

```bash
GOOS=linux GOARCH=arm64 go test -c -tags integration -o fw.test ./internal/firewall
orb -m routerd-lab sudo ./fw.test -test.v
```
