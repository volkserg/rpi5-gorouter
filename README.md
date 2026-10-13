# rpi5-gorouter

`routerd` — router_service для Raspberry Pi 5 на Go: DHCP, DNS-прокси с
наполнением nft-set, NAT и выборочная маршрутизация трафика к заданным доменам
и подсетям через VPN-туннель (например, к корпоративной сети) на одном порту `eth0`.
Замена bash-версии без вызова внешних утилит в рабочем режиме.

Статус: **этап 3** — демон `routerd run`: sysctl, правила nftables и policy
routing через netlink, три режима отправки трафика в туннель (`redirect`,
`tproxy`, `route`) с `VPN_FAILOVER`; встроенный DNS-прокси на :53 (вместо
dnsmasq) — адреса доменов из списка попадают в nft-set со сроком
max(TTL, `VPN_DYNAMIC_TIMEOUT`), ECS в Pi-hole, фильтр AAAA, override-upstream;
все команды `router_service_ctl`, кроме `apply-network`.
Архитектура, решения и план — в [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Сборка

```bash
make test        # юнит-тесты (работают и на macOS)
make build-rpi   # bin/routerd-linux-arm64
```

## Использование

```bash
routerd ctl help
routerd ctl status
routerd ctl check-config
sudo routerd ctl start
```

Порядок запуска: `dnscrypt-proxy.socket` → `dnscrypt-proxy` → `pihole-FTL` →
`routerd` → `gost-run`. `stop` останавливает `gost-run` и `routerd`; Pi-hole и
dnscrypt-proxy продолжают работать. `logs` — единственное место, где routerd
вызывает внешнюю программу (`journalctl`).

Каталог конфигов — `/usr/local/etc/router_service`; для стенда и отладки
переопределяется переменной `ROUTERD_CONFIG_DIR`. Юниты systemd — в `deploy/systemd/`.

## Тестовый стенд

Network namespace в Linux-VM (OrbStack, Debian 13 arm64), без Docker —
см. `testbed/lab.sh`:

```bash
make build-rpi
orb -m routerd-lab sudo ./testbed/lab.sh bootstrap      # один раз
orb -m routerd-lab sudo ./testbed/lab.sh check-kernel   # ядро VM против эталона RPi
orb -m routerd-lab sudo ./testbed/lab.sh up
orb -m routerd-lab sudo ./testbed/lab.sh install
orb -m routerd-lab sudo ./testbed/lab.sh test       # текущий режим
orb -m routerd-lab sudo ./testbed/lab.sh test-all   # redirect, tproxy, route × closed/open
orb -m routerd-lab sudo ./testbed/lab.sh mode tproxy open
```

Интеграционные тесты nftables (root, в отдельном netns):

```bash
GOOS=linux GOARCH=arm64 go test -c -tags integration -o fw.test ./internal/firewall
orb -m routerd-lab sudo ./fw.test -test.v
```
