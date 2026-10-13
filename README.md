# rpi5-gorouter

`routerd` — router_service для Raspberry Pi 5 на Go: DHCP, DNS-прокси с
наполнением nft-set, NAT и выборочная маршрутизация трафика к заданным доменам
и подсетям через VPN-туннель (например, к корпоративной сети) на одном порту `eth0`.
Замена bash-версии без вызова внешних утилит в рабочем режиме.

Статус: **этап 1** — все команды `router_service_ctl` (кроме `apply-network`),
управление юнитами через D-Bus. Демона (`routerd run`) ещё нет — он появится
на этапе 2 вместе с nftables.
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
переопределяется переменной `ROUTERD_CONFIG_DIR`.
