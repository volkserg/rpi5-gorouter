# rpi5-gorouter

`routerd` — router_service для Raspberry Pi 5 на Go: DHCP, DNS-прокси с
наполнением nft-set, NAT и выборочная маршрутизация трафика к заданным доменам
и подсетям через VPN-туннель (например, к корпоративной сети) на одном порту `eth0`.
Замена bash-версии без вызова внешних утилит в рабочем режиме.

Статус: **этап 0** — разбор конфигов и списков, CLI только на чтение.
Архитектура, решения и план — в [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Сборка

```bash
make test        # юнит-тесты (работают и на macOS)
make build-rpi   # bin/routerd-linux-arm64
```

## Использование

```bash
routerd ctl help
routerd ctl info
routerd ctl check-config
routerd ctl list-vpn-domains
```

Каталог конфигов — `/usr/local/etc/router_service`; для стенда и отладки
переопределяется переменной `ROUTERD_CONFIG_DIR`.
