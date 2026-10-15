# rpi5-gorouter

`routerd` — шлюз LAN для Raspberry Pi 5 с одним портом `eth0`: DHCP, DNS,
NAT и выборочная маршрутизация трафика к заданным доменам и подсетям через
VPN-туннель (например, к корпоративной сети). Один статический бинарник на
Go; в рабочем режиме не вызывает внешние утилиты — ядро, systemd и
NetworkManager управляются через netlink и D-Bus.

Возможности:

- **Межсетевой экран и маршрутизация** — nftables и policy routing через
  netlink; три режима отправки трафика в туннель (`redirect`, `tproxy`,
  `route`), поведение при недоступном туннеле — `VPN_FAILOVER`.
- **DNS-прокси на :53** — адреса доменов из списка попадают в nft-set со
  сроком max(TTL, `VPN_DYNAMIC_TIMEOUT`); ECS для Pi-hole, фильтр AAAA,
  отдельные upstream для заданных доменов.
- **DHCP-сервер** — аренды в `/var/lib/routerd/leases.json`, имена клиентов
  в зоне `*.lan` и PTR.
- **Цепочка DNS** routerd → Pi-hole → dnscrypt-proxy: routerd сверяет и
  исправляет ключи цепочки в `pihole.toml`.
- **`apply-network`** — адрес RPi в NetworkManager по D-Bus с автооткатом.
- **CLI `router_service_ctl`**, `install.sh`, автодополнение bash/zsh.

Архитектура и принятые решения — [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md),
настройка туннеля (GOST на RPi и удалённых узлах) — [docs/TUNNEL.md](docs/TUNNEL.md).

## Сборка

```bash
make test        # юнит-тесты (macOS или Linux)
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
слушает другой адрес. Если `/usr/local/bin/router_service_ctl` — обычный файл,
а не symlink на routerd, установщик останавливается и ничего не меняет.

После установки:
1. Указать свой сервер в `gost-run.service` (`sudo systemctl edit --full gost-run`)
   под `VPN_MODE` — варианты слушателя в комментарии юнита, сервер — [docs/TUNNEL.md](docs/TUNNEL.md).
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

Network namespace на Linux-машине arm64 (Debian 13, root) — см. `testbed/lab.sh`.
Стенд ставит пакеты и меняет сетевые настройки, поэтому лучше отдельная VM:
на Mac — OrbStack, на Linux — любая VM arm64 или выделенная машина. Бинарники
собираются на macOS или Linux. Команды с Mac (VM OrbStack `routerd-lab`);
внутри Linux-машины стенда — то же без `orb -m routerd-lab`:

```bash
make build-rpi build-lab   # build-lab: dohd и dhcpprobe для стенда
orb -m routerd-lab sudo ./testbed/lab.sh bootstrap      # один раз: пакеты, GOST, nginx
orb -m routerd-lab sudo ./testbed/lab.sh bootstrap-dns  # один раз: Pi-hole, dnscrypt-proxy
orb -m routerd-lab sudo ./testbed/lab.sh check-kernel   # ядро стенда против эталона RPi
orb -m routerd-lab sudo ./testbed/lab.sh up
orb -m routerd-lab sudo ./testbed/lab.sh install        # через install.sh --skip-deps
orb -m routerd-lab sudo ./testbed/lab.sh test           # текущий режим
orb -m routerd-lab sudo ./testbed/lab.sh test-all       # redirect, tproxy, route
orb -m routerd-lab sudo ./testbed/lab.sh test-install   # повторный запуск, --force, отказы
orb -m routerd-lab sudo ./testbed/lab.sh test-idle 300  # долгое простаивающее соединение (отдельно: долго)
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
