# rpi5-gorouter

**routerd** превращает Raspberry Pi 5 в шлюз локальной сети с выборочной
маршрутизацией: трафик к ресурсам корпоративной сети идёт через VPN-туннель,
всё остальное — напрямую через обычный роутер. Устройствам в сети не нужен
свой VPN-клиент: достаточно получить адрес по DHCP.

```
            DHCP, DNS, шлюз
устройства LAN ───────────────▶ RPi 5 (routerd) ──────────▶ роутер ──▶ интернет
                                      │
                                      └─ corp.example.com, 10.20.0.0/16
                                         ═══ VPN-туннель ═══▶ корпоративная сеть
```

Один статический бинарник на Go. В рабочем режиме не вызывает внешних утилит:
ядро, systemd и NetworkManager управляются напрямую через netlink и D-Bus.

## Возможности

- **Выборочная маршрутизация** — список доменов, IP и подсетей; адреса доменов
  попадают в список по DNS-ответам. Три режима отправки в туннель (`redirect`,
  `tproxy`, `route`); если туннель недоступен,
  трафик к адресам из списка не пропускается или идёт напрямую.
- **DNS** — прокси на :53 перед Pi-hole и dnscrypt-proxy; отдельные DNS-серверы
  для заданных доменов (например, внутренний DNS компании).
- **DHCP** — сервер с именами клиентов в зоне `*.lan`.
- **Безопасное изменение сети** — адрес RPi применяется через NetworkManager с
  автоматическим откатом, если доступ пропал.
- **Устойчивость** — запуск после отключения питания, работа без туннеля,
  изменение списков без перезапуска.
- **Сервисы на самой RPi** — программа на RPi может ходить в сеть как
  устройство LAN: со списками, туннелем и DNS routerd.
- **Веб-интерфейс** — панель по HTTPS: состояние сервисов и туннеля с
  внешним адресом выхода, обращения устройств (успех, таймаут, маршрут) с
  подсказками, что направить в туннель, проверка ресурса напрямую и через
  туннель, устройства, список VPN (импорт и экспорт), редактор DNS override,
  журнал; вход по логину и паролю.
- **Установка** — `install.sh` или роль Ansible; команда управления `rsc`
  с автодополнением bash/zsh.

## Требования

- Raspberry Pi 5, Raspberry Pi OS / Debian 13 (arm64), NetworkManager.
- Подключение к LAN одним портом `eth0`; статический адрес RPi задаёт
  `rsc apply-network` из `router.conf`.
- Сервер VPN-туннеля (GOST) — для отправки трафика в корпоративную сеть;
  routerd работает и без него, см. [docs/TUNNEL.md](docs/TUNNEL.md).

Pi-hole и dnscrypt-proxy ставятся автоматически, если их нет.

## Установка

### На RPi: install.sh

Скачать релиз ([все релизы](https://github.com/volkserg/rpi5-gorouter/releases)),
проверить и установить:

```bash
V=v0.4.2
curl -fLO https://github.com/volkserg/rpi5-gorouter/releases/download/$V/routerd-$V-linux-arm64.tar.gz
curl -fLO https://github.com/volkserg/rpi5-gorouter/releases/download/$V/SHA256SUMS
sha256sum -c SHA256SUMS
tar -xzf routerd-$V-linux-arm64.tar.gz
cd routerd-$V-linux-arm64 && sudo ./install.sh
```

Установщик ставит недостающие Pi-hole и dnscrypt-proxy, routerd с командой
`rsc`, юнит systemd и примеры конфигов, проверяет конфигурацию и запускает
сервисы. Обновление — то же самое с новой версией в `V`: конфиги не
перезаписываются.

<details>
<summary>Параметры install.sh</summary>

| Параметр | |
|---|---|
| `--force` | заменить конфиги примерами, прежние — в `*.bak.<время>` |
| `--no-start` | только установить, не запускать |
| `--skip-deps` | не ставить Pi-hole и dnscrypt-proxy |
| `ROUTERD_BIN=<путь>` | взять бинарник не из `bin/` рядом со скриптом |

Конфиг dnscrypt-proxy установщик не меняет — только направляет
`dnscrypt-proxy.socket` на `DNSCRYPT_ADDR`. Если `rsc` или
`router_service_ctl` в `/usr/local/bin` — чужой файл, установщик
останавливается, ничего не изменив.

</details>

### С рабочей машины: Ansible

Коллекция `volkserg.rpi5_gorouter` ставится из git; конфиг и списки задаются
переменными инвентаря, routerd берётся из релиза той же версии:

```yaml
# requirements.yml
collections:
  - name: git+https://github.com/volkserg/rpi5-gorouter.git#/ansible/rpi5_gorouter
    version: v0.4.2
```

Пример инвентаря и все переменные — в [README коллекции](ansible/rpi5_gorouter/README.md).

### После установки

1. Задать адреса сети в `/usr/local/etc/router_service/router.conf` и
   проверить: `sudo rsc check-config`.
2. Применить адрес RPi: `sudo rsc apply-network`, проверить доступ и в
   течение 60 с подтвердить `sudo rsc apply-network --confirm` — иначе
   NetworkManager вернёт прежние настройки.
3. Выключить DHCP на роутере (если routerd раздаёт адреса, `DHCP_ENABLED=yes`).
4. Настроить клиент туннеля — [docs/TUNNEL.md](docs/TUNNEL.md). До этого
   работают DHCP, DNS и выход в интернет; адреса из списка недоступны
   (`VPN_FAILOVER=closed`) или идут напрямую (`open`). Запущенный клиент
   routerd подхватывает сам, без перезапуска.

## Настройка

Конфиги лежат в `/usr/local/etc/router_service`:

| Файл | Содержимое |
|---|---|
| `router.conf` | адреса сети, DHCP, режим туннеля, DNS — [все ключи с описанием](deploy/config/router.conf) |
| `vpn_domains.txt` | домены, IP и подсети, трафик к которым идёт в туннель |
| `dns_override.txt` | домены со своим DNS-сервером: `corp.example.com 10.20.0.53` |

Основные ключи `router.conf`:

```ini
IFACE=eth0                  # интерфейс LAN
ROUTER_IP=192.168.3.1       # роутер — шлюз самой RPi
RPI5_IP=192.168.3.2         # RPi — шлюз и DNS для устройств LAN
LAN_POOL_START=192.168.3.100
LAN_POOL_END=192.168.3.250
#VPN_MODE=redirect          # redirect (TCP) | tproxy (TCP+UDP) | route (весь IP)
#VPN_FAILOVER=closed        # без туннеля: closed — не пускать, open — напрямую
```

Изменения применяются без перезапуска: `sudo rsc reload-vpn-domains`
(после смены `VPN_MODE` — `sudo rsc restart`).
Файл можно проверить до замены: `rsc check-config --vpn-file <файл>`
(также `--router-conf`, `--override-file`).

Списки ведутся **либо** на RPi командами `rsc`, **либо** ролью Ansible: файл,
заданный в инвентаре, роль перезаписывает при каждом запуске.

### Сервисы на самой RPi

Собственный трафик RPi идёт мимо правил routerd. Чтобы программа на RPi
работала как устройство LAN, ей выделяется свой network namespace:

1. В `router.conf` — имя и подсеть: `LOCAL_CLIENTS="app:10.99.0.0/30"`, затем
   `sudo rsc reload-vpn-domains`.
2. Юнит программы — по образцу
   [deploy/systemd/local-app.service](deploy/systemd/local-app.service):
   четыре строки подключают его к сети `routerd-local@app.service`
   (адрес `10.99.0.2`, шлюз и DNS — RPi).

`rsc status` показывает состояние сети каждого сервиса.

### Веб-интерфейс

1. В `router.conf` — `WEB_UI=yes` (порт — `WEB_PORT`, по умолчанию 8443),
   затем `sudo ./install.sh` или роль: они включают `routerd-web.service`.
2. Пользователь: `sudo routerd web passwd admin` (также `deluser`, `users`;
   в роли — `routerd_web_users`).
3. Открыть `https://192.168.3.2:8443` (или `https://<имя RPi>.local:8443`) и
   принять самоподписанный сертификат.

Вход с «запомнить устройство» действует 30 дней; смена пароля завершает все
сессии пользователя. Сервис работает от отдельного пользователя без прав и
передаёт запросы демону через локальный сокет.

Раздел «Обращения» показывает, к каким ресурсам обращаются устройства, были
ли ответы и каким маршрутом шёл трафик. История хранится только на RPi
(`/var/lib/routerd/history`), срок — `ACCESS_HISTORY_DAYS` (по умолчанию 7
суток, `0` — не учитывать).

## Использование

```bash
rsc status                                # состояние сервисов и туннеля
rsc list-vpn-domains
sudo rsc add-vpn-domain corp.example.com  # remove-vpn-domain — удалить
sudo rsc add-vpn-ip 10.20.0.0/16          # remove-vpn-ip — удалить
sudo rsc load-vpn-domains domains.txt     # добавить из файла (load-vpn-ips — для IP)
sudo rsc restart
rsc logs
rsc help                                  # все команды
```

`rsc` — короткое имя `routerd`; `routerd <команда>` и `router_service_ctl
<команда>` работают так же. `rsc stop` останавливает routerd и клиент
туннеля, Pi-hole и dnscrypt-proxy продолжают работать.

## Документация

- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) — устройство и принятые решения.
- [docs/TUNNEL.md](docs/TUNNEL.md) — туннель: GOST на RPi и на удалённых узлах.
- [ansible/rpi5_gorouter](ansible/rpi5_gorouter/README.md) — роль Ansible.
- [testbed/](testbed/README.md) — тестовый стенд в network namespace.

## Разработка

```bash
make test        # юнит-тесты (macOS или Linux)
make build-rpi   # bin/routerd-linux-arm64
make dist        # архив для установки
make release     # релиз на GitHub по тегу vX.Y.Z
```

Сквозные проверки всех режимов, установки и роли — на [стенде](testbed/README.md).

## Лицензия

[MIT](LICENSE)
