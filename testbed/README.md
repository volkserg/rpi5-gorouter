# Тестовый стенд

Сеть RPi и её окружение в network namespace на Linux-машине arm64
(Debian 13, root): LAN-клиенты, домашний роутер, «интернет» и узлы туннеля.
Стенд ставит пакеты и меняет сетевые настройки, поэтому лучше отдельная VM:
на Mac — OrbStack, на Linux — любая VM arm64 или выделенная машина.

Бинарники собираются на macOS или Linux. Команды ниже — с Mac (VM OrbStack
`routerd-lab`); внутри Linux-машины стенда — то же без `orb -m routerd-lab`.

## Подготовка

```bash
make build-rpi build-lab   # build-lab: dohd и dhcpprobe для стенда
orb -m routerd-lab sudo ./testbed/lab.sh bootstrap      # один раз: пакеты, GOST, nginx
orb -m routerd-lab sudo ./testbed/lab.sh bootstrap-dns  # один раз: Pi-hole, dnscrypt-proxy
orb -m routerd-lab sudo ./testbed/lab.sh check-kernel   # ядро стенда против эталона RPi
orb -m routerd-lab sudo ./testbed/lab.sh up
orb -m routerd-lab sudo ./testbed/lab.sh install        # через install.sh --skip-deps
```

## Проверки

```bash
orb -m routerd-lab sudo ./testbed/lab.sh test           # текущий режим
orb -m routerd-lab sudo ./testbed/lab.sh test-all       # redirect, tproxy, route
orb -m routerd-lab sudo ./testbed/lab.sh test-install   # повторный запуск, --force, отказы
orb -m routerd-lab sudo ./testbed/lab.sh test-ansible   # роль Ansible во всех режимах (после make dist)
orbctl restart routerd-lab && orb -m routerd-lab sudo ./testbed/lab.sh test-boot  # после перезагрузки
orb -m routerd-lab sudo ./testbed/lab.sh test-no-tunnel # без клиента туннеля, затем GOST без перезапуска
orb -m routerd-lab sudo ./testbed/lab.sh test-local-client  # сервис на RPi как клиент LAN, все режимы
orb -m routerd-lab sudo ./testbed/lab.sh test-web       # веб-интерфейс: вход, сессии, CSRF, API демона
orb -m routerd-lab sudo ./testbed/lab.sh test-idle 300  # долгое простаивающее соединение (долго)
orb -m routerd-lab sudo ./testbed/lab.sh mode tproxy open
```

DNS на стенде — как на бою: routerd → Pi-hole (:5353) → dnscrypt-proxy
(:5053, socket activation) → DoH-сервер стенда (`testbed/dohd`, сертификат
от собственного CA стенда) → авторитетный DNS тестовых зон `*.example`.

Туннель — два узла (входной и выходной) с nginx и GOST, как описано в
[docs/TUNNEL.md](../docs/TUNNEL.md); конфиги — в [nodes/](nodes/).

Локальный сервис стенда — `lab-local-app.service`, собранный из примера
[deploy/systemd/local-app.service](../deploy/systemd/local-app.service), в
namespace `lab-app` (`LOCAL_CLIENTS` в `testbed/conf/router.conf`). Его сеть
создаётся из namespace `rpi` через `nsenter --net`: с `NetworkNamespacePath`
systemd дал бы юниту своё пространство монтирования.

## Интеграционные тесты nftables

Root, в отдельном netns:

```bash
GOOS=linux GOARCH=arm64 go test -c -tags integration -o fw.test ./internal/firewall
orb -m routerd-lab sudo ./fw.test -test.v
```

## Веб-интерфейс без стенда

```bash
go run ./testbed/webdemo   # https://127.0.0.1:8443, вход demo / demo
```

Поддельный демон: состояние туннеля меняется каждые 20 с (`-period`), чтобы
были видны все состояния панели. На стенде интерфейс доступен клиентам LAN по
`https://192.168.3.2:8443` (учётная запись — `LAB_WEB_USER`/`LAB_WEB_PASS`
в `lab.sh`).
