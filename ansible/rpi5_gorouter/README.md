# volkserg.rpi5_gorouter

Ansible-коллекция с ролью `routerd`: установка и настройка
[routerd](https://github.com/volkserg/rpi5-gorouter) на Raspberry Pi 5
(Raspberry Pi OS / Debian 13, arm64).

## Установка коллекции

Из git-репозитория (публикация на Galaxy не нужна), `requirements.yml`:

```yaml
collections:
  - name: git+https://github.com/volkserg/rpi5-gorouter.git#/ansible/rpi5_gorouter
    version: v0.3.0
```

```bash
ansible-galaxy collection install -r requirements.yml
```

Версия коллекции совпадает с версией routerd: тег `v0.3.0` даёт роль, которая
по умолчанию ставит routerd из релиза `v0.3.0`.

## Пример

`inventory.yml`:

```yaml
all:
  hosts:
    rpi5:
      ansible_host: rpi5.local
      ansible_user: pi
```

`host_vars/rpi5.yml`:

```yaml
routerd_conf:
  IFACE: eth0
  NM_CONN: netplan-eth0
  ROUTER_IP: 192.168.3.1
  RPI5_IP: 192.168.3.2
  LAN_SUBNET: 192.168.3.0/24
  LAN_POOL_START: 192.168.3.100
  LAN_POOL_END: 192.168.3.250
  VPN_MODE: redirect
# Списки — готовыми файлами рядом с инвентарём (по записи на строку,
# комментарии #)…
routerd_vpn_file: "{{ inventory_dir }}/files/vpn_domains.txt"
routerd_dns_override_file: "{{ inventory_dir }}/files/dns_override.txt"
# …или записями прямо здесь (не одновременно с файлом):
# routerd_vpn_entries:
#   - corp.example.com
#   - 10.20.0.0/16
# routerd_dns_overrides:
#   - domain: corp.example.com
#     server: 10.20.0.53
```

`site.yml`:

```yaml
- name: routerd
  hosts: rpi5
  become: true
  roles:
    - volkserg.rpi5_gorouter.routerd
```

```bash
ansible-playbook -i inventory.yml site.yml
```

## Что делает роль

1. Проверяет платформу (Linux arm64, systemd) и что имена `rsc` и
   `router_service_ctl` не заняты другой программой.
2. Ставит недостающее: dnscrypt-proxy (apt) и Pi-hole (официальный установщик,
   сразу на порту из `DNS_UPSTREAM`); задаёт адрес `dnscrypt-proxy.socket`.
   Конфиг dnscrypt-proxy не трогает.
3. Скачивает архив routerd из релиза GitHub с проверкой sha256 (`SHA256SUMS`
   релиза) или берёт `routerd_archive` с машины Ansible; ставит бинарник,
   `rsc` и `router_service_ctl`, `routerd.service`, шаблон
   `routerd-local@.service` (`LOCAL_CLIENTS`), автодополнение bash/zsh.
4. Пишет `router.conf` из `routerd_conf` и, если заданы, списки
   `vpn_domains.txt` и `dns_override.txt` (из файлов или записей). Каждый файл
   проверяется до записи (`rsc check-config --vpn-file …`): с ошибкой он на RPi
   не попадёт.
5. Включает в автозапуск и запускает dnscrypt-proxy, Pi-hole, routerd (после
   отключения питания RPi поднимается сама). Изменение бинарника
   или юнита — перезапуск routerd, изменение конфигов — перечитывание
   (`reload`, без перезапуска).
6. Если адрес RPi в NetworkManager отличается от `router.conf`, применяет его
   (`rsc apply-network`), переподключается и подтверждает (`--confirm`). Если
   RPi после изменения недоступна, NetworkManager через 60 с сам возвращает
   прежние настройки.

Повторный запуск ничего не меняет, если конфигурация та же.

Роль не ставит и не настраивает клиент туннеля (GOST; имя его юнита — ключ
`VPN_SERVICE` в `routerd_conf`, по умолчанию `gost-run.service`) —
см. [docs/TUNNEL.md](../../docs/TUNNEL.md).

## Переменные

| Переменная | По умолчанию | |
|---|---|---|
| `routerd_version` | версия коллекции | релиз routerd на GitHub |
| `routerd_archive` | `""` | архив `routerd-*-linux-arm64.tar.gz` с машины Ansible (`make dist`) вместо релиза |
| `routerd_conf` | `{}` | ключи `router.conf`; не указанные — значения по умолчанию routerd ([описание](../../deploy/config/router.conf)) |
| `routerd_vpn_file` | `null` | файл `vpn_domains.txt` с машины Ansible, копируется как есть |
| `routerd_dns_override_file` | `null` | файл `dns_override.txt` с машины Ansible |
| `routerd_vpn_entries` | `null` | записи `vpn_domains.txt` в инвентаре (вместо файла) |
| `routerd_dns_overrides` | `null` | записи `dns_override.txt` (`domain`, `server`) в инвентаре (вместо файла) |

Список, не заданный ни файлом, ни записями, роль не трогает — его ведут на
RPi командами `rsc add-vpn-domain`, `load-vpn-domains` и т.п.
| `routerd_install_deps` | `true` | ставить Pi-hole и dnscrypt-proxy |
| `routerd_apply_network` | `true` | применять адрес RPi в NetworkManager |
| `routerd_start` | `true` | включать и запускать сервисы |

Типы проверяются по `meta/argument_specs.yml`.

## Проверка

На тестовом стенде репозитория — `testbed/lab.sh test-ansible`: роль во всех
режимах `VPN_MODE`, повторный запуск без изменений, затем сквозные проверки.
`apply-network` на стенде не проверяется (NetworkManager в namespace не работает).
