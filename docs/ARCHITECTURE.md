# routerd — архитектура и план миграции

Go-замена собственной логики bash-проекта rpi5-router:
Raspberry Pi 5 с одним портом `eth0` в одной L2-сети с домашним роутером —
шлюз, DHCP и DNS для LAN, NAT и выборочная маршрутизация трафика к заданным
доменам и подсетям через VPN-туннель (например, к корпоративной сети).

Цель: в рабочем режиме не вызывать внешние утилиты (iptables, ipset, nmcli,
systemctl, sed…). Единственное исключение — `journalctl` в команде `logs`.

## Совместимость

Сохраняются: порты, цепочка DNS, форматы `router.conf`, `vpn_domains.txt`,
`dns_override.txt`, команды `router_service_ctl` (symlink на `routerd`).

```
Клиент → routerd DNS (:53) → Pi-hole (:5353) → dnscrypt-proxy (:5053, DoH) → Cloudflare
TCP к VPN-адресам → nft REDIRECT :1080 → GOST (конфиг ведёт пользователь) → туннель
UDP/443 к VPN-адресам → REJECT icmp port-unreachable (браузер уходит с QUIC на TCP)
```

## Что заменяется

| Сейчас | routerd |
|---|---|
| `source router.conf` | `internal/config`: безопасный разбор KEY=VALUE, валидация, netmask/broadcast |
| Kea DHCP4 | `insomniacslk/dhcp` + свой менеджер аренд (JSON-снапшот) |
| dnsmasq (ipset=, server=, bogus-priv) | DNS-прокси на `miekg/dns`; промежуточно — dnsmasq с `nftset=` |
| iptables + ipset | `google/nftables`, своя таблица `router_service` |
| nmcli | NetworkManager по D-Bus + Checkpoint (автооткат) |
| systemctl / pgrep / ss | `go-systemd` D-Bus, `/proc/net`, счётчики nft |
| `pihole-FTL --config` | точечная правка `pihole.toml` при остановленном FTL |

Остаются внешними: Pi-hole, dnscrypt-proxy, GOST. Кода импорта/миграции
данных из заменяемых сервисов (аренды Kea и т.п.) нет — осознанно.

## Принятые решения

- Один бинарник `routerd`; CLI — `routerd ctl …` или symlink `router_service_ctl`.
- Работает от root с ограниченным `CapabilityBoundingSet`
  (CAP_NET_ADMIN, CAP_NET_BIND_SERVICE; CAP_NET_RAW не нужен — DHCP отвечает broadcast).
- nft-set: `vpn_static` (interval — IP/CIDR из файла, слияние перекрытий)
  и `vpn_dynamic` (timeout — адреса из DNS, `max(TTL, 24h)`, продление при каждом ответе).
- DNS: ECS /32 в Pi-hole (реальные клиенты в статистике); AAAA для VPN-доменов
  отфильтровываются по умолчанию (`FILTER_AAAA=all` — опция); имена `*.lan`
  и PTR из DHCP-аренд, зоны локальные и никогда не форвардятся.
- DHCP: «терпимый authoritative» — NAK для чужой подсети и занятого адреса,
  ACK для свободного адреса из пула (восстановление после потери базы);
  перед OFFER — проверка таблицы соседей ядра.
- Pi-hole: без API; при старте сверяются `dns.port`, `dns.upstreams`,
  `dns.EDNS0ECS`, `dns.revServers`.
- GOST: конфиг под управлением пользователя, routerd только запускает/проверяет юнит.
  Удалённая сторона может быть цепочкой из нескольких узлов — routerd о ней ничего
  не знает, его зона ответственности заканчивается на локальном слушателе GOST или `tun0`.
- Новые ключи `router.conf` допустимы, всегда с дефолтами.

### Режимы VPN

| `VPN_MODE` | GOST на RPi | routerd | Через VPN |
|---|---|---|---|
| `redirect` (по умолчанию) | `red://:VPN_PORT` | nft `redirect` TCP | TCP |
| `tproxy` | `red://…?tproxy=true` + `redu://` | nft `tproxy` TCP+UDP, метка, `ip rule` → `local default dev lo` | TCP, UDP |
| `route` | `tun://` (L3) | метка + `ct mark`, `ip rule` → `default dev VPN_TUN`, MSS clamp, `rp_filter=2` на tun | весь IP |

`tproxy` — целевой режим: TCP завершается на RPi (нет TCP-over-TCP), UDP идёт
через relay. `route` — полная прозрачность ценой TCP-over-TCP.

| Ключ | Значения | По умолчанию |
|---|---|---|
| `VPN_MODE` | `redirect` / `tproxy` / `route` | `redirect` |
| `VPN_FAILOVER` | `closed` — туннель упал, VPN-адреса недоступны; `open` — снять перехват, идти напрямую | `closed` |
| `VPN_PORT` | порт слушателя GOST | `1080` |
| `VPN_TUN` | интерфейс для `route` | `tun0` |
| `QUIC_REJECT` | отклонять UDP/443 к VPN-адресам | `yes` |

Удалённая сторона (под управлением пользователя): GOST `relay` (`bind=true`)
поверх WebSocket за обратным HTTPS-прокси (nginx, TLS, аутентификация клиента);
один сервис покрывает все три режима.

### Исправленные ошибки bash-версии

1. `reload-vpn-domains` терял `dns_override` до полного рестарта.
2. Формат `upstream:port` в `dns_override.txt` не работал (dnsmasq ждёт `#`) — принимаются оба.
3. `send_redirects=0` выставлялся только для `all`, а ядро делает OR с `eth0` — RPi слала клиентам ICMP redirect.
4. `999.1.1.1` считался IP; CIDR не нормализовался (`1.2.3.4/24` → `1.2.3.0/24`).
5. Точка в домене была regex в grep/sed; `echo >>` склеивал строки без завершающего `\n`.
6. dnsmasq запускался без надзора через pid-файл.

## Структура

```
cmd/routerd/          точка входа; argv[0]=router_service_ctl → CLI
internal/config/      router.conf
internal/domain/      нормализация, проверка, суффиксный матчер (семантика dnsmasq)
internal/lists/       vpn_domains.txt, dns_override.txt; flock + атомарная запись
internal/cli/         команды router_service_ctl
internal/services/    systemd по D-Bus, порядок запуска (+ servicestest — подделка для тестов)
internal/sysinfo/     /proc: слушающие порты, sysctl (для status)
— далее по этапам —
internal/firewall/    nftables: сборка ruleset (чистая функция) + применение
internal/dnsproxy/    DNS-прокси
internal/dhcp/        аренды (чистая логика) + сервер
internal/netcfg/      NetworkManager D-Bus / netlink (проверка)
internal/sysctl/      запись /proc/sys
internal/managed/     pihole.toml, dnscrypt-proxy.toml
internal/control/     unix-сокет CLI ↔ демон
internal/daemon/      сборка, sd_notify, SIGHUP
testbed/              стенд (netns в VM)
```

Юнит-тесты — всё, что не трогает ядро (работают и на macOS).
Linux-специфичное — под `//go:build linux`, проверяется на стенде.

## Этапы

Боевая RPi не трогается, пока Go-версия не проверена на стенде целиком, поэтому
этапы не обязаны сосуществовать с bash-стеком на одном устройстве. Точка отката
при переключении боя — юниты bash-версии (отключаются, не удаляются).

| # | routerd берёт на себя | Остаётся старым |
|---|---|---|
| 0 | каркас: config, lists, domain, CLI на чтение (`info`, `list-vpn-domains`, `check-config`) | всё |
| 1 | все команды CLI (кроме apply-network), start/stop/status/logs через D-Bus; правки списков применяются через `ReloadUnit(routerd.service)` (SIGHUP) | init.sh, ipset, dnsmasq, Kea, nmcli |
| 2 | nftables + sysctl (режим `redirect`); dnsmasq на `nftset=` как отдельный юнит | dnsmasq, Kea, nmcli |
| 2a | режимы `tproxy` и `route`, `VPN_FAILOVER` | dnsmasq, Kea, nmcli |
| 3 | DNS-прокси (сначала теневой режим) | Kea, nmcli |
| 4 | DHCP | nmcli |
| 5 | NetworkManager D-Bus, pihole/dnscrypt | — |
| 6 | install.sh, completions, документация | — |

## Тестовый стенд

Без Docker: одна VM Debian 13 arm64 (OrbStack на Mac), внутри — network
namespace, связанные veth-парами:

- `rpi` — routerd, Pi-hole, dnscrypt-proxy, nftables, GOST-клиент;
- `client` — udhcpc, dig, curl;
- `exit` — удалённый узел туннеля: GOST-сервер с той же конфигурацией, что в рабочей
  среде, и тестовый веб-сервер;
- внешний роутер — отдельный namespace (не основной namespace VM, чтобы
  трафик не утёк в настоящий интернет).

Стенд автономный: свой CA, фейковый DoH-сервер, проверка пакетами (tcpdump),
короткие таймауты set. Поднимается и сносится одним скриптом; первым шагом
сверяет nft-опции ядра VM с эталоном боевого ядра (`testbed/kernel-rpi.txt`).
Боевая RPi (ядро 6.12 rpt, 16K-страницы) в тестах не участвует.

Нельзя проверить на стенде: реакцию клиентов на ICMP redirect, Android/Chrome,
IPv6 от реального роутера, производительность, NetworkManager/Checkpoint,
конфликт avahi с Pi-hole на :5353.
