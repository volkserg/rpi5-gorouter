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
  (CAP_NET_ADMIN, CAP_NET_BIND_SERVICE; CAP_NET_RAW не нужен — DHCP отвечает
  broadcast; CAP_DAC_OVERRIDE, CAP_CHOWN, CAP_FOWNER — только для правки pihole.toml).
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
- Новые ключи `router.conf` допустимы, всегда с дефолтами: `VPN_MODE`, `VPN_FAILOVER`,
  `VPN_PORT`, `VPN_TUN`, `QUIC_REJECT`, `VPN_DYNAMIC_TIMEOUT` (24h),
  `DNS_UPSTREAM` (`127.0.0.1#5353`), `FILTER_AAAA` (`vpn`), `DNS_ECS` (`yes`),
  `DHCP_ENABLED` (`yes`), `DHCP_LEASE_TIME` (`24h`), `LOCAL_DOMAIN` (`lan`),
  `PIHOLE_MANAGE` (`yes`), `PIHOLE_TOML` (`/etc/pihole/pihole.toml`),
  `DNSCRYPT_ADDR` (`127.0.0.1#5053`).
- `routerd.service` — `Type=notify-reload`: `reload-vpn-domains` завершается,
  когда routerd применил списки; статус применения — в `StatusText` юнита.
- DNS-прокси (этап 3): слушает адрес RPi и `127.0.0.1` на :53 (как dnsmasq с
  `interface=eth0`; `IP_FREEBIND` — можно стартовать до назначения адреса),
  без кэша, до 300 одновременных запросов к upstream, повтор по TCP при TC,
  урезание ответа под размер UDP клиента. Домен из списка (и его поддомены,
  совпадение по имени запроса, как `ipset=` в dnsmasq) — A-записи ответа идут
  в `vpn_dynamic` со сроком max(минимальный TTL, `VPN_DYNAMIC_TIMEOUT`), до 7 суток;
  повторный ответ продлевает срок (удалить+добавить в одной транзакции —
  обновление таймаута на месте умеют не все ядра). `FILTER_AAAA=vpn|all|none`.
  ECS /32 уходит только в `DNS_UPSTREAM` (Pi-hole), не в override-upstream и не
  для loopback-клиентов; клиенту ECS и OPT возвращаются только если он сам их
  прислал. bogus-priv: PTR частных и служебных сетей (RFC 6303, 100.64/10) — NXDOMAIN.
- Модуль требует Go 1.25 (зависимости `miekg/dns`, `insomniacslk/dhcp`).
  Сборка — кросс-компиляция на машине разработчика, бинарник статический;
  на Debian 13 Go 1.25+ есть в trixie-backports.
- DHCP (этап 4): UDP :67 на интерфейсе LAN (SO_BINDTODEVICE), ответы клиентам
  без адреса — broadcast (raw-сокет не нужен). Опции как в Kea: маска, шлюз и DNS =
  RPi, broadcast, домен (`LOCAL_DOMAIN`), срок аренды (`DHCP_LEASE_TIME`, 24h),
  T1 = 1/2, T2 = 7/8 срока. Клиент — по client-id (опция 61), иначе по MAC.
  Выбор адреса: прежний адрес клиента → запрошенный → никогда не выданный →
  давно истёкший; адреса RPi и роутера не выдаются. «Терпимый authoritative»:
  REQUEST адреса чужой подсети, вне пула или занятого — NAK, свободного из
  пула — ACK даже без аренды. Перед выдачей — таблица соседей ядра: адрес,
  на котором живёт устройство с другим MAC (статика), не выдаётся 10 минут;
  DECLINE — так же. Аренды — `/var/lib/routerd/leases.json` (атомарная запись
  при каждом изменении); испорченный файл — старт с пустой базой. Relay-агенты
  не поддерживаются.
- Имена клиентов: hostname (опция 12) → метка DNS (`iPhone (Bob)` → `iphone-bob`),
  повторы — `-2`, `-3`; имя закреплено за клиентом, пока его запись свежая
  (истекла не раньше срока аренды назад). DNS-прокси отвечает на `имя.lan` и PTR
  адресов из аренд сам, никогда не пересылая в Pi-hole (тот ответил бы на `.lan`
  NXDOMAIN); чужие имена в `.lan` — NXDOMAIN.
- Pi-hole (этап 5, `PIHOLE_MANAGE=yes`): при старте и SIGHUP routerd сверяет в
  `pihole.toml` ключи цепочки — `dns.port` (порт из `DNS_UPSTREAM`),
  `dns.upstreams` (`DNSCRYPT_ADDR`), `dns.EDNS0ECS` (`DNS_ECS`) и свою запись
  `dns.revServers` (`true,<LAN>,127.0.0.1#53,<LOCAL_DOMAIN>` — Pi-hole спрашивает
  имена клиентов у routerd; чужие записи сохраняются). При расхождении — в
  фоне, после готовности routerd: дождаться, пока FTL ответит на DNS (только
  что запущенный FTL не реагирует на SIGTERM и через минуту добивается
  SIGKILL), остановить его по D-Bus, точечно заменить строки (многострочные
  массивы FTL, хвостовые комментарии; права и владелец сохраняются), запустить.
  Для этого юниту нужны `CAP_DAC_OVERRIDE`, `CAP_CHOWN`, `CAP_FOWNER` и
  `ReadWritePaths=/etc/pihole`. Состояние — в `status`.
- dnscrypt-proxy: конфиг ведёт пользователь; routerd только проверяет по D-Bus,
  что `dnscrypt-proxy.socket` слушает `DNSCRYPT_ADDR`, и показывает это в `status`.
- `apply-network` (этап 5): как `nmcli con mod … && nmcli con up` в bash-версии,
  но через D-Bus NetworkManager. Подключение — `NM_CONN`, иначе ethernet-подключение
  `IFACE`. Перед изменением — `CheckpointCreate` на устройство с откатом через 60 с;
  профиль обновляется (`Update2`, на диск — для netplan-профиля NM пишет и YAML),
  устаревший ключ `addresses` удаляется (иначе NM игнорирует `address-data` и
  `gateway`), DNS — ключом `dns`; затем активация и ожидание состояния
  «активировано». Ошибка — немедленный откат. Успех — нужно подтвердить
  `apply-network --confirm` за 60 с, иначе NetworkManager вернёт прежние
  настройки сам (защита от потери доступа к RPi). `--rollback` — откат сразу,
  `--dry-run` — показать изменения. После применения routerd перечитывает
  конфиг (адрес RPi нужен DNS и DHCP). На стенде не проверяется (NetworkManager
  в namespace не работает) — только юнит-тесты с подделкой D-Bus.
- Перезагрузка сохраняет адреса в `vpn_dynamic`; если параметры set'ов изменились
  (например, таймаут), таблица пересоздаётся — не все ядра обновляют их на месте.

### Режимы VPN

| `VPN_MODE` | GOST на RPi | routerd | Через VPN |
|---|---|---|---|
| `redirect` (по умолчанию) | `red://:VPN_PORT` | nft `redirect` TCP | TCP |
| `tproxy` | `red://…?tproxy=true` + `redu://` | nft `tproxy` TCP+UDP, метка, `ip rule` → `local default dev lo` | TCP, UDP |
| `route` | `tun://` (L3) | метка + `ct mark`, `ip rule` → `default dev VPN_TUN`, MSS clamp, `rp_filter=2` на tun | весь IP |

`tproxy` — целевой режим: TCP завершается на RPi (нет TCP-over-TCP), UDP идёт
через relay. `route` — полная прозрачность ценой TCP-over-TCP.

Детали реализации:

- метка `0x52`, таблица маршрутизации `152`, `ip rule` с приоритетом 1520;
- `tproxy`: если слушателя нет, `tproxy` не срабатывает — отдельное правило всё
  равно помечает пакет, и он доставляется локально (RST / port unreachable),
  а не уходит напрямую; UDP/443 при `QUIC_REJECT=yes` не перехватывается,
  его отклоняет forward-цепочка;
- `route`: решение принимается на первом пакете и хранится в `ct mark`
  (истечение записи в `vpn_dynamic` не рвёт соединение); метка восстанавливается
  только для пакетов из LAN — иначе ответы из туннеля ушли бы обратно в него;
  `unreachable default metric 4096` в таблице 152 — туннель упал, трафик не
  утекает; MSS clamp по MTU маршрута; `rp_filter=2` на интерфейсе туннеля;
- доступность туннеля проверяется локально раз в 2 с: слушает ли порт GOST
  (`redirect`, `tproxy`) или поднят ли интерфейс (`route`). Связь GOST с
  удалённым узлом routerd не проверяет;
- `VPN_FAILOVER=open`: туннель недоступен — правила перехвата и `ip rule`
  снимаются (set'ы, NAT и QUIC-reject остаются), вернулся — восстанавливаются.
  Состояние видно в `router_service_ctl status` (StatusText routerd).

GOST-клиенту в режимах `tproxy` и `route` нужен `CAP_NET_ADMIN`
(`IP_TRANSPARENT`, создание tun): юнит GOST ведёт пользователь.

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
internal/firewall/    nftables через netlink: таблица router_service, set'ы, правила (Linux)
internal/sysctl/      запись /proc/sys (ip_forward, redirects — в т.ч. для интерфейса)
internal/dnsproxy/    DNS-прокси на :53 (miekg/dns): override, nft-set по TTL, ECS, AAAA, bogus-priv,
                      локальная зона *.lan
internal/dhcp/        DHCP: пул и аренды (чистая логика), обработка сообщений, JSON-хранилище,
                      зона имён; сокет :67 и проверка ARP — Linux
internal/routing/     policy routing через netlink: ip rule, таблица 152 (Linux)
internal/daemon/      routerd run: применение, sd_notify (notify-reload), SIGHUP,
                      слежение за туннелем, VPN_FAILOVER, очистка
deploy/systemd/       routerd.service
testbed/              стенд: lab.sh, эталон ядра RPi, конфиги стенда
internal/pihole/      сверка и точечная правка ключей цепочки в pihole.toml
internal/netcfg/      apply-network: NetworkManager по D-Bus + Checkpoint
— далее по этапам —
internal/control/     unix-сокет CLI ↔ демон
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
| 2 | демон `routerd run`, nftables + sysctl (режим `redirect`), dnsmasq на `nftset=` как юнит `routerd-dnsmasq`; стенд и сквозные проверки | dnsmasq, Kea, nmcli |
| 2a | режимы `tproxy` и `route`, `VPN_FAILOVER`, policy routing (`internal/routing`); стенд — все режимы × closed/open | dnsmasq, Kea, nmcli |
| 3 | DNS-прокси на Go вместо dnsmasq; `routerd-dnsmasq` и пакет `internal/dnsmasq` удалены. Теневой режим не понадобился — боевая RPi до проверки всего на стенде не трогается | Kea, nmcli |
| 4 | DHCP вместо Kea (`insomniacslk/dhcp`), имена `*.lan` и PTR из аренд; клиент стенда получает адрес по DHCP | nmcli |
| 5 | `apply-network` (NetworkManager D-Bus + Checkpoint), сверка `pihole.toml`, проверка `dnscrypt-proxy.socket` | — |
| 6 | install.sh, completions, документация | — |

## Тестовый стенд

Без Docker: одна VM Debian 13 arm64 (OrbStack на Mac), внутри — network
namespace, связанные veth-парами:

- `rpi` — routerd, Pi-hole, dnscrypt-proxy, nftables, GOST-клиент;
- `client` — получает адрес по DHCP от routerd (busybox udhcpc), dig, curl;
  `client2` — устройство со статикой для проверки конфликтов адресов;
  REQUEST в состоянии INIT-REBOOT и RELEASE отправляет `testbed/dhcpprobe`
  (busybox udhcpc их по запросу не шлёт);
- `exit` — удалённый узел туннеля: GOST-сервер с той же конфигурацией, что в рабочей
  среде, и тестовый веб-сервер;
- внешний роутер — отдельный namespace (не основной namespace VM, чтобы
  трафик не утёк в настоящий интернет).

Стенд автономный, проверка пакетами (tcpdump) и журналами сервисов,
короткие таймауты set. Поднимается и сносится одним скриптом; первым шагом
сверяет nft-опции ядра VM с эталоном боевого ядра (`testbed/kernel-rpi.txt`).

DNS-цепочка стенда повторяет боевую: настоящий Pi-hole v6 (ставится
официальным установщиком в автоматическом режиме — нужен заранее созданный
`pihole.toml`) на :5353 и dnscrypt-proxy из Debian (socket activation на
`127.0.0.1:5053`) в namespace `rpi`; единственный сервер dnscrypt-proxy —
DoH-сервер стенда `testbed/dohd` (doh.example, 203.0.113.55), закреплённый в
DNS stamp по хэшу собственного CA стенда; за ним — авторитетный DNS тестовых
зон (203.0.113.54), отвечающий NXDOMAIN на всё прочее (иначе dnscrypt-proxy
отбраковывает сервер как «lying resolver»). Тестовые зоны — `*.example`:
на `.test` Pi-hole отвечает сам (RFC 6761), не спрашивая upstream.

Важно для этапа 4: Pi-hole так же локально обслуживает `lan`, `internal`,
`home.arpa`, `pi.hole` (`local=/lan/`), поэтому имена `*.lan` из DHCP-аренд
routerd должен отдавать сам, до пересылки в Pi-hole.
Боевая RPi (ядро 6.12 rpt, 16K-страницы) в тестах не участвует.

Пока не повторяет бой: туннель — `relay+ws` без TLS и nginx (ждёт разбора
боевых конфигов удалённой стороны).

Нельзя проверить на стенде: реакцию клиентов на ICMP redirect, Android/Chrome,
IPv6 от реального роутера, производительность, NetworkManager/Checkpoint,
конфликт avahi с Pi-hole на :5353.
