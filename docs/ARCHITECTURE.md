# routerd — архитектура

Raspberry Pi 5 с одним портом `eth0` в одной L2-сети с домашним роутером —
шлюз, DHCP и DNS для LAN, NAT и выборочная маршрутизация трафика к заданным
доменам и подсетям через VPN-туннель (например, к корпоративной сети).

Принцип: в рабочем режиме routerd не вызывает внешние утилиты — ядро, systemd
и NetworkManager управляются напрямую (netlink, D-Bus, `/proc`). Единственное
исключение — `journalctl` в команде `logs`.

## Потоки трафика

```
Клиент → routerd DNS (:53) → Pi-hole (:5353) → dnscrypt-proxy (:5053, DoH) → DoH-сервер
TCP к VPN-адресам → nft REDIRECT :1080 → GOST (конфиг ведёт пользователь) → туннель
UDP/443 к VPN-адресам → REJECT icmp port-unreachable (браузер уходит с QUIC на TCP)
```

Интерфейсы: `router.conf`, `vpn_domains.txt`, `dns_override.txt` в
`/usr/local/etc/router_service`, команды управления `rsc` (symlink на `routerd`, второе имя — `router_service_ctl`).

## Компоненты

| Задача | Реализация |
|---|---|
| Конфиг | `internal/config`: безопасный разбор KEY=VALUE, валидация, netmask/broadcast |
| DHCP | `insomniacslk/dhcp` + свой менеджер аренд (JSON-снапшот) |
| DNS | DNS-прокси на `miekg/dns`: override-upstream, nft-set по ответам, ECS, локальная зона |
| Межсетевой экран | `google/nftables`, своя таблица `router_service` |
| Адрес RPi | NetworkManager по D-Bus + Checkpoint (автооткат) |
| Сервисы | systemd по D-Bus (`go-systemd`), состояние — `/proc/net`, счётчики nft |
| Pi-hole | точечная правка `pihole.toml` при остановленном FTL |
| Веб-интерфейс | `net/http` + HTML/JS без сборки (`embed`), API демона — JSON через unix-сокет |

Внешние компоненты, которыми routerd управляет: Pi-hole,
dnscrypt-proxy, GOST.

## Принятые решения

- Один бинарник `routerd`; команды управления — `rsc <команда>` (symlink),
  `routerd <команда>` или `router_service_ctl <команда>`.
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
- Все ключи `router.conf` имеют значения по умолчанию: адресация LAN (`IFACE`,
  `ROUTER_IP`, `RPI5_IP`, `LAN_SUBNET`, пул, `DNS1`/`DNS2`, `NM_CONN`) и ключи
  `VPN_MODE`, `VPN_FAILOVER`, `VPN_PORT`, `VPN_TUN`, `VPN_SERVICE`
  (`gost-run.service`), `QUIC_REJECT`,
  `VPN_DYNAMIC_TIMEOUT` (24h), `DNS_UPSTREAM` (`127.0.0.1#5353`), `FILTER_AAAA`
  (`vpn`), `DNS_ECS` (`yes`), `DHCP_ENABLED` (`yes`), `DHCP_LEASE_TIME` (`24h`),
  `LOCAL_DOMAIN` (`lan`), `PIHOLE_MANAGE` (`yes`), `PIHOLE_TOML`
  (`/etc/pihole/pihole.toml`), `DNSCRYPT_ADDR` (`127.0.0.1#5053`). Описание —
  [deploy/config/router.conf](../deploy/config/router.conf).
- `routerd.service` — `Type=notify-reload`: `reload-vpn-domains` завершается,
  когда routerd применил списки; статус применения — в `StatusText` юнита.
- DNS-прокси: слушает адрес RPi и `127.0.0.1` на :53 (как dnsmasq с
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
  Сборка — кросс-компиляция на macOS или Linux, бинарник статический;
  на Debian 13 Go 1.25+ есть в trixie-backports.
- DHCP: UDP :67 на интерфейсе LAN (SO_BINDTODEVICE), ответы клиентам
  без адреса — broadcast (raw-сокет не нужен). Опции: маска, шлюз и DNS =
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
  адресов из аренд сам, никогда не пересылая в Pi-hole: тот обслуживает `lan`,
  `internal`, `home.arpa` локально и ответил бы NXDOMAIN; чужие имена в `.lan` —
  NXDOMAIN.
- Pi-hole (`PIHOLE_MANAGE=yes`): при старте и SIGHUP routerd сверяет в
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
- `apply-network`: по аналогии с `nmcli con mod … && nmcli con up`, но через
  D-Bus NetworkManager. Подключение — `NM_CONN`, иначе ethernet-подключение
  `IFACE`. Перед изменением — `CheckpointCreate` на устройство с откатом через 60 с;
  профиль обновляется только в памяти NM (`Update2` с `IN_MEMORY`; на диске —
  прежний), `--confirm` записывает его на диск (`Save`; для netplan-профиля NM
  пишет и YAML) и только потом снимает checkpoint — перезагрузка или отключение
  питания до подтверждения возвращают прежние настройки,
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
- Смена списка применяется сразу и к адресам, которые клиенты уже держат в
  своих DNS-кэшах: DNS-прокси помнит недавние ответы на A-запросы (любые имена,
  до истечения TTL, не больше 20 000 имён, только в памяти). При `reload`
  адреса имён, попавших в список, сразу добавляются в `vpn_dynamic`, а имён,
  ушедших из него, — убираются, если тот же адрес не нужен имени, оставшемуся
  в списке. Без этого добавленный домен шёл бы напрямую, пока клиент не спросит
  DNS заново (до TTL записи), а удалённый — в туннель до `VPN_DYNAMIC_TIMEOUT`.
  После пересоздания таблицы адреса из недавних ответов возвращаются в set.
- Отключение питания: routerd, Pi-hole и `dnscrypt-proxy.socket` в автозапуске;
  `routerd.service` и пример `gost-run.service` — `Restart=on-failure` без
  ограничения частоты запусков (`StartLimitIntervalSec=0`). routerd слушает DNS
  с `IP_FREEBIND` (стартует до назначения адреса) и при старте заново строит
  таблицу nftables. Аренды, списки и `pihole.toml` заменяются атомарно:
  временный файл, `fsync`, `rename`, `fsync` каталога. Если после правки
  `pihole.toml` systemd отклонил запуск Pi-hole (частые перезапуски), routerd
  повторяет запуск — остановленный Pi-hole означал бы отсутствие DNS в LAN.
- `send_redirects=0` выставляется и для `all`, и для `IFACE`: ядро объединяет
  их по OR, и иначе RPi рассылала бы клиентам ICMP redirect на роутер.
- В режиме route routerd следит не только за тем, поднят ли интерфейс туннеля,
  но и за его индексом: GOST, перезапущенный быстрее интервала проверки (2 с),
  пересоздаёт tun, ядро удаляет маршрут в старый интерфейс, и его нужно вернуть.

### Локальные сервисы (LOCAL_CLIENTS)

Трафик процессов самой RPi проходит цепочку `output`, а правила routerd
привязаны к входному интерфейсу (`iifname`). Чтобы программа на RPi ходила в
сеть как устройство LAN, она получает свой network namespace:

- `routerd-local@<имя>.service` (oneshot, `routerd local-client up|down`)
  создаёт `/run/netns/<имя>`, veth-пару `rc-<имя>` ↔ `eth0` с адресами из
  `LOCAL_CLIENTS` (первый адрес подсети — RPi, второй — сервис), маршрут по
  умолчанию через RPi и `/etc/netns/<имя>/resolv.conf` с DNS routerd
  (`RPI5_IP`). Существующий namespace переиспользуется, veth пересоздаётся.
- Это отдельный юнит, а не демон: создание namespace требует `CAP_SYS_ADMIN`
  и общего с системой пространства монтирования (namespace закрепляется
  bind-монтированием в `/run/netns`), а демон работает в урезанном юните.
  Поэтому в шаблоне нет `ProtectSystem`, `PrivateTmp` и `NetworkNamespacePath`
  — с ними systemd дал бы юниту своё пространство монтирования.
- routerd повторяет правила LAN для каждого `rc-<имя>` (перехват во всех
  режимах, отклонение QUIC) и добавляет masquerade для подсети сервиса.
  Правила ставятся по имени интерфейса, поэтому порядок запуска юнитов не
  важен; перезапуск routerd не трогает namespace и работающий сервис.
- Юнит сервиса подключается строками `Requires=`/`After=` на
  `routerd-local@<имя>`, `NetworkNamespacePath=` и `BindReadOnlyPaths=` для
  resolv.conf ([пример](../deploy/systemd/local-app.service)): остановка сети
  останавливает и сервис.
- `check-config` отклоняет подсеть, пересекающуюся с LAN, другими сервисами и
  подсетями из `vpn_domains.txt` (трафик сервиса к его шлюзу ушёл бы в туннель).

### Веб-интерфейс

- Два процесса: демон (root, урезанный юнит) открывает API в
  `/run/routerd/api.sock` (0660, группа `routerd-web`), а `routerd-web.service`
  (`routerd web serve`, пользователь `routerd-web`, без capabilities, жёсткая
  песочница systemd) раздаёт страницы и проверяет вход. Все действия выполняет
  демон; ошибка в веб-части не затрагивает маршрутизацию, а остановленный
  демон интерфейс показывает как «routerd не отвечает».
- API демона не проверяет пользователей: доступ — по правам на сокет.
  Веб-сервис передаёт логин в заголовке `X-Routerd-User` (для журнала).
- Списки API правит теми же функциями и под той же блокировкой (`flock`),
  что `rsc`, с теми же проверками, что `check-config` (в том числе пересечение
  подсетей с `LOCAL_CLIENTS`), и применяет их в основном цикле демона — как
  перечитывание по SIGHUP, без гонок с ним. Импорт «заменить» записывает файл
  как загружен (с комментариями) и не принимает файл с битыми строками;
  «добавить» пропускает битые строки. Предпросмотр импорта ничего не меняет.
- HTTPS на `RPI5_IP:WEB_PORT` (80/443 заняты Pi-hole). Сертификат
  самоподписанный (ECDSA P-256, 10 лет), перевыпускается, только если сменился
  адрес или имя RPi или срок подходит к концу.
- Пользователи — `web_users` в каталоге конфигов (`логин:pbkdf2-sha256$…`,
  root:routerd-web 0640), только из терминала (`routerd web passwd`). Сессия —
  подписанная HMAC cookie без хранения на сервере; в подпись входит хеш пароля,
  поэтому смена пароля завершает сессии. Cookie `Secure`, `HttpOnly`,
  `SameSite=Strict`; 12 ч или 30 дней («запомнить устройство»).
- Вход по MAC-адресу отклонён: MAC в LAN подделывается, а телефоны используют
  случайные MAC.
- Защита: изменяющие запросы — только с заголовком `X-Routerd-CSRF` и своим
  `Origin`; CSP без inline-скриптов и стилей; после 5 неудачных входов с адреса
  — пауза от 1 до 15 минут; не больше двух проверок пароля одновременно.

### Режимы VPN

| `VPN_MODE` | GOST на RPi | routerd | Через VPN |
|---|---|---|---|
| `redirect` (по умолчанию) | `red://:VPN_PORT` | nft `redirect` TCP | TCP |
| `tproxy` | `red://…?tproxy=true` + `redu://` | nft `tproxy` TCP+UDP, метка, `ip rule` → `local default dev lo` | TCP, UDP |
| `route` | `tun://` (L3) | метка + `ct mark`, `ip rule` → `default dev VPN_TUN`, MSS clamp, `rp_filter=2` на tun | весь IP |

`tproxy` — целевой режим: TCP завершается на RPi (нет TCP-over-TCP), UDP идёт
поверх HTTP-туннеля GOST (`udp=true`). `route` — полная прозрачность ценой TCP-over-TCP.

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
  Состояние видно в `rsc status` (StatusText routerd).

GOST-клиенту в режимах `tproxy` и `route` нужен `CAP_NET_ADMIN`
(`IP_TRANSPARENT`, создание tun), в `tproxy` ещё `CAP_NET_BIND_SERVICE`
(ответ на UDP с исходного порта сервера): юнит GOST (`VPN_SERVICE`) ведёт пользователь, пример —
`deploy/systemd/gost-run.service`.

| Ключ | Значения | По умолчанию |
|---|---|---|
| `VPN_MODE` | `redirect` / `tproxy` / `route` | `redirect` |
| `VPN_FAILOVER` | `closed` — туннель упал, VPN-адреса недоступны; `open` — снять перехват, идти напрямую | `closed` |
| `VPN_PORT` | порт слушателя GOST | `1080` |
| `VPN_TUN` | интерфейс для `route` | `tun0` |
| `VPN_SERVICE` | systemd-юнит клиента туннеля для `rsc start/stop/status/logs` | `gost-run.service` |
| `QUIC_REJECT` | отклонять UDP/443 к VPN-адресам | `yes` |

Удалённая сторона (под управлением пользователя): nginx `stream` с выбором по SNI
→ GOST `http` поверх TLS с авторизацией и `udp=true`, цепочка узлов на сервере,
tun-сервер на выходном узле для `route` — [TUNNEL.md](TUNNEL.md).

## Структура

```
cmd/routerd/          точка входа; argv[0]=rsc или router_service_ctl → команды управления
internal/config/      router.conf
internal/domain/      нормализация, проверка, суффиксный матчер (семантика dnsmasq)
internal/lists/       vpn_domains.txt, dns_override.txt; flock + атомарная запись
internal/cli/         команды управления (rsc), автодополнение bash/zsh
internal/services/    systemd по D-Bus, порядок запуска (+ servicestest — подделка для тестов)
internal/sysinfo/     /proc: слушающие порты, sysctl (для status)
internal/firewall/    nftables через netlink: таблица router_service, set'ы, правила (Linux)
internal/sysctl/      запись /proc/sys (ip_forward, redirects — в т.ч. для интерфейса)
internal/dnsproxy/    DNS-прокси на :53 (miekg/dns): override, nft-set по TTL, ECS, AAAA, bogus-priv,
                      локальная зона *.lan
internal/dhcp/        DHCP: пул и аренды (чистая логика), обработка сообщений, JSON-хранилище,
                      зона имён; сокет :67 и проверка ARP — Linux
internal/routing/     policy routing через netlink: ip rule, таблица 152 (Linux)
internal/pihole/      сверка и точечная правка ключей цепочки в pihole.toml
internal/netcfg/      apply-network: NetworkManager по D-Bus + Checkpoint
internal/localclient/ сеть локальных сервисов: netns, veth, resolv.conf (routerd local-client)
internal/daemon/      routerd run: применение, sd_notify (notify-reload), SIGHUP,
                      слежение за туннелем, VPN_FAILOVER, очистка
internal/api/         API демона: JSON через unix-сокет (для веб-интерфейса)
internal/web/         веб-интерфейс: HTTPS, вход и сессии, страницы (assets/), шлюз к API
deploy/systemd/       routerd.service, routerd-local@.service, routerd-web.service,
                      примеры gost-run.service и local-app.service
deploy/config/        примеры router.conf (все ключи), vpn_domains.txt, dns_override.txt
install.sh            установка/обновление на RPi (bash — единственное место вне Go)
ansible/rpi5_gorouter/ коллекция Ansible: роль routerd (установка из релиза, конфиги из инвентаря)
testbed/              стенд: lab.sh, эталон ядра RPi, конфиги стенда и узлов туннеля;
                      webdemo — веб-интерфейс с поддельным демоном на машине разработчика
```

Юнит-тесты — всё, что не трогает ядро (работают на macOS и Linux).
Linux-специфичное — под `//go:build linux`, проверяется на стенде.

## Файлы на RPi

| Файл | Что это |
|---|---|
| `/usr/local/etc/router_service/` | `router.conf`, `vpn_domains.txt`, `dns_override.txt`; каталог переопределяется `ROUTERD_CONFIG_DIR` (стенд, отладка) |
| `/var/lib/routerd/leases.json` | аренды DHCP |
| `/etc/pihole/pihole.toml` | конфиг Pi-hole; routerd сверяет в нём только ключи цепочки DNS |
| `/etc/systemd/system/routerd.service` | юнит routerd |
| `/etc/systemd/system/routerd-local@.service` | сеть локального сервиса (`LOCAL_CLIENTS`) |
| `/run/netns/<имя>`, `/etc/netns/<имя>/resolv.conf` | namespace и DNS локального сервиса |
| `/etc/systemd/system/routerd-web.service` | веб-интерфейс (`WEB_UI=yes`) |
| `/usr/local/etc/router_service/web_users` | пользователи веб-интерфейса |
| `/var/lib/routerd-web/` | ключ подписи сессий, самоподписанный сертификат |
| `/run/routerd/api.sock` | API демона для веб-интерфейса |
| `/etc/systemd/system/dnscrypt-proxy.socket.d/routerd.conf` | адрес dnscrypt-proxy (`DNSCRYPT_ADDR`) |
| `/usr/local/bin/routerd`, `rsc`, `router_service_ctl` | бинарник и symlink'и на него |

Порядок запуска (`rsc start`): `dnscrypt-proxy.socket` → `dnscrypt-proxy` →
`pihole-FTL` → `routerd` → клиент туннеля (`VPN_SERVICE`); не установленные
юниты пропускаются. `rsc stop` останавливает клиент туннеля и routerd. `rsc
logs` — единственное место, где routerd вызывает внешнюю программу
(`journalctl`). Автодополнение генерирует бинарник: `routerd completion bash|zsh`.

## Тестовый стенд

Одна Linux-машина arm64 (Debian 13; на Mac — VM OrbStack, на Linux — VM или
выделенная машина), внутри — network namespace, связанные veth-парами:

- `rpi` — routerd, Pi-hole, dnscrypt-proxy, nftables, GOST-клиент;
- `client` — получает адрес по DHCP от routerd (busybox udhcpc), dig, curl;
  `client2` — устройство со статикой для проверки конфликтов адресов;
  REQUEST в состоянии INIT-REBOOT и RELEASE отправляет `testbed/dhcpprobe`
  (busybox udhcpc их по запросу не шлёт);
- `entry`, `exit` — входной и выходной узлы туннеля:
  nginx `stream` (SNI, `proxy_protocol`) → GOST `http`+`tls` с авторизацией и
  `probeResist`, цепочка entry → exit, tun-сервер на exit; сертификаты от CA стенда;
- внешний роутер — отдельный namespace (не основной namespace машины, чтобы
  трафик не утёк в настоящий интернет).

Стенд автономный, проверка пакетами (tcpdump) и журналами сервисов,
короткие таймауты set. Поднимается и сносится одним скриптом; топология —
юнит `lab-topology.service`, а сервисы стенда, как на RPi, в автозапуске, так
что после перезагрузки машины стенд поднимается сам (`lab.sh test-boot`
проверяет это и перезапуск после SIGKILL); первым шагом
сверяет nft-опции ядра машины с эталоном боевого ядра RPi
(`testbed/kernel-rpi.txt`: 6.12 rpt, 16K-страницы).

DNS-цепочка стенда повторяет боевую: настоящий Pi-hole v6 (ставится
официальным установщиком в автоматическом режиме — нужен заранее созданный
`pihole.toml`) на :5353 и dnscrypt-proxy из Debian (socket activation на
`127.0.0.1:5053`) в namespace `rpi`; единственный сервер dnscrypt-proxy —
DoH-сервер стенда `testbed/dohd` (doh.example, 203.0.113.55), закреплённый в
DNS stamp по хэшу собственного CA стенда; за ним — авторитетный DNS тестовых
зон (203.0.113.54), отвечающий NXDOMAIN на всё прочее (иначе dnscrypt-proxy
отбраковывает сервер как «lying resolver»). Тестовые зоны — `*.example`:
на `.test` Pi-hole отвечает сам (RFC 6761), не спрашивая upstream.

Нельзя проверить на стенде: реакцию клиентов на ICMP redirect, Android/Chrome,
IPv6 от реального роутера, производительность, NetworkManager/Checkpoint,
конфликт avahi с Pi-hole на :5353.
