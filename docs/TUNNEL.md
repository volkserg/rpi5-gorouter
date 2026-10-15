# Туннель: GOST на RPi и на удалённых узлах

routerd не устанавливает туннель сам: он направляет трафик к адресам из
`vpn_domains.txt` в локальный GOST (`gost-run.service`), а GOST везёт его на
удалённый узел. Ниже — схема, проверенная на стенде (`testbed/lab.sh`, все три
`VPN_MODE`), и что нужно на сервере для каждого режима.

## Схема

```
LAN → routerd → gost-run (RPi) ══TLS══▶ входной узел ══TLS══▶ выходной узел → интернет
                                         nginx :443               nginx :443
                                         └ SNI data.* → GOST      └ SNI data.* → GOST (+ tun для route)
```

На каждом узле:

- **nginx `stream` на :443** выбирает бэкенд по SNI без расшифровки
  (`ssl_preread`): имя туннеля (`data.…`) — GOST на `127.0.0.1:9443`, остальное —
  обычный веб-сайт узла. Адрес клиента передаётся по `proxy_protocol`.
- **GOST**: слушатель `tls`, обработчик `http` (CONNECT) с авторизацией.
  `probeResist` — запрос без авторизации получает ответ веб-сайта узла, а не
  ошибку прокси (защита от сканирования).
- **Цепочка** узлов задаётся на сервере (`chains` в `gost.yml`): клиент на RPi
  знает только входной узел, узлов может быть сколько угодно.

Готовые конфиги стенда: [testbed/nodes/nginx.conf](../testbed/nodes/nginx.conf),
[testbed/nodes/gost-entry.yaml](../testbed/nodes/gost-entry.yaml), выходной узел —
`lab-gost-exit` в `testbed/lab.sh`.

## Что нужно режимам

| `VPN_MODE` | Что идёт в туннель | Требование к серверу |
|---|---|---|
| `redirect` | TCP | `http` + `tls` — как есть |
| `tproxy` | TCP и UDP | `udp=true` в обработчике `http` **на каждом узле** (UDP поверх HTTP — расширение GOST, работает и в цепочке) |
| `route` | весь IP | то же + tun-сервер на **выходном** узле, NAT подсети tun |

`udp=true` не меняет поведение для TCP: клиенты в режиме `redirect` продолжают
работать, поэтому его можно включить заранее.

### Выходной узел

`/etc/gost/gost.yml` (права 0600 — в нём пароль) — как
[testbed/nodes/gost-exit.yaml](../testbed/nodes/gost-exit.yaml): сервис `tunnel`
(`http` + `tls`, `udp: true`, `proxyProtocol: 1`) и сервис `tun` на
`127.0.0.1:8421`. Запуск — `gost -C /etc/gost/gost.yml`. Получить YAML из
привычной строки параметров: `gost -L … -O yaml` (CLI кладёт каждый параметр
на все уровни — обработчик, слушатель, сервис; в файле достаточно одного:
`udp`, `probeResist`, `knock`, таймауты — обработчик, `proxyProtocol` —
сервис, `name` и `net` tun — слушатель).

Для `route` — ещё пересылка и NAT подсети tun:

```bash
sysctl -w net.ipv4.ip_forward=1
nft add table ip gost_tun
nft add chain ip gost_tun post '{ type nat hook postrouting priority srcnat; }'
nft add rule ip gost_tun post ip saddr 192.168.123.0/24 oifname "eth0" masquerade
```

tun-сервер слушает только `127.0.0.1`: клиент достаёт его через цепочку
(`tun://:0/127.0.0.1:8421` — адрес разрешается на выходном узле), снаружи UDP-порт
закрыт.

### Входной (промежуточный) узел

`gost.yml` — как [testbed/nodes/gost-entry.yaml](../testbed/nodes/gost-entry.yaml):
обработчик `http` с `udp: true` и `chain` к следующему узлу (`connector: http`,
`dialer: tls` с `secure: true`).

### Общее

- GOST слушает `127.0.0.1:9443`, а не `:9443`: снаружи доступен только nginx.
- `secure=true` (в цепочке — `tls.secure: true`): проверять сертификат
  следующего узла. По умолчанию GOST принимает любой сертификат. Для
  самоподписанного — `caFile=<сертификат CA>`.

## Клиент на RPi

Пример — [deploy/systemd/gost-run.service](../deploy/systemd/gost-run.service):

```
redirect  gost -L red://:1080 -F https://user:password@data.example.com:443?secure=true
tproxy    gost -L red://:1080?tproxy=true -L redu://:1080?ttl=30s -F …
route     gost -L tun://:0/127.0.0.1:8421?net=192.168.123.2/24&name=tun0 -F …
```

Юнит работает без root (`DynamicUser`): `CAP_NET_ADMIN` нужен `tproxy` и `route`,
`CAP_NET_BIND_SERVICE` — `tproxy`, чтобы отвечать на UDP с исходного порта
сервера (например, 53). После смены режима — `rsc restart`.

## Проверено на стенде

- Все режимы через два узла (входной → выходной), `secure=true` с CA стенда.
- Выходной узел видит клиентом входной, входной — RPi (по `proxy_protocol`).
- Без пароля и с неверным паролем прокси не пускает; запрос без авторизации и
  запрос по имени веб-сайта получают ответ веб-сайта.
- GOST и tun-сервер не слушают внешние адреса.
- Сертификат с чужим именем — ошибка `x509` при `secure=true`.
