# Изменения volkserg.rpi5_gorouter

Версия коллекции совпадает с версией routerd, которую роль ставит по умолчанию.

## 0.3.0

- routerd: сервисы на самой RPi как клиенты LAN — `LOCAL_CLIENTS`, шаблон
  `routerd-local@.service` (роль и `install.sh` его ставят), пример юнита
  `deploy/systemd/local-app.service`.
- routerd: в режиме route туннель восстанавливается после быстрого (быстрее
  2 с) перезапуска GOST — раньше маршрут в новый tun не возвращался.
- routerd: имена без точки отвечаются из зоны `lan` (или NXDOMAIN), а не
  зацикливаются через Pi-hole.

## 0.2.3

- routerd: запросы в зону `lan` (DNS-SD) не зацикливаются через Pi-hole,
  `.local` — сразу NXDOMAIN.
- README: статический адрес RPi задаёт `apply-network`.

## 0.2.2

- README routerd переписан: описание, установка, настройка, использование.
- `requires_ansible: ">=2.16.0"`, теги и этот файл — замечания `ansible-lint`
  для коллекции.

## 0.2.1

- Проверка имён команд не падает на ansible-core 2.19+, когда `rsc` ещё нет.
- `rsc` и `router_service_ctl` — только ссылки на routerd: ссылка на другую
  программу отклоняется.
- Ссылка автодополнения `router_service_ctl` заменяет прежний файл; прежнее
  zsh-дополнение `_router_service_ctl` удаляется.

## 0.2.0

- `routerd_vpn_file`, `routerd_dns_override_file` — списки готовыми файлами с
  машины Ansible.
- `router.conf` и списки проверяются до записи (`rsc check-config --… <файл>`):
  файл с ошибкой на RPi не попадает.

## 0.1.0

- Роль `routerd`: routerd из релиза GitHub (проверка по `SHA256SUMS`) или
  локального архива, `router.conf` и списки из инвентаря, Pi-hole и
  dnscrypt-proxy, автозапуск, `apply-network` с подтверждением.
