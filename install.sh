#!/bin/bash
#===============================================================================
# install.sh — установка и обновление routerd на Raspberry Pi OS / Debian 13
# (arm64). Повторный запуск безопасен: существующие конфиги не меняются.
#
# Что делает:
#   1. Ставит недостающее: dnscrypt-proxy (apt), Pi-hole (официальный
#      установщик).
#   2. Ставит routerd, команды rsc и router_service_ctl, routerd.service,
#      шаблон routerd-local@.service (LOCAL_CLIENTS), автодополнение bash/zsh;
#      конфиги — примеры, только если их нет.
#   3. check-config, apply-network --dry-run, включение и запуск.
#
# Клиент туннеля (GOST, юнит VPN_SERVICE — по умолчанию gost-run.service)
# ставится и настраивается отдельно — docs/TUNNEL.md.
#
# Использование (из распакованного архива или клона репозитория):
#   sudo ./install.sh              установка или обновление
#   sudo ./install.sh --force      заменить конфиги примерами (старые → *.bak.<время>)
#   sudo ./install.sh --no-start   не запускать после установки
#   sudo ./install.sh --skip-deps  не ставить Pi-hole и dnscrypt-proxy
#
# Бинарник: bin/routerd-linux-arm64 рядом со скриптом (make build-rpi / make dist)
# или ROUTERD_BIN=<путь>.
#===============================================================================

set -euo pipefail

SRC_DIR="$(cd "$(dirname "$0")" && pwd)"
ROUTERD_BIN="${ROUTERD_BIN:-${SRC_DIR}/bin/routerd-linux-arm64}"
CONFIG_DIR="/usr/local/etc/router_service"
BIN_DIR="/usr/local/bin"
UNIT_DIR="/etc/systemd/system"
BASH_COMPLETION="/usr/share/bash-completion/completions/rsc"
ZSH_COMPLETION="/usr/local/share/zsh/site-functions/_rsc"
# Команды управления — symlink'и на routerd.
CTL_NAMES=(rsc router_service_ctl)
PIHOLE_INSTALLER="https://install.pi-hole.net"
STAMP="$(date +%Y%m%d-%H%M%S)"

FORCE=false
START=true
DEPS=true
for arg in "$@"; do
    case "${arg}" in
    --force) FORCE=true ;;
    --no-start) START=false ;;
    --skip-deps) DEPS=false ;;
    -h | --help)
        sed -n '/^# Использование/,/^# или ROUTERD_BIN/p' "$0" | sed 's/^# \{0,1\}//'
        exit 0
        ;;
    *)
        echo "Неизвестный параметр: ${arg} (см. --help)" >&2
        exit 2
        ;;
    esac
done

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'
[[ -t 1 ]] || RED='' GREEN='' YELLOW='' CYAN='' NC=''

log_info() { echo -e "${GREEN}[INFO]${NC} $*"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $*"; }
log_step() { echo -e "\n${CYAN}== $* ==${NC}"; }
die() {
    echo -e "${RED}[ERROR]${NC} $*" >&2
    exit 1
}

ctl() { "${BIN_DIR}/rsc" "$@"; }

# conf_get <ключ> <по умолчанию> — значение из установленного router.conf.
conf_get() {
    local v=""
    [[ -f "${CONFIG_DIR}/router.conf" ]] &&
        v="$(sed -n "s/^[[:space:]]*$1=[\"']\{0,1\}\([^\"'#]*\).*/\1/p" "${CONFIG_DIR}/router.conf" | tail -1)"
    v="${v%"${v##*[![:space:]]}"}"
    echo "${v:-$2}"
}

unit_exists() {
    local st
    st="$(systemctl show -P LoadState "$1" 2>/dev/null)"
    [[ -n "${st}" && "${st}" != not-found ]]
}

# place <пример> <назначение> — пример конфига, если назначения нет (или --force).
place() {
    local src=$1 dst=$2
    if [[ -e "${dst}" ]] && [[ "${FORCE}" != true ]]; then
        log_info "  ${dst}: есть, не меняется"
        return
    fi
    if [[ -e "${dst}" ]]; then
        cp -p "${dst}" "${dst}.bak.${STAMP}"
        log_info "  ${dst}: заменён примером (прежний — ${dst}.bak.${STAMP})"
    else
        log_info "  ${dst}: установлен пример"
    fi
    install -m 0644 "${src}" "${dst}"
}

#===============================================================================
# Проверки
#===============================================================================
[[ ${EUID} -eq 0 ]] || die "запустите от root: sudo $0 $*"
[[ -d /run/systemd/system ]] || die "нужен systemd"
[[ -x "${ROUTERD_BIN}" ]] || die "нет ${ROUTERD_BIN} — соберите (make build-rpi) или укажите ROUTERD_BIN"
VERSION="$("${ROUTERD_BIN}" version 2>&1)" || die "${ROUTERD_BIN} не запускается на этой системе ($(uname -m)): ${VERSION}"
log_info "Устанавливается ${VERSION}"
# Обычный файл вместо symlink на routerd — другая программа с тем же именем:
# не затираем.
for n in "${CTL_NAMES[@]}"; do
    p="${BIN_DIR}/${n}"
    # Свободно или ссылка на routerd; иначе — файл или ссылка на другую программу.
    if [[ -e "${p}" || -L "${p}" ]] && [[ "$(readlink -f "${p}")" != "$(readlink -f "${BIN_DIR}/routerd")" ]]; then
        die "${p} — не symlink на routerd: сначала уберите или переименуйте его"
    fi
done

#===============================================================================
# 1. Зависимости
#===============================================================================
install_pihole() {
    local tmp
    # Автоматическая установка Pi-hole v6 требует готового pihole.toml.
    # Порт 5353 и upstream dnscrypt-proxy — сразу, чтобы не занять :53 routerd.
    if [[ ! -f /etc/pihole/pihole.toml ]]; then
        install -d -m 0755 /etc/pihole
        local dns_port dnscrypt
        dns_port="$(conf_get DNS_UPSTREAM 127.0.0.1#5353)"
        dnscrypt="$(conf_get DNSCRYPT_ADDR 127.0.0.1#5053)"
        cat >/etc/pihole/pihole.toml <<EOF
[dns]
  upstreams = ["${dnscrypt}"]
  port = ${dns_port##*#}
EOF
    fi
    tmp="$(mktemp -d)"
    curl -fsSL "${PIHOLE_INSTALLER}" -o "${tmp}/basic-install.sh" || die "не удалось скачать ${PIHOLE_INSTALLER}"
    log_info "  установка Pi-hole (несколько минут)..."
    bash "${tmp}/basic-install.sh" --unattended || die "установка Pi-hole не удалась (журнал: /etc/pihole/install.log)"
    rm -rf "${tmp}"
    log_info "  Pi-hole: $(pihole -v 2>/dev/null | head -1). Пароль веб-интерфейса: sudo pihole setpassword"
}

if [[ "${DEPS}" == true ]]; then
    log_step "Зависимости"
    if ! dpkg -s dnscrypt-proxy >/dev/null 2>&1; then
        log_info "  dnscrypt-proxy из apt..."
        apt-get update -q
        DEBIAN_FRONTEND=noninteractive apt-get install -y -q dnscrypt-proxy
    else
        log_info "  dnscrypt-proxy: есть"
    fi
fi

# dnscrypt-proxy.socket должен слушать DNSCRYPT_ADDR (по умолчанию пакет
# слушает 127.0.2.1:53). Конфиг dnscrypt-proxy остаётся вашим.
if unit_exists dnscrypt-proxy.socket; then
    want="$(conf_get DNSCRYPT_ADDR 127.0.0.1#5053)"
    want="${want/\#/:}"
    if systemctl show -P Listen dnscrypt-proxy.socket | grep -q "^${want} "; then
        log_info "  dnscrypt-proxy.socket слушает ${want}"
    else
        mkdir -p "${UNIT_DIR}/dnscrypt-proxy.socket.d"
        cat >"${UNIT_DIR}/dnscrypt-proxy.socket.d/routerd.conf" <<EOF
# Установлено install.sh routerd: адрес dnscrypt-proxy в цепочке DNS (DNSCRYPT_ADDR).
[Socket]
ListenStream=
ListenDatagram=
ListenStream=${want}
ListenDatagram=${want}
EOF
        systemctl daemon-reload
        systemctl restart dnscrypt-proxy.socket 2>/dev/null || true
        log_info "  dnscrypt-proxy.socket → ${want} (${UNIT_DIR}/dnscrypt-proxy.socket.d/routerd.conf)"
    fi
fi

if [[ "${DEPS}" == true ]]; then
    if command -v pihole >/dev/null; then
        log_info "  Pi-hole: есть"
    else
        install_pihole
    fi
fi

#===============================================================================
# 2. routerd
#===============================================================================
log_step "routerd"
# Через временный файл: работающий routerd продолжает работать до перезапуска.
install -m 0755 "${ROUTERD_BIN}" "${BIN_DIR}/.routerd.new"
mv -f "${BIN_DIR}/.routerd.new" "${BIN_DIR}/routerd"
for n in "${CTL_NAMES[@]}"; do
    ln -sfn routerd "${BIN_DIR}/${n}"
done
log_info "  ${BIN_DIR}/routerd; ${CTL_NAMES[*]} → routerd"

mkdir -p "${CONFIG_DIR}"
for f in router.conf vpn_domains.txt dns_override.txt; do
    place "${SRC_DIR}/deploy/config/${f}" "${CONFIG_DIR}/${f}"
done

install -m 0644 "${SRC_DIR}/deploy/systemd/routerd.service" "${UNIT_DIR}/routerd.service"
log_info "  ${UNIT_DIR}/routerd.service"
# Сеть локальных сервисов (LOCAL_CLIENTS) — шаблон, экземпляры подключает юнит сервиса.
install -m 0644 "${SRC_DIR}/deploy/systemd/routerd-local@.service" "${UNIT_DIR}/routerd-local@.service"
log_info "  ${UNIT_DIR}/routerd-local@.service"
mkdir -p "$(dirname "${BASH_COMPLETION}")" "$(dirname "${ZSH_COMPLETION}")"
"${BIN_DIR}/routerd" completion bash >"${BASH_COMPLETION}"
# bash-completion подгружает файл по имени команды — второе имя ссылкой.
ln -sfn rsc "$(dirname "${BASH_COMPLETION}")/router_service_ctl"
"${BIN_DIR}/routerd" completion zsh >"${ZSH_COMPLETION}"
rm -f "$(dirname "${ZSH_COMPLETION}")/_router_service_ctl"
log_info "  автодополнение: ${BASH_COMPLETION}, ${ZSH_COMPLETION}"

systemctl daemon-reload

#===============================================================================
# 3. Проверка и запуск
#===============================================================================
log_step "Проверка"
ctl check-config || die "исправьте конфиги в ${CONFIG_DIR} и запустите install.sh снова"

NETWORK_PENDING=false
if out="$(ctl apply-network --dry-run 2>&1)"; then
    echo "${out}"
    grep -q '→' <<<"${out}" && NETWORK_PENDING=true
else
    log_warn "apply-network --dry-run: ${out}"
fi

# Всё, без чего шлюз не работает, — в автозапуске: после отключения питания
# RPi поднимается сама. Pi-hole и dnscrypt-proxy — если установлены.
for u in dnscrypt-proxy.socket pihole-FTL.service routerd.service; do
    if unit_exists "${u}"; then
        systemctl enable "${u}" >/dev/null 2>&1
        log_info "${u}: в автозапуске"
    fi
done

if [[ "${START}" == true ]]; then
    log_step "Запуск"
    ctl restart || die "запуск не удался: rsc logs"
fi

echo
log_info "Готово: ${VERSION}"
[[ "${NETWORK_PENDING}" == true ]] &&
    log_warn "Адрес RPi в NetworkManager отличается от router.conf: sudo rsc apply-network, затем --confirm"
# Юнит клиента туннеля — VPN_SERVICE (суффикс .service можно не писать).
gost_unit="$(conf_get VPN_SERVICE gost-run.service)"
[[ "${gost_unit}" == *.* ]] || gost_unit="${gost_unit}.service"
if ! unit_exists "${gost_unit}"; then
    log_warn "Клиент туннеля не настроен (${gost_unit}, VPN_SERVICE): docs/TUNNEL.md, пример — deploy/systemd/gost-run.service"
elif ! systemctl is-enabled --quiet "${gost_unit}"; then
    log_warn "${gost_unit} не в автозапуске: sudo systemctl enable ${gost_unit}"
fi
[[ "$(conf_get DHCP_ENABLED yes)" == yes ]] &&
    log_warn "DHCP раздаёт routerd — выключите DHCP-сервер на роутере $(conf_get ROUTER_IP 192.168.3.1)"
echo "Состояние: rsc status    Журнал: rsc logs    Справка: rsc help"
