#!/bin/bash
#===============================================================================
# lab.sh — тестовый стенд routerd: network namespace + veth внутри одной
# Linux-машины arm64 (Debian 13, root). Стенд ставит Pi-hole, nginx и др. и
# меняет сетевые настройки, поэтому лучше отдельная VM: на Mac — OrbStack,
# на Linux — любая VM (или выделенная машина).
#
# Топология:
#
#   lab-client ─┐   клиент: адрес по DHCP от routerd
#   lab-client2 ┤   устройство со статикой (проверка конфликтов адресов)
#               ├─ lab-lan (br0, L2-коммутатор LAN 192.168.3.0/24, broadcast для DHCP)
#   lab-rpi ────┤      rpi 192.168.3.2 — тестируемый routerd
#   lab-router ─┘      router 192.168.3.1 — «домашний роутер», DHCP выключен
#        │ wan0 198.51.100.2/30
#   lab-inet  — «интернет»: 203.0.113.10 (прямой сайт), 203.0.113.20 (сайт за туннелем),
#        │      203.0.113.53 (DNS corp.example), 203.0.113.54 (DNS тестовых зон),
#        │      203.0.113.55 (DoH doh.example); основной namespace VM в схеме не участвует
#   lab-entry — входной узел туннеля 198.51.100.10/30 (nginx + GOST, цепочка к exit)
#   lab-exit  — выходной узел туннеля 198.51.100.6/30 (nginx + GOST + tun-сервер)
#
# Туннель — как на бою: GOST-клиент на RPi → TLS (SNI data.entry.example) →
# nginx stream (выбор по SNI, proxy_protocol) → GOST http с авторизацией и
# защитой от сканирования (probeResist) → тем же путём на exit → интернет.
#
# Использование (внутри Linux-машины стенда, от root):
#   lab.sh bootstrap      установить пакеты стенда (нужен интернет один раз)
#   lab.sh bootstrap-dns  установить настоящие Pi-hole и dnscrypt-proxy (интернет)
#   lab.sh check-kernel   сверить ядро VM с эталоном боевой RPi + пробные правила
#   lab.sh up | down      поднять / снести топологию (down заодно останавливает сервисы)
#   lab.sh install        поставить routerd (bin/routerd-linux-arm64) и сервисы стенда
#   lab.sh mode <redirect|tproxy|route> [closed|open]  режим VPN_MODE и VPN_FAILOVER
#   lab.sh test           сквозные проверки текущего режима (после up + install)
#   lab.sh test-all       все режимы подряд
#   lab.sh test-install   проверки install.sh: повторный запуск, --force, отказы
#   lab.sh test-idle [с]  долгое простаивающее соединение через туннель (по умолчанию 120 с)
#   lab.sh status         адреса и маршруты во всех namespace
#   lab.sh exec <ns> cmd  выполнить команду в namespace (rpi, client, router, inet, entry, exit, lan)
#
# Бинарники (make build-rpi build-lab) собираются на macOS или Linux.
# С Mac: orb -m routerd-lab sudo <путь-к-репозиторию>/testbed/lab.sh <команда>
#===============================================================================

set -euo pipefail

LAB_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_DIR="$(cd "${LAB_DIR}/.." && pwd)"
ETALON="${LAB_DIR}/kernel-rpi.txt"
CONFIG_DIR="/usr/local/etc/router_service"
UNIT_DIR="/etc/systemd/system"
SRV_DIR="/srv/lab"
NAMESPACES=(lan router rpi client client2 inet entry exit)

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_info() { echo -e "${GREEN}[INFO]${NC} $*"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $*"; }
log_error() { echo -e "${RED}[ERROR]${NC} $*" >&2; }
die() {
    log_error "$*"
    exit 1
}

need_root() {
    [[ $EUID -eq 0 ]] || die "нужен root: sudo $0 $*"
}

nsx() {
    local ns=$1
    shift
    ip netns exec "lab-${ns}" "$@"
}

#===============================================================================
# bootstrap
#===============================================================================
cmd_bootstrap() {
    need_root
    log_info "Установка пакетов стенда..."
    apt-get update -q
    DEBIAN_FRONTEND=noninteractive apt-get install -y -q \
        nftables iproute2 iputils-ping tcpdump busybox dnsutils curl kmod dnsmasq-base \
        nginx-light libnginx-mod-stream shellcheck zsh
    # nginx нужен только узлам туннеля в их namespace (lab.sh install).
    systemctl disable --now nginx 2>/dev/null || true
    install_gost
    log_info "Готово."
}

# install_gost ставит последний релиз GOST v3 (linux/arm64) с GitHub.
install_gost() {
    if command -v gost >/dev/null; then
        log_info "gost уже установлен: $(gost -V 2>&1 | head -1)"
        return
    fi
    local api="https://api.github.com/repos/go-gost/gost/releases/latest" url tmp
    url="$(curl -fsSL "${api}" | grep -oE '"browser_download_url": *"[^"]*linux_arm64\.tar\.gz"' | grep -oE 'https://[^"]+')" ||
        die "не удалось получить список релизов GOST (${api})"
    tmp="$(mktemp -d)"
    curl -fsSL "${url}" -o "${tmp}/gost.tgz" || die "не удалось скачать ${url}"
    tar -xzf "${tmp}/gost.tgz" -C "${tmp}" gost
    install -m 0755 "${tmp}/gost" /usr/local/bin/gost
    rm -rf "${tmp}"
    log_info "gost установлен: $(gost -V 2>&1 | head -1)"
}

#===============================================================================
# bootstrap-dns: настоящие Pi-hole и dnscrypt-proxy
#===============================================================================
PIHOLE_INSTALLER="https://raw.githubusercontent.com/pi-hole/pi-hole/master/automated%20install/basic-install.sh"

cmd_bootstrap_dns() {
    need_root
    log_info "dnscrypt-proxy из apt..."
    DEBIAN_FRONTEND=noninteractive apt-get install -y -q dnscrypt-proxy
    # Пакет сам включает socket на 127.0.2.1:53 в основном namespace VM —
    # на стенде он работает только в namespace rpi (lab.sh install).
    systemctl disable --now dnscrypt-proxy.socket dnscrypt-proxy.service 2>/dev/null || true

    if command -v pihole >/dev/null; then
        log_info "Pi-hole уже установлен: $(pihole -v 2>/dev/null | head -1)"
        return
    fi
    # Автоматическая установка Pi-hole v6 работает только при существующем
    # pihole.toml. Upstream на время установки — DNS самой VM (для gravity).
    local vm_dns
    vm_dns="$(awk '/^nameserver/ {print $2; exit}' /etc/resolv.conf)"
    install -d -m 0755 /etc/pihole
    cat >/etc/pihole/pihole.toml <<EOF
[dns]
  upstreams = ["${vm_dns}"]
  port = 5353
  listeningMode = "ALL"
EOF
    local tmp
    tmp="$(mktemp -d)"
    curl -fsSL "${PIHOLE_INSTALLER}" -o "${tmp}/basic-install.sh" || die "не удалось скачать ${PIHOLE_INSTALLER}"
    log_info "Установка Pi-hole (несколько минут)..."
    bash "${tmp}/basic-install.sh" --unattended || die "установка Pi-hole не удалась (журнал: /etc/pihole/install.log)"
    rm -rf "${tmp}"
    systemctl disable --now pihole-FTL 2>/dev/null || true
    log_info "Pi-hole установлен: $(pihole -v 2>/dev/null | head -1)"
}

#===============================================================================
# check-kernel
#===============================================================================

# Опции, без которых routerd не работает (все режимы VPN_MODE).
REQUIRED_OPTS=(
    NF_TABLES NF_TABLES_INET NF_TABLES_IPV4 NF_CONNTRACK NF_NAT
    NF_NAT_REDIRECT NF_NAT_MASQUERADE
    NFT_CT NFT_NAT NFT_MASQ NFT_REDIR
    NFT_REJECT NFT_REJECT_INET NFT_REJECT_IPV4 NF_REJECT_IPV4
    NFT_SOCKET NFT_TPROXY NF_TPROXY_IPV4
    TUN VETH IP_ADVANCED_ROUTER IP_MULTIPLE_TABLES
)

# Модуль ядра для опции; пусто — булева опция без своего модуля
# (её проверяет пробный ruleset).
module_for() {
    case $1 in
    NF_TABLES_INET | NF_TABLES_IPV4 | NF_NAT_REDIRECT | NF_NAT_MASQUERADE | \
        IP_ADVANCED_ROUTER | IP_MULTIPLE_TABLES) echo "" ;;
    *) echo "$1" | tr 'A-Z' 'a-z' ;;
    esac
}

# Модуль есть в ядре VM: встроен или загружаем.
vm_has_module() {
    local mod=$1 dir
    dir="/lib/modules/$(uname -r)"
    grep -qE "/${mod}\.ko(\.[a-z]+)?$" "${dir}/modules.builtin" 2>/dev/null && return 0
    grep -qE "/${mod}\.ko(\.[a-z]+)?:" "${dir}/modules.dep" 2>/dev/null && return 0
    return 1
}

cmd_check_kernel() {
    need_root
    [[ -f "${ETALON}" ]] || die "нет эталона ${ETALON}"
    local fail=0 opt val mod

    log_info "Ядро VM: $(uname -r), страница $(getconf PAGESIZE) байт (на RPi — 16384)"
    for opt in "${REQUIRED_OPTS[@]}"; do
        val="$(grep -E "^CONFIG_${opt}=" "${ETALON}" | cut -d= -f2 || true)"
        if [[ "${val}" != "y" && "${val}" != "m" ]]; then
            log_error "CONFIG_${opt}: нет в боевом ядре — routerd не сможет это использовать"
            fail=1
            continue
        fi
        mod="$(module_for "${opt}")"
        if [[ -n "${mod}" ]] && ! vm_has_module "${mod}"; then
            log_error "CONFIG_${opt}: модуля ${mod} нет в ядре VM — стенд не проверит эту часть"
            fail=1
            continue
        fi
        echo "  ✓ CONFIG_${opt}=${val} (RPi)${mod:+, ${mod} есть в VM}"
    done
    if grep -q "^# CONFIG_NFT_REJECT_NETDEV is not set" "${ETALON}"; then
        log_warn "На RPi нет NFT_REJECT_NETDEV: reject в семействе netdev не использовать"
    fi

    log_info "Пробный ruleset во временном namespace..."
    if probe_ruleset; then
        log_info "Пробный ruleset применён: redirect, masquerade, reject, tproxy, socket, ct mark, set interval/timeout, ip rule, tun"
    else
        log_error "Пробный ruleset не применился"
        fail=1
    fi
    [[ ${fail} -eq 0 ]] || die "проверка ядра не пройдена"
    log_info "Ядро VM подходит для стенда."
}

# probe_ruleset применяет в отдельном namespace все конструкции nftables
# и маршрутизации, которые использует routerd во всех режимах.
probe_ruleset() {
    local ns="lab-probe-$$" rc=0
    ip netns add "${ns}"
    # shellcheck disable=SC2064
    trap "ip netns del ${ns} 2>/dev/null || true" RETURN
    ip netns exec "${ns}" nft -f - <<'EOF' || rc=1
table inet probe {
    set static4 { type ipv4_addr; flags interval; elements = { 10.0.0.0/8, 192.0.2.1 } }
    set dyn4 { type ipv4_addr; flags timeout; timeout 24h; }
    chain pre_nat {
        type nat hook prerouting priority dstnat;
        meta l4proto tcp ip daddr @static4 counter redirect to :1080
    }
    chain post_nat {
        type nat hook postrouting priority srcnat;
        ip saddr 192.168.3.0/24 ip daddr != 192.168.3.0/24 counter masquerade
    }
    chain filter_fwd {
        type filter hook forward priority filter; policy accept;
        udp dport 443 ip daddr @dyn4 counter reject with icmp type port-unreachable
        tcp flags syn tcp option maxseg size set rt mtu
    }
    chain mangle_pre {
        type filter hook prerouting priority mangle;
        meta mark set ct mark
        meta l4proto { tcp, udp } socket transparent 1 meta mark set 0x1 accept
        meta l4proto udp ip daddr @static4 tproxy ip to :1080 meta mark set 0x1 accept
        ip daddr @dyn4 ct mark set 0x2
    }
}
EOF
    ip netns exec "${ns}" nft add element inet probe dyn4 '{ 192.0.2.5 timeout 10s }' || rc=1
    ip netns exec "${ns}" ip rule add fwmark 0x1 lookup 100 || rc=1
    ip netns exec "${ns}" ip route add local 0.0.0.0/0 dev lo table 100 || rc=1
    ip netns exec "${ns}" ip tuntap add tun0 mode tun || rc=1
    ip netns exec "${ns}" ip route add unreachable default metric 4096 table 101 || rc=1
    return ${rc}
}

#===============================================================================
# up / down
#===============================================================================

# veth_pair <ns-a> <if-a> <ns-b> <if-b>
veth_pair() {
    # Временные имена короткие: имя интерфейса — не длиннее 15 символов.
    local a="va${RANDOM}" b="vb${RANDOM}"
    ip link add "${a}" type veth peer name "${b}"
    ip link set "${a}" netns "lab-$1"
    ip link set "${b}" netns "lab-$3"
    nsx "$1" ip link set "${a}" name "$2"
    nsx "$3" ip link set "${b}" name "$4"
    nsx "$1" ip link set "$2" up
    nsx "$3" ip link set "$4" up
}

cmd_up() {
    need_root
    if ip netns list | grep -q '^lab-'; then
        die "стенд уже поднят (lab.sh down)"
    fi
    local ns
    for ns in "${NAMESPACES[@]}"; do
        ip netns add "lab-${ns}"
        nsx "${ns}" ip link set lo up
    done

    # LAN-коммутатор: мост без IP, порты к router, rpi, client.
    nsx lan ip link add br0 type bridge
    nsx lan ip link set br0 up
    local port
    for port in router rpi client client2; do
        veth_pair "${port}" eth0 lan "p-${port}"
        nsx lan ip link set "p-${port}" master br0
    done

    # Домашний роутер: LAN + WAN, NAT наружу, DHCP нет.
    nsx router ip addr add 192.168.3.1/24 dev eth0
    veth_pair router wan0 inet r0
    nsx router ip addr add 198.51.100.2/30 dev wan0
    nsx inet ip addr add 198.51.100.1/30 dev r0
    nsx router ip route add default via 198.51.100.1
    nsx router sysctl -qw net.ipv4.ip_forward=1
    nsx router nft -f - <<'EOF'
table ip home_router {
    chain post {
        type nat hook postrouting priority srcnat;
        oifname "wan0" masquerade
    }
}
EOF

    # «Интернет»: адреса тестовых сайтов на dummy-интерфейсе.
    nsx inet ip link add srv type dummy
    nsx inet ip link set srv up
    local a
    for a in 203.0.113.10 203.0.113.20 203.0.113.53 203.0.113.54 203.0.113.55 203.0.113.99; do
        nsx inet ip addr add "${a}/32" dev srv
    done
    nsx inet sysctl -qw net.ipv4.ip_forward=1

    # Входной узел туннеля (к нему подключается RPi).
    veth_pair entry eth0 inet e0
    nsx entry ip addr add 198.51.100.10/30 dev eth0
    nsx inet ip addr add 198.51.100.9/30 dev e0
    nsx entry ip route add default via 198.51.100.9

    # Выходной узел туннеля.
    veth_pair exit eth0 inet x0
    nsx exit ip addr add 198.51.100.6/30 dev eth0
    nsx inet ip addr add 198.51.100.5/30 dev x0
    nsx exit ip route add default via 198.51.100.5
    nsx exit sysctl -qw net.ipv4.ip_forward=1
    nsx exit nft -f - <<'EOF'
table ip exit_node {
    chain post {
        type nat hook postrouting priority srcnat;
        ip saddr 192.168.123.0/24 oifname "eth0" masquerade
    }
}
EOF

    # RPi: статический адрес, как его выставил бы NetworkManager на бою.
    nsx rpi ip addr add 192.168.3.2/24 dev eth0
    nsx rpi ip route add default via 192.168.3.1

    # client и client2 — без адреса: client получает его по DHCP от routerd.
    # MAC фиксированы: для routerd это те же устройства при пересоздании стенда.
    nsx client ip link set eth0 address 02:00:00:00:00:50
    nsx client2 ip link set eth0 address 02:00:00:00:00:51
    log_info "Стенд поднят. Проверка связности..."
    selftest
}

selftest() {
    local ok=1
    check() {
        local desc=$1
        shift
        if "$@" >/dev/null 2>&1; then
            echo "  ✓ ${desc}"
        else
            echo "  ✗ ${desc}"
            ok=0
        fi
    }
    check "rpi → router (LAN)" nsx rpi ping -c1 -W1 192.168.3.1
    check "rpi → интернет через NAT роутера" nsx rpi ping -c1 -W1 203.0.113.10
    check "rpi → удалённый узел" nsx rpi ping -c1 -W1 198.51.100.6
    check "exit → интернет" nsx exit ping -c1 -W1 203.0.113.20
    check "entry → exit" nsx entry ping -c1 -W1 198.51.100.6
    check "основной namespace VM не видит стенд" bash -c '! ping -c1 -W1 203.0.113.10'
    [[ ${ok} -eq 1 ]] || die "связность стенда нарушена"
}

# Юниты стенда: управляемые routerd (имена как на бою) и вспомогательные.
STAND_UNITS=(gost-run routerd pihole-FTL dnscrypt-proxy dnscrypt-proxy.socket
    lab-dns-corp lab-dns-vpn lab-dns-public lab-dohd lab-web-direct lab-web-vpn
    lab-nginx-entry lab-gost-entry lab-nginx-exit lab-gost-exit)

cmd_down() {
    need_root
    local u ns
    for u in "${STAND_UNITS[@]}"; do
        [[ "${u}" == *.* ]] || u="${u}.service"
        systemctl stop "${u}" 2>/dev/null || true
    done
    for ns in $(ip netns list | awk '/^lab-/ {print $1}'); do
        ip netns del "${ns}"
    done
    # Новый стенд — чистая база аренд DHCP.
    rm -f /var/lib/routerd/leases.json /run/lab-dhcp/*.env
    log_info "Стенд снесён."
}

cmd_status() {
    local ns
    for ns in "${NAMESPACES[@]}"; do
        ip netns list | grep -q "^lab-${ns}\b" || continue
        echo -e "${YELLOW}== lab-${ns}${NC}"
        nsx "${ns}" ip -br addr | grep -v '^lo '
        nsx "${ns}" ip route | sed 's/^/   route: /'
    done
}

#===============================================================================
# install: routerd и сервисы стенда
#===============================================================================

# unit <имя> <namespace> <ExecStart> — вспомогательный юнит стенда в namespace.
unit() {
    cat >"${UNIT_DIR}/$1.service" <<EOF
[Unit]
Description=Стенд routerd: $1
[Service]
NetworkNamespacePath=/run/netns/lab-$2
ExecStart=$3
Restart=on-failure
EOF
}

# in_ns <юнит> <namespace> — drop-in, запускающий боевой юнит в namespace стенда.
# resolv.conf основного namespace VM (DNS OrbStack) в namespace стенда
# недоступен — подставляем DNS «интернета» стенда, как рабочие DNS1/DNS2 на бою
# (иначе, например, FTL при остановке подолгу ждёт резолва NTP-сервера).
in_ns() {
    mkdir -p "${UNIT_DIR}/$1.service.d" "/etc/netns/lab-$2"
    echo "nameserver 203.0.113.54" >"/etc/netns/lab-$2/resolv.conf"
    cat >"${UNIT_DIR}/$1.service.d/lab-netns.conf" <<EOF
[Service]
NetworkNamespacePath=/run/netns/lab-$2
BindReadOnlyPaths=/etc/netns/lab-$2/resolv.conf:/etc/resolv.conf
EOF
}

# Публичные тестовые зоны (их видит DoH-сервер): TTL 120, A и AAAA.
# Зона .example, а не .test: Pi-hole отвечает на .test (RFC 6761) сам,
# не спрашивая upstream (как и на lan, internal, home.arpa, invalid, onion).
PUBLIC_ZONES="--address=/vpn.example/203.0.113.20 --address=/vpn.example/2001:db8::20 \
--address=/direct.example/203.0.113.10 --address=/direct.example/2001:db8::10 \
--address=/ads.example/203.0.113.99 \
--address=/entry.example/198.51.100.10 --address=/exit.example/198.51.100.6 --address=/#/"
# --address=/#/ — на всё остальное NXDOMAIN, как настоящий резолвер: иначе
# dnscrypt-proxy считает сервер «lying resolver» и не использует его.
PKI_DIR="${SRV_DIR}/pki"
LAB_ETC="/etc/routerd-lab"

# pki: собственный CA стенда и сертификат DoH-сервера doh.example (203.0.113.55).
# CA добавляется в доверенные VM — dnscrypt-proxy проверяет цепочку по системным.
pki() {
    # Сертификаты выпущены под текущие имена — ничего не делаем.
    if [[ -f "${PKI_DIR}/exit-fullchain.crt" ]] &&
        openssl x509 -noout -ext subjectAltName -in "${PKI_DIR}/doh.crt" 2>/dev/null | grep -q "DNS:doh.example"; then
        return
    fi
    rm -rf "${PKI_DIR}"
    mkdir -p "${PKI_DIR}"
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 3650 \
        -subj "/CN=routerd lab CA" -keyout "${PKI_DIR}/ca.key" -out "${PKI_DIR}/ca.crt" 2>/dev/null
    openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
        -subj "/CN=doh.example" -keyout "${PKI_DIR}/doh.key" -out "${PKI_DIR}/doh.csr" 2>/dev/null
    printf 'subjectAltName=DNS:doh.example,IP:203.0.113.55\nextendedKeyUsage=serverAuth\n' >"${PKI_DIR}/doh.ext"
    openssl x509 -req -in "${PKI_DIR}/doh.csr" -CA "${PKI_DIR}/ca.crt" -CAkey "${PKI_DIR}/ca.key" \
        -CAcreateserial -days 825 -extfile "${PKI_DIR}/doh.ext" -out "${PKI_DIR}/doh.crt" 2>/dev/null
    # Сервер отдаёт цепочку целиком: dnscrypt-proxy ищет закреплённый хэш (CA)
    # среди сертификатов, присланных сервером.
    cat "${PKI_DIR}/doh.crt" "${PKI_DIR}/ca.crt" >"${PKI_DIR}/doh-fullchain.crt"
    # Узлы туннеля: один сертификат на веб-сайт узла и GOST (data.*).
    local n
    for n in entry exit; do
        openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
            -subj "/CN=www.${n}.example" -keyout "${PKI_DIR}/${n}.key" -out "${PKI_DIR}/${n}.csr" 2>/dev/null
        printf 'subjectAltName=DNS:www.%s.example,DNS:data.%s.example\nextendedKeyUsage=serverAuth\n' "${n}" "${n}" >"${PKI_DIR}/${n}.ext"
        openssl x509 -req -in "${PKI_DIR}/${n}.csr" -CA "${PKI_DIR}/ca.crt" -CAkey "${PKI_DIR}/ca.key" \
            -CAcreateserial -days 825 -extfile "${PKI_DIR}/${n}.ext" -out "${PKI_DIR}/${n}.crt" 2>/dev/null
        cat "${PKI_DIR}/${n}.crt" "${PKI_DIR}/ca.crt" >"${PKI_DIR}/${n}-fullchain.crt"
    done
    # nginx читает ключи от root, GOST тоже — права по умолчанию достаточны.
    install -m 0644 "${PKI_DIR}/ca.crt" /usr/local/share/ca-certificates/routerd-lab-ca.crt
    update-ca-certificates >/dev/null
    log_info "CA стенда создан: ${PKI_DIR}/ca.crt"
}

install_dns_chain() {
    local dohd="${REPO_DIR}/bin/dohd-linux-arm64"
    [[ -x "${dohd}" ]] || die "нет ${dohd} — соберите: make build-lab"
    install -m 0755 "${dohd}" /usr/local/bin/lab-dohd
    install -m 0755 "${REPO_DIR}/bin/dhcpprobe-linux-arm64" /usr/local/bin/lab-dhcpprobe
    pki

    unit lab-dns-public inet "/usr/sbin/dnsmasq --keep-in-foreground --conf-file=/dev/null --pid-file= --log-facility=- \
--listen-address=203.0.113.54 --bind-interfaces --no-resolv --log-queries --local-ttl=120 ${PUBLIC_ZONES}"
    unit lab-dohd inet "/usr/local/bin/lab-dohd -listen 203.0.113.55:443 \
-cert ${PKI_DIR}/doh-fullchain.crt -key ${PKI_DIR}/doh.key -upstream 203.0.113.54:53"

    if ! command -v pihole >/dev/null || ! command -v dnscrypt-proxy >/dev/null; then
        log_warn "Pi-hole/dnscrypt-proxy не установлены (lab.sh bootstrap-dns) — вместо них заглушка"
        unit pihole-FTL rpi "/usr/sbin/dnsmasq --keep-in-foreground --conf-file=/dev/null --pid-file= --log-facility=- \
--port=5353 --listen-address=127.0.0.1 --bind-interfaces --no-resolv --log-queries --server=203.0.113.54"
        return
    fi

    # dnscrypt-proxy: socket activation на 127.0.0.1:5053;
    # единственный сервер — DoH стенда, закреплённый по хэшу CA.
    local stamp
    stamp="$(/usr/local/bin/lab-dohd -stamp -ca "${PKI_DIR}/ca.crt" -addr 203.0.113.55 -host doh.example)"
    mkdir -p "${LAB_ETC}"
    sed "s|@STAMP@|${stamp}|" "${LAB_DIR}/conf/dnscrypt-proxy.toml" >"${LAB_ETC}/dnscrypt-proxy.toml"
    mkdir -p "${UNIT_DIR}/dnscrypt-proxy.socket.d" "${UNIT_DIR}/dnscrypt-proxy.service.d"
    cat >"${UNIT_DIR}/dnscrypt-proxy.socket.d/lab.conf" <<EOF
[Socket]
NetworkNamespacePath=/run/netns/lab-rpi
ListenStream=
ListenDatagram=
ListenStream=127.0.0.1:5053
ListenDatagram=127.0.0.1:5053
EOF
    cat >"${UNIT_DIR}/dnscrypt-proxy.service.d/lab.conf" <<EOF
[Service]
NetworkNamespacePath=/run/netns/lab-rpi
ExecStart=
ExecStart=/usr/sbin/dnscrypt-proxy -config ${LAB_ETC}/dnscrypt-proxy.toml
EOF

    # Pi-hole: в namespace rpi. Ключи цепочки (порт, upstream, ECS, revServers)
    # сверяет и правит routerd (PIHOLE_MANAGE) — намеренно портим их, чтобы
    # проверить это: upstream мимо dnscrypt-proxy, ECS выключен.
    in_ns pihole-FTL rpi
    systemctl stop pihole-FTL 2>/dev/null || true
    pihole_break
    pihole-FTL --config dns.listeningMode ALL >/dev/null
    # ads.example — в denylist: проверка, что фильтрация Pi-hole в цепочке работает.
    pihole-FTL sqlite3 /etc/pihole/gravity.db \
        "INSERT OR IGNORE INTO domainlist (type, domain, enabled, comment) VALUES (1, 'ads.example', 1, 'routerd lab');" >/dev/null
}

# pihole_break портит ключи цепочки в pihole.toml (FTL должен быть остановлен).
pihole_break() {
    pihole-FTL --config dns.port 5353 >/dev/null
    pihole-FTL --config dns.upstreams '["203.0.113.54"]' >/dev/null
    pihole-FTL --config dns.EDNS0ECS false >/dev/null
}
pihole_key() { pihole-FTL --config "$1" 2>/dev/null; }
pihole_key_is() { [[ "$(pihole_key "$1")" == "$2" ]]; }
pihole_ready() { systemctl is-active --quiet pihole-FTL && nsx rpi dig +short +time=1 +tries=1 -p 5353 pi.hole @127.0.0.1 >/dev/null; }

# run_installer <параметры> — install.sh репозитория. На стенде юниты работают в
# namespace (drop-in lab-netns.conf), поэтому автозапуск при загрузке VM, когда
# namespace ещё нет, выключается.
run_installer() {
    local rc=0
    ROUTERD_BIN="${REPO_DIR}/bin/routerd-linux-arm64" "${REPO_DIR}/install.sh" "$@" || rc=$?
    systemctl disable routerd.service >/dev/null 2>&1
    return "${rc}"
}

ctl() { ROUTERD_CONFIG_DIR="${CONFIG_DIR}" /usr/local/bin/router_service_ctl "$@"; }

cmd_install() {
    need_root
    ip netns list | grep -q '^lab-rpi' || die "сначала lab.sh up"
    local bin="${REPO_DIR}/bin/routerd-linux-arm64"
    [[ -x "${bin}" ]] || die "нет ${bin} — соберите: make build-rpi"
    command -v gost >/dev/null || die "нет gost — lab.sh bootstrap"

    mkdir -p "${CONFIG_DIR}"
    install -m 0644 "${LAB_DIR}"/conf/{router.conf,vpn_domains.txt,dns_override.txt} "${CONFIG_DIR}/"

    # DNS-цепочка как на бою: Pi-hole :5353 → dnscrypt-proxy :5053 → DoH стенда.
    install_dns_chain
    # routerd ставит install.sh, как на бою; зависимости стенд ставит сам
    # (bootstrap, bootstrap-dns), запуск — ниже, после сервисов стенда.
    run_installer --skip-deps --no-start
    in_ns routerd rpi
    # DNS внутренней зоны corp.example (для dns_override.txt) на 203.0.113.53.
    unit lab-dns-corp inet "/usr/sbin/dnsmasq --keep-in-foreground --conf-file=/dev/null --pid-file= --log-facility=- \
--listen-address=203.0.113.53 --bind-interfaces --no-resolv --log-queries --address=/corp.example/203.0.113.10"
    # UDP-сервис на адресе vpn.example: по журналу видно, откуда пришёл UDP.
    unit lab-dns-vpn inet "/usr/sbin/dnsmasq --keep-in-foreground --conf-file=/dev/null --pid-file= --log-facility=- \
--listen-address=203.0.113.20 --bind-interfaces --no-resolv --log-queries --address=/udp.example/203.0.113.20"

    # Сайты: busybox httpd пишет в журнал адрес клиента каждого запроса.
    mkdir -p "${SRV_DIR}/direct" "${SRV_DIR}/vpn"
    echo "direct-site" >"${SRV_DIR}/direct/index.html"
    echo "vpn-site" >"${SRV_DIR}/vpn/index.html"
    unit lab-web-direct inet "/bin/busybox httpd -f -vv -p 203.0.113.10:80 -h ${SRV_DIR}/direct"
    unit lab-web-vpn inet "/bin/busybox httpd -f -vv -p 203.0.113.20:80 -h ${SRV_DIR}/vpn"

    # Удалённые узлы туннеля.
    install_node entry
    install_node exit
    sed "s|@PKI@|${PKI_DIR}|g" "${LAB_DIR}/nodes/gost-entry.yaml" >"${SRV_DIR}/node-entry/gost.yaml"
    unit lab-gost-entry entry "/usr/local/bin/gost -C ${SRV_DIR}/node-entry/gost.yaml"
    in_ns lab-gost-entry entry
    sed "s|@PKI@|${PKI_DIR}|g" "${LAB_DIR}/nodes/gost-exit.yaml" >"${SRV_DIR}/node-exit/gost.yaml"
    unit lab-gost-exit exit "/usr/local/bin/gost -C ${SRV_DIR}/node-exit/gost.yaml"
    in_ns lab-gost-exit exit
    gost_client "$(conf_get VPN_MODE)"
    # GOST-клиент резолвит адрес входного узла через routerd, как на бою (gost-resolv.conf).
    mkdir -p "${UNIT_DIR}/gost-run.service.d" "${LAB_ETC}"
    echo "nameserver 127.0.0.1" >"${LAB_ETC}/gost-resolv.conf"
    printf '[Service]\nBindReadOnlyPaths=%s/gost-resolv.conf:/etc/resolv.conf\n' "${LAB_ETC}" \
        >"${UNIT_DIR}/gost-run.service.d/lab-resolv.conf"

    systemctl daemon-reload
    systemctl restart lab-dns-public lab-dohd lab-dns-corp lab-dns-vpn lab-web-direct lab-web-vpn \
        lab-nginx-entry lab-gost-entry lab-nginx-exit lab-gost-exit
    systemctl restart dnscrypt-proxy.socket pihole-FTL

    # restart, а не start: при переустановке должен заработать новый бинарник.
    log_info "Установлено. Перезапуск стека как на бою: router_service_ctl restart"
    ctl restart
    # routerd исправляет pihole.toml в фоне — дождаться, пока Pi-hole снова в строю.
    wait_for 120 pihole_key_is dns.upstreams "[ 127.0.0.1#5053 ]" || die "routerd не исправил pihole.toml"
    wait_for 60 pihole_ready || die "Pi-hole не поднялся после правки конфига"
    # Клиент получает адрес по DHCP от routerd.
    dhcp_client client >/dev/null || die "клиент не получил адрес по DHCP"
    log_info "Клиент получил по DHCP $(client_ip)"
}

#===============================================================================
# mode: переключение VPN_MODE / VPN_FAILOVER
#===============================================================================
conf_get() { sed -n "s/^$1=//p" "${CONFIG_DIR}/router.conf" 2>/dev/null || sed -n "s/^$1=//p" "${LAB_DIR}/conf/router.conf"; }
conf_set() {
    if grep -q "^$1=" "${CONFIG_DIR}/router.conf"; then
        sed -i "s/^$1=.*/$1=$2/" "${CONFIG_DIR}/router.conf"
    else
        echo "$1=$2" >>"${CONFIG_DIR}/router.conf"
    fi
}

# install_node <узел> — nginx узла туннеля: SNI data.<узел>.example → GOST
# (127.0.0.1:9443), остальное — веб-сайт узла www.<узел>.example.
install_node() {
    local n=$1 dir="${SRV_DIR}/node-$1"
    mkdir -p "${dir}/www" "${dir}/tmp"
    echo "www-${n}" >"${dir}/www/index.html"
    sed -e "s|@NAME@|${n}|g" -e "s|@DIR@|${dir}|g" -e "s|@PKI@|${PKI_DIR}|g" \
        "${LAB_DIR}/nodes/nginx.conf" >"${dir}/nginx.conf"
    unit "lab-nginx-${n}" "${n}" "/usr/sbin/nginx -c ${dir}/nginx.conf -g 'daemon off;'"
    in_ns "lab-nginx-${n}" "${n}"
}

# gost_client <режим> — юнит GOST-клиента на «RPi» под режим routerd.
gost_client() {
    local chain="-F https://lab:entry-secret@data.entry.example:443?secure=true" listen
    case $1 in
    redirect) listen="-L red://:1080" ;;
    tproxy) listen="-L red://:1080?tproxy=true -L redu://:1080?ttl=30s" ;;
    route) listen="-L tun://:0/127.0.0.1:8421?net=192.168.123.2/24&name=tun0" ;;
    *) die "неизвестный режим: $1" ;;
    esac
    # Юнит — пример из deploy/ (те же ограничения прав), со своей командой.
    sed -e "s|^ExecStart=.*|ExecStart=/usr/local/bin/gost ${listen//&/\\&} ${chain}|" \
        -e "s|^\[Service\]|[Service]\nNetworkNamespacePath=/run/netns/lab-rpi|" \
        "${REPO_DIR}/deploy/systemd/gost-run.service" >"${UNIT_DIR}/gost-run.service"
}

cmd_mode() {
    need_root
    local mode=${1:-} failover=${2:-closed}
    [[ -n "${mode}" ]] || die "использование: lab.sh mode <redirect|tproxy|route> [closed|open]"
    gost_client "${mode}"
    conf_set VPN_MODE "${mode}"
    conf_set VPN_FAILOVER "${failover}"
    systemctl daemon-reload
    systemctl restart gost-run
    ctl reload-vpn-domains >/dev/null
    log_info "Режим ${mode}, VPN_FAILOVER=${failover}"
}

#===============================================================================
# test: сквозные проверки
#===============================================================================
fails=0
pass() { echo -e "  ${GREEN}✓${NC} $*"; }
fail() {
    echo -e "  ${RED}✗${NC} $*"
    fails=$((fails + 1))
}
expect() {
    local desc=$1
    shift
    if "$@" >/dev/null 2>&1; then pass "${desc}"; else fail "${desc}"; fi
}
# https_get <узел> <www|data> — содержимое https://<host>.<узел>.example/ из LAN
# (с проверкой сертификата по CA стенда).
https_get() {
    local ip host="$2.$1.example"
    ip="$(node_ip "$1")"
    nsx client curl -fsS --max-time 5 --resolve "${host}:443:${ip}" "https://${host}/" 2>/dev/null
}
# listen_addr <ns> <t|u> <порт> — адреса, на которых слушает порт.
listen_addr() { nsx "$1" ss -Hln"$2" | awk -v p=":$3" '$4 ~ p"$" {sub(p"$", "", $4); print $4}' | sort -u | xargs; }
node_ip() { case $1 in entry) echo 198.51.100.10 ;; exit) echo 198.51.100.6 ;; esac; }
# proxy_get <user:pass|""> <адрес> — запрос к сайту через GOST входного узла как HTTPS-прокси.
proxy_get() {
    local auth=${1:+$1@}
    nsx client curl -fsS --max-time 5 --resolve data.entry.example:443:198.51.100.10 \
        -x "https://${auth}data.entry.example:443" "http://$2/" 2>/dev/null | grep -q site
}
# node_saw <узел> <адрес> — GOST узла за последние 30 с обслужил клиента с адреса
# (адрес из proxy_protocol nginx).
# node_saw_since <узел> <строка> <секунд> — GOST узла обслуживал соединение к адресу.
node_saw_since() { journalctl -u "lab-gost-$1" --since "-$3s" -o cat | grep -qF "$2"; }
node_saw() { journalctl -u "lab-gost-$1" --since -30s -o cat | grep -q "\"client\":\"$2:"; }

# Адрес клиента последнего запроса к сайту (из журнала busybox httpd).
seen_by() {
    journalctl -u "$1" -n 20 --no-pager -o cat | grep -oE '[0-9]+(\.[0-9]+){3}' | tail -1
}
set_has() { nsx rpi nft list set ip router_service "$1" | grep -q "$2"; }
resolve() { nsx "$1" dig +short +time=2 +tries=1 "$2" "@$3"; }
fetch() { nsx client curl -fsS --max-time 5 "http://$1/" >/dev/null 2>&1 || true; }
eq() { [[ "$1" == "$2" ]]; }
not() { ! "$@"; }
# quic_refused: клиент получает ICMP port unreachable на UDP/443 к адресу
# (ловим пакетом на клиенте — как ответ видит браузер).
quic_refused() {
    local cap
    cap="$(mktemp)"
    nsx client timeout 4 tcpdump -i eth0 -n -c 1 "icmp[0] = 3 and icmp[1] = 3 and src host 192.168.3.2" >"${cap}" 2>/dev/null &
    sleep 0.5
    nsx client dig +tries=1 +time=1 -p 443 "@$1" x >/dev/null 2>&1 || true
    wait
    grep -q "udp port 443 unreachable" "${cap}"
    local rc=$?
    rm -f "${cap}"
    return ${rc}
}
table_present() { nsx rpi nft list tables | grep -q router_service; }
# dhcp_client <ns> [аргументы udhcpc…] — получить аренду (hostname из LAB_HOST, по умолчанию labclient).
dhcp_client() {
    local ns=$1
    shift
    nsx "${ns}" env LAB_NS="${ns}" busybox udhcpc -i eth0 -s "${LAB_DIR}/udhcpc.sh" \
        -q -n -t 4 -T 1 -x "hostname:${LAB_HOST:-labclient}" "$@" 2>&1
}
lease_var() { sed -n "s/^$2=//p" "/run/lab-dhcp/$1.env" 2>/dev/null; }
client_ip() { lease_var client ip; }
in_pool() {
    local last=${1##*.}
    [[ "${1%.*}" == 192.168.3 && ${last} -ge 100 && ${last} -le 250 ]]
}
since_log() { journalctl -u routerd --since "@$1" --no-pager -o cat; }
eq_lease_state() { [[ "$(lease_state "$1")" == "$2" ]]; }
lease_state() { grep -A6 "\"ip\": \"$1\"" /var/lib/routerd/leases.json | sed -n 's/.*"state": "\(.*\)".*/\1/p' | head -1; }
# Адрес клиента в hex — для поиска ECS в байтах пакета.
ip_hex() { printf '%02x%02x%02x%02x' ${1//./ }; }

resolve6() { nsx client dig +short +time=2 +tries=1 AAAA "$1" @192.168.3.2; }
rcode() { nsx client dig +time=2 +tries=1 "$@" @192.168.3.2 | grep -oE 'status: [A-Z]+' | cut -d' ' -f2; }
# ecs_sent: routerd передаёт «Pi-hole» адрес клиента (EDNS Client Subnet).
# tcpdump разбирает порт 5353 как mDNS и опции EDNS не печатает, поэтому
# ищем опцию в байтах пакета: код 8, длина 8, IPv4, /32, 192.168.3.50.
ecs_sent() {
    local cap
    cap="$(mktemp)"
    nsx rpi timeout 4 tcpdump -i lo -n -x -c 1 "udp dst port 5353" >"${cap}" 2>/dev/null &
    sleep 0.5
    resolve client direct.example 192.168.3.2 >/dev/null || true
    wait
    grep -E '^\s+0x' "${cap}" | cut -d: -f2 | tr -d ' \n' | grep -q "0008000800012000$(ip_hex "$(client_ip)")"
    local rc=$?
    rm -f "${cap}"
    return ${rc}
}
doh_saw() { journalctl -u lab-dohd -n 50 --no-pager -o cat | grep -q "doh query $1\."; }
# Клиент запроса по журналу Pi-hole (API без пароля на стенде).
pihole_client_is() {
    nsx rpi curl -fsS "http://127.0.0.1/api/queries?domain=$1&length=5" | grep -q "\"ip\":\"$2\""
}
dns_down() { ! nsx client dig +short +time=1 +tries=1 vpn.example @192.168.3.2 >/dev/null 2>&1; }
# Откуда пришёл последний UDP-запрос к сервису на адресе vpn.example.
udp_seen() {
    nsx client dig +short +time=2 +tries=1 udp.example @203.0.113.20 >/dev/null 2>&1 || true
    journalctl -u lab-dns-vpn -n 5 --no-pager -o cat | grep 'query\[A\] udp.example' | tail -1 | grep -oE '[0-9]+(\.[0-9]+){3}$'
}
# ICMP к vpn.example пришёл в «интернет» со стороны удалённого узла.
icmp_via_exit() {
    local cap
    cap="$(mktemp)"
    nsx inet timeout 4 tcpdump -i x0 -n -c 1 "icmp[0] = 8 and dst host 203.0.113.20" >"${cap}" 2>/dev/null &
    sleep 0.5
    nsx client ping -c 2 -W 1 203.0.113.20 >/dev/null 2>&1 || true
    wait
    grep -q "ICMP echo request" "${cap}"
    local rc=$?
    rm -f "${cap}"
    return ${rc}
}
# wait_for <секунд> <команда…> — ждать, пока команда не станет успешной.
wait_for() {
    local n=$1
    shift
    for _ in $(seq "$((n * 2))"); do
        "$@" >/dev/null 2>&1 && return 0
        sleep 0.5
    done
    return 1
}
web_ok() { nsx client curl -fsS --max-time 3 "http://$1/" >/dev/null 2>&1; }
status_has() { systemctl show routerd -p StatusText | grep -q "$1"; }

cmd_test() {
    need_root
    fails=0
    local mode
    mode="$(conf_get VPN_MODE)"
    log_info "Режим ${mode}"

    log_info "DHCP"
    local cip nip
    cip="$(client_ip)"
    expect "клиент получил адрес из пула: ${cip}" in_pool "${cip}"
    expect "шлюз и DNS клиента — RPi 192.168.3.2" eq "$(lease_var client router) $(lease_var client dns)" "192.168.3.2 192.168.3.2"
    expect "домен lan, аренда 24h, сервер 192.168.3.2" \
        eq "$(lease_var client domain) $(lease_var client lease) $(lease_var client serverid)" "lan 86400 192.168.3.2"
    expect "labclient.lan → адрес клиента" eq "$(resolve client labclient.lan 192.168.3.2)" "${cip}"
    expect "PTR адреса клиента → labclient.lan" eq "$(nsx client dig +short -x "${cip}" @192.168.3.2)" labclient.lan.
    expect "чужое имя в .lan — NXDOMAIN (не уходит в Pi-hole)" eq "$(rcode nobody.lan)" NXDOMAIN

    systemctl restart routerd
    dhcp_client client -r "${cip}" >/dev/null
    expect "аренда пережила перезапуск routerd: тот же адрес" eq "$(client_ip)" "${cip}"

    # busybox udhcpc не шлёт REQUEST в INIT-REBOOT и RELEASE по запросу — пробник.
    expect "REQUEST адреса чужой подсети (INIT-REBOOT) → DHCPNAK" \
        eq "$(nsx client /usr/local/bin/lab-dhcpprobe -iface eth0 -request 10.9.9.9 | cut -d' ' -f1)" NAK
    expect "REQUEST своего адреса после перезагрузки клиента → DHCPACK" \
        eq "$(nsx client /usr/local/bin/lab-dhcpprobe -iface eth0 -request "${cip}")" "ACK ${cip}"

    # Устройство со статикой на следующем свободном адресе: routerd видит его
    # в ARP и не выдаёт этот адрес новому клиенту.
    nip="${cip%.*}.$(( ${cip##*.} + 1 ))"
    nsx client2 ip addr replace "${nip}/24" dev eth0
    nsx client2 ping -c 1 -W 1 192.168.3.2 >/dev/null 2>&1 || true
    LAB_HOST=altclient dhcp_client client -x 0x3d:01aabbccddeeff >/dev/null
    expect "адрес ${nip}, занятый устройством со статикой, не выдан" \
        bash -c "ip=\$(sed -n 's/^ip=//p' /run/lab-dhcp/client.env); [[ \$ip != ${nip} && \$ip != ${cip} ]]"
    nsx client2 ip addr flush dev eth0
    dhcp_client client -r "${cip}" >/dev/null
    expect "исходный клиент вернул свой адрес" eq "$(client_ip)" "${cip}"

    nsx client /usr/local/bin/lab-dhcpprobe -iface eth0 -release "${cip}" -server 192.168.3.2 >/dev/null
    expect "DHCPRELEASE: аренда освобождена" wait_for 3 eq_lease_state "${cip}" released
    dhcp_client client -r "${cip}" >/dev/null
    expect "после release тот же адрес снова выдан" eq "$(lease_state "${cip}") $(client_ip)" "bound ${cip}"

    log_info "DNS"
    expect "vpn.example резолвится через routerd → «Pi-hole»" eq "$(resolve client vpn.example 192.168.3.2)" 203.0.113.20
    expect "адрес vpn.example попал в vpn_dynamic" set_has vpn_dynamic 203.0.113.20
    expect "у адреса из DNS есть срок жизни (VPN_DYNAMIC_TIMEOUT)" set_has vpn_dynamic "203.0.113.20 .*expires"
    expect "direct.example резолвится" eq "$(resolve client direct.example 192.168.3.2)" 203.0.113.10
    expect "адрес direct.example в set не попал" not set_has vpn_dynamic 203.0.113.10
    expect "corp.example (dns_override) отвечает свой DNS 203.0.113.53" eq "$(resolve client corp.example 192.168.3.2)" 203.0.113.10
    expect "DNS слушается и на loopback RPi (для GOST)" eq "$(resolve rpi vpn.example 127.0.0.1)" 203.0.113.20
    # TTL 120 у источника; через кэш Pi-hole может прийти чуть меньше — но больше 30s.
    expect "срок жизни адреса — max(TTL ≈120s, VPN_DYNAMIC_TIMEOUT 30s)" set_has vpn_dynamic "203.0.113.20 timeout [12]m"
    expect "AAAA для vpn.example отфильтрован (FILTER_AAAA=vpn)" eq "$(resolve6 vpn.example)" ""
    expect "AAAA для direct.example проходит" eq "$(resolve6 direct.example)" 2001:db8::10
    expect "bogus-priv: PTR частной сети — NXDOMAIN без upstream" eq "$(rcode -x 192.168.3.77)" NXDOMAIN
    expect "ECS: routerd передаёт в Pi-hole адрес клиента" ecs_sent
    if command -v pihole >/dev/null; then
        local probe="chk${RANDOM}.direct.example"
        resolve client "${probe}" 192.168.3.2 >/dev/null || true
        expect "цепочка до DoH: запрос дошёл до DoH-сервера стенда" doh_saw "${probe}"
        expect "Pi-hole видит реального клиента (ECS)" wait_for 3 pihole_client_is "${probe}" "$(client_ip)"
        expect "Pi-hole блокирует ads.example из denylist" eq "$(resolve client ads.example 192.168.3.2)" 0.0.0.0

        log_info "Pi-hole под управлением routerd"
        expect "routerd выставил upstream Pi-hole — dnscrypt-proxy" eq "$(pihole_key dns.upstreams)" "[ 127.0.0.1#5053 ]"
        expect "routerd включил ECS в Pi-hole" eq "$(pihole_key dns.EDNS0ECS)" true
        expect "routerd добавил revServers для LAN" bash -c "pihole-FTL --config dns.revServers | grep -q 'true,192.168.3.0/24,127.0.0.1#53,lan'"
        expect "Pi-hole знает имя клиента (PTR через Pi-hole → routerd)" \
            eq "$(nsx rpi dig +short -p 5353 -x "$(client_ip)" @127.0.0.1)" labclient.lan.
        systemctl stop pihole-FTL
        pihole_break
        systemctl start pihole-FTL
        ctl reload-vpn-domains >/dev/null
        expect "reload исправляет расхождение в pihole.toml" wait_for 60 pihole_key_is dns.upstreams "[ 127.0.0.1#5053 ]"
        wait_for 60 pihole_ready || true
        expect "после исправления цепочка через Pi-hole работает" eq "$(resolve client vpn.example 192.168.3.2)" 203.0.113.20
    fi

    log_info "Маршрутизация"
    fetch vpn.example
    expect "vpn.example: запрос пришёл с удалённого узла 198.51.100.6 (через туннель)" eq "$(seen_by lab-web-vpn)" 198.51.100.6
    fetch direct.example
    expect "direct.example: запрос пришёл с WAN роутера 198.51.100.2 (напрямую)" eq "$(seen_by lab-web-direct)" 198.51.100.2

    log_info "UDP и ICMP"
    case ${mode} in
    redirect)
        expect "UDP к vpn.example идёт напрямую (режим redirect — только TCP)" eq "$(udp_seen)" 198.51.100.2
        expect "ICMP к vpn.example идёт напрямую" not icmp_via_exit
        ;;
    tproxy)
        expect "UDP к vpn.example идёт через туннель" eq "$(udp_seen)" 198.51.100.6
        expect "ICMP к vpn.example идёт напрямую (tproxy — TCP и UDP)" not icmp_via_exit
        ;;
    route)
        expect "UDP к vpn.example идёт через туннель" eq "$(udp_seen)" 198.51.100.6
        expect "ICMP к vpn.example идёт через туннель (L3)" icmp_via_exit
        ;;
    esac

    log_info "QUIC"
    expect "UDP/443 к vpn.example отклоняется (ICMP port unreachable)" quic_refused 203.0.113.20
    expect "UDP/443 к direct.example не отклоняется" not quic_refused 203.0.113.10

    log_info "CLI → SIGHUP → nftables"
    # Освежаем адрес из DNS: на стенде он живёт VPN_DYNAMIC_TIMEOUT=30s, а
    # проверяется сохранение при reload, а не срок жизни.
    resolve client vpn.example 192.168.3.2 >/dev/null
    ctl add-vpn-ip 203.0.113.10 >/dev/null
    expect "add-vpn-ip: 203.0.113.10 в vpn_static" set_has vpn_static 203.0.113.10
    fetch direct.example
    expect "direct.example теперь идёт через туннель" eq "$(seen_by lab-web-direct)" 198.51.100.6
    ctl remove-vpn-ip 203.0.113.10 >/dev/null
    fetch direct.example
    expect "remove-vpn-ip: снова напрямую" eq "$(seen_by lab-web-direct)" 198.51.100.2
    expect "после reload адрес из DNS в vpn_dynamic сохранился" set_has vpn_dynamic 203.0.113.20

    log_info "VPN_FAILOVER"
    systemctl stop gost-run
    expect "closed: туннель упал — vpn.example недоступен" wait_for 6 not web_ok vpn.example
    expect "closed: direct.example работает" web_ok direct.example
    cmd_mode "${mode}" open >/dev/null
    systemctl stop gost-run
    expect "open: туннель упал — перехват снят" wait_for 6 status_has "перехват снят"
    fetch vpn.example
    expect "open: vpn.example идёт напрямую" eq "$(seen_by lab-web-vpn)" 198.51.100.2
    systemctl start gost-run
    expect "open: туннель вернулся — перехват восстановлен" wait_for 10 not status_has "перехват снят"
    wait_for 10 web_ok vpn.example || true
    fetch vpn.example
    expect "open: vpn.example снова через туннель" eq "$(seen_by lab-web-vpn)" 198.51.100.6
    cmd_mode "${mode}" closed >/dev/null
    wait_for 10 web_ok vpn.example || true

    log_info "Удалённые узлы туннеля"
    expect "www.exit.example — веб-сайт узла" eq "$(https_get exit www)" www-exit
    expect "data.entry.example без авторизации — тот же сайт (probeResist)" eq "$(https_get entry data)" www-entry
    expect "прокси без пароля не пускает" not proxy_get "" 203.0.113.10
    expect "прокси с чужим паролем не пускает" not proxy_get lab:wrong 203.0.113.10
    expect "прокси с паролем пускает" proxy_get lab:entry-secret 203.0.113.10
    expect "GOST узлов слушает только 127.0.0.1:9443" eq "$(listen_addr entry t 9443) $(listen_addr exit t 9443)" "127.0.0.1 127.0.0.1"
    expect "tun-сервер exit слушает только 127.0.0.1:8421" eq "$(listen_addr exit u 8421)" 127.0.0.1
    fetch vpn.example
    expect "цепочка: exit видит клиентом entry" wait_for 5 node_saw exit 198.51.100.10
    expect "цепочка: entry видит клиентом RPi (адрес роутера)" wait_for 5 node_saw entry 198.51.100.2

    log_info "Остановка и запуск"
    ctl stop >/dev/null
    expect "stop убирает таблицу router_service" not table_present
    expect "stop: DNS на :53 больше не отвечает" dns_down
    ctl start >/dev/null
    expect "start возвращает таблицу" table_present

    [[ ${fails} -eq 0 ]] || die "проверок не пройдено: ${fails}"
    log_info "Все проверки пройдены."
}

cmd_test_all() {
    need_root
    local m failed=()
    for m in redirect tproxy route; do
        cmd_mode "${m}" closed
        wait_for 10 web_ok vpn.example || true
        (cmd_test) || failed+=("${m}")
    done
    cmd_mode redirect closed
    [[ ${#failed[@]} -eq 0 ]] || die "не пройдены режимы: ${failed[*]}"
    log_info "Все режимы пройдены."
}

#===============================================================================
# test-idle: долгое простаивающее соединение через туннель (отдельно — долго)
#===============================================================================
cmd_test_idle() {
    need_root
    local secs=${1:-120} srv start dur out
    fails=0
    log_info "Режим $(conf_get VPN_MODE): TLS-соединение к адресу из списка простаивает ${secs} с"
    # Сервер держит соединение, пока открыт его ввод (sleep): из /dev/null он
    # закрывал бы соединение сразу. $! — PID openssl (последний в конвейере;
    # ip netns exec выполняет exec в том же процессе).
    sleep "$((secs + 30))" | ip netns exec lab-inet openssl s_server -quiet -accept 203.0.113.20:8443 \
        -cert "${PKI_DIR}/doh-fullchain.crt" -key "${PKI_DIR}/doh.key" >/dev/null 2>&1 &
    srv=$!
    sleep 1
    # Адрес попадает в туннель, только пока свежа DNS-запись vpn.example.
    resolve client vpn.example 192.168.3.2 >/dev/null
    expect "203.0.113.20 в списке VPN" set_has vpn_dynamic 203.0.113.20
    start=${SECONDS}
    # Без -quiet s_client закрывает соединение сам, когда кончается ввод (через
    # secs); при разрыве выходит раньше (вывод в обоих случаях «closed»).
    # Конвейер ждёт и sleep, поэтому время выхода s_client записывается внутри.
    local tmp
    tmp="$(mktemp -d)"
    sleep "${secs}" | {
        nsx client openssl s_client -connect 203.0.113.20:8443 >"${tmp}/out" 2>&1
        echo "${SECONDS}" >"${tmp}/end"
    } || true
    dur=$(($(cat "${tmp}/end") - start))
    out="$(tail -1 "${tmp}/out")"
    rm -rf "${tmp}"
    kill "${srv}" 2>/dev/null || true
    wait "${srv}" 2>/dev/null || true
    expect "соединение шло через туннель (входной узел)" node_saw_since entry 203.0.113.20:8443 "$((dur + 5))"
    expect "соединение прожило ${dur} с из ${secs} (${out})" test "${dur}" -ge "${secs}"
    [[ ${fails} -eq 0 ]] || die "соединение разорвано раньше времени"
}

#===============================================================================
# test-install: install.sh (после install)
#===============================================================================
cmd_test_install() {
    need_root
    [[ -L /usr/local/bin/router_service_ctl ]] || die "сначала lab.sh install"
    local out sum_conf sum_gost
    sum_conf="$(sha256sum <"${CONFIG_DIR}/router.conf")"
    sum_gost="$(sha256sum <"${UNIT_DIR}/gost-run.service")"
    echo "install.sh:"

    out="$(run_installer --skip-deps --no-start 2>&1)" && pass "повторный запуск" || fail "повторный запуск: ${out}"
    expect "router.conf не изменён" eq "$(sha256sum <"${CONFIG_DIR}/router.conf")" "${sum_conf}"
    expect "gost-run.service не изменён" eq "$(sha256sum <"${UNIT_DIR}/gost-run.service")" "${sum_gost}"
    expect "router_service_ctl → routerd" eq "$(readlink /usr/local/bin/router_service_ctl)" routerd
    expect "check-config в выводе" grep -q 'router.conf' <<<"${out}"
    expect "без NetworkManager — предупреждение, не ошибка" grep -q 'apply-network --dry-run' <<<"${out}"
    expect "автодополнение bash" bash -n /usr/share/bash-completion/completions/router_service_ctl
    expect "автодополнение bash: команды" grep -q 'apply-network' /usr/share/bash-completion/completions/router_service_ctl
    if command -v zsh >/dev/null; then
        expect "автодополнение zsh" zsh -n /usr/local/share/zsh/site-functions/_router_service_ctl
    fi

    out="$(run_installer --skip-deps --no-start --force 2>&1)" || fail "--force: ${out}"
    expect "--force: бэкап router.conf" compgen -G "${CONFIG_DIR}/router.conf.bak.*"
    expect "--force: пример router.conf" cmp -s "${REPO_DIR}/deploy/config/router.conf" "${CONFIG_DIR}/router.conf"
    expect "--force: gost-run.service не тронут" eq "$(sha256sum <"${UNIT_DIR}/gost-run.service")" "${sum_gost}"
    install -m 0644 "${LAB_DIR}"/conf/{router.conf,vpn_domains.txt,dns_override.txt} "${CONFIG_DIR}/"
    rm -f "${CONFIG_DIR}"/*.bak.*

    rm /usr/local/bin/router_service_ctl
    printf '#!/bin/bash\n' >/usr/local/bin/router_service_ctl
    out="$(run_installer --skip-deps --no-start 2>&1)" && fail "чужой router_service_ctl затёрт" ||
        expect "чужой router_service_ctl: отказ" grep -q 'не symlink' <<<"${out}"
    expect "чужой router_service_ctl: не тронут" grep -q '^#!/bin/bash' /usr/local/bin/router_service_ctl
    ln -sfn routerd /usr/local/bin/router_service_ctl

    ctl restart >/dev/null
    expect "routerd после переустановки" systemctl is-active --quiet routerd
    [[ ${fails} -eq 0 ]] || die "не пройдено проверок: ${fails}"
    log_info "install.sh: все проверки пройдены."
}

case "${1:-help}" in
bootstrap) cmd_bootstrap ;;
bootstrap-dns) cmd_bootstrap_dns ;;
check-kernel) cmd_check_kernel ;;
up) cmd_up ;;
down) cmd_down ;;
install) cmd_install ;;
mode)
    shift
    cmd_mode "$@"
    ;;
test) cmd_test ;;
test-all) cmd_test_all ;;
test-install) cmd_test_install ;;
test-idle)
    shift
    cmd_test_idle "$@"
    ;;
status) cmd_status ;;
exec)
    need_root
    [[ $# -ge 3 ]] || die "использование: lab.sh exec <ns> <команда…>"
    ns=$2
    shift 2
    nsx "${ns}" "$@"
    ;;
*)
    sed -n '/^# Использование/,/^# С Mac/p' "$0" | sed 's/^# \{0,1\}//'
    ;;
esac
