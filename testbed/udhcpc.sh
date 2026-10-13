#!/bin/sh
# Скрипт busybox udhcpc для клиентов стенда: адрес, маршрут, resolv.conf
# namespace и файл с параметрами аренды для проверок (/run/lab-dhcp/<ns>.env).
# Имя namespace передаётся в LAB_NS.
ns="${LAB_NS:?LAB_NS не задан}"
state="/run/lab-dhcp/${ns}.env"
case "$1" in
deconfig)
    ip addr flush dev "$interface"
    ip link set "$interface" up
    ;;
bound | renew)
    ip addr flush dev "$interface"
    ip addr add "$ip/$subnet" broadcast "${broadcast:-+}" dev "$interface"
    ip route replace default via "${router%% *}" dev "$interface"
    mkdir -p "/etc/netns/$ns" /run/lab-dhcp
    {
        [ -n "$domain" ] && echo "search $domain"
        for s in $dns; do echo "nameserver $s"; done
    } >"/etc/netns/$ns/resolv.conf"
    printf 'ip=%s\nsubnet=%s\nbroadcast=%s\nrouter=%s\ndns=%s\ndomain=%s\nlease=%s\nserverid=%s\n' \
        "$ip" "$subnet" "$broadcast" "$router" "$dns" "$domain" "$lease" "$serverid" >"$state"
    ;;
esac
exit 0
