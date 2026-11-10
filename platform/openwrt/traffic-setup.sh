#!/bin/sh
# openwrt-traffic-setup.sh — настройка route/rule для tproxy на OpenWrt.
# Гоняется deploy'ом kgate ПОСЛЕ nft-kgate.conf (часть traffic-path Phase 2).
#
# Требования: ip-full (ip rule), nftables, sing-box (tproxy :7893).
# Идемпотентно: повторный прогон — те же правила.
set -u

# локальная таблица для tproxy-маркированных пакетов (роутинг на себя)
ip rule add fwmark 1 table 100 2>/dev/null || true
ip route replace local 0.0.0.0/0 dev lo table 100

echo "traffic-setup: ip rule fwmark 1 → table 100 (local) готов"
