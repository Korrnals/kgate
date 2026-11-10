#!/bin/sh
# openwrt-traffic-setup.sh — настройка route/rule для tproxy на OpenWrt.
#
# ВНИМАНИЕ (honest marking, wave-1 D1): Phase 2 scaffolding — НЕ подключено.
# Ни install.sh, ни deploy, ни shim, ни init этот скрипт пока НЕ запускают;
# в релизные архивы он не входит. Wire-up планируется на field E2E (Flint 2).
# Применяется пока только вручную/в лабе (sh traffic-setup.sh ПОСЛЕ ручного
# nft -f nft-kgate.conf).
#
# Требования: ip-full (ip rule), nftables, sing-box (tproxy :7893).
# Идемпотентно: повторный прогон — те же правила.
set -u

# локальная таблица для tproxy-маркированных пакетов (роутинг на себя)
ip rule add fwmark 1 table 100 2>/dev/null || true
ip route replace local 0.0.0.0/0 dev lo table 100

echo "traffic-setup: ip rule fwmark 1 → table 100 (local) готов"
