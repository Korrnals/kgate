#!/bin/sh
# lab/matrix.sh — verb-покрытие ndm-shim ВНУТРИ контейнера openwrt/rootfs
# (busybox sh). Вызывается lab/run.sh; репозиторий смонтирован в /kgate:ro.
#
# Окружение: KGATE_LAB=1 — контейнер rootless, NET_ADMIN нет, поэтому
# привилегированные вербы (nft-таблица, ip route) ЧЕСТНО DEGRADE-ят в
# state-маркеры шима (см. шапку platform/openwrt/ndmc-shim). Матрица
# фиксирует: PASS (реальный kernel-эффект), DEGRADE (лаб-маркер, verb
# отработал), FAIL (verb не сработал — матрица красная).
# policy-v2-вербы обязаны отвечать ЯВНОЙ заглушкой ("Phase 2"), а не
# generic-ошибкой — это отдельные строки матрицы.
set -u
export PATH=/sbin:/usr/sbin:/usr/bin:/bin
export KGATE_LAB=1
export KGATE_STATE_DIR=/etc/kgate
export KGATE_INTENT_FILE=/etc/kgate/intent
export KGATE_LOG_FILE=/tmp/kgate-ndmc.log

PASS=0; DEG=0; FAIL=0; FAILED=""
row() { # <label> <status> [detail]
	printf '  %-52s %-8s %s\n' "$1" "$2" "${3:-}"
	case "$2" in
		PASS)    PASS=$((PASS + 1)) ;;
		DEGRADE) DEG=$((DEG + 1)) ;;
		*)       FAIL=$((FAIL + 1)); FAILED="$FAILED [$1]" ;;
	esac
}
has() { # <needle> <label> — $G = последний вывод ndmc
	case "$G" in
		*"$1"*) row "$2" PASS ;;
		*)      row "$2" FAIL "нет подстроки: $1" ;;
	esac
}
lacks() { # <needle> <label>
	case "$G" in
		*"$1"*) row "$2" FAIL "найдено: $1" ;;
		*)      row "$2" PASS ;;
	esac
}
stub() { # <verb> <label> — rc!=0 И "Phase 2" в выводе (явная заглушка, не generic)
	G=$(ndmc -c "$1" 2>&1); rc=$?
	case "$G" in *"Phase 2"*) p=1 ;; *) p=0 ;; esac
	if [ "$rc" -ne 0 ] && [ "$p" = 1 ]; then
		row "$2" PASS "exit=$rc"
	else
		row "$2" FAIL "rc=$rc out=$G"
	fi
}

echo "=== kgate OpenWrt lab matrix — shim verb coverage ==="
echo "  image: ${LAB_IMAGE_TAG:-docker.io/openwrt/rootfs:latest}"
mkdir -p "$KGATE_STATE_DIR"
echo up > "$KGATE_INTENT_FILE"   # deploy сеет intent=up (install.sh делает то же)
cp /kgate/platform/openwrt/ndmc-shim /usr/bin/ndmc
chmod 0755 /usr/bin/ndmc
ln -sf /usr/bin/ndmc /bin/ndmc   # демон жёстко зовёт /bin/ndmc
row "shim установлен (/usr/bin/ndmc + /bin/ndmc -> symlink)" PASS

# 1: amd64-бинарь kgate стартует в openwrt rootfs (design §Lab: amd64 для лабы)
G=$(/kgate/lab/work/release/pkg/kgate version 2>&1); ok=$?
[ "$ok" = 0 ] && row "amd64 kgate стартует в rootfs (kgate version)" PASS "$G" || row "amd64 kgate стартует" FAIL "rc=$ok: $G"

# 2-4: тумблер Proxy0 (nft | lab-degrade)
G=$(ndmc -c "show interface Proxy0" 2>&1); rc=$?
[ "$rc" = 0 ] && has "state: down" "show interface Proxy0 (down) -> state" || row "show interface Proxy0 (down)" FAIL "rc=$rc"
G=$(ndmc -c "interface Proxy0 up" 2>&1); rc=$?
if [ "$rc" -ne 0 ]; then row "interface Proxy0 up" FAIL "rc=$rc: $G"
elif nft list table inet kgate >/dev/null 2>&1; then row "interface Proxy0 up (kernel nft)" PASS
else row "interface Proxy0 up (lab state-marker)" DEGRADE "нет NET_ADMIN"
fi
G=$(ndmc -c "show interface Proxy0" 2>&1)
has "state: up" "show interface Proxy0 (up) -> state"

# 5: persisted-intent (sc view) — daemon intentDown() читает именно это
G=$(ndmc -c "show sc interface Proxy0" 2>&1)
has "up: yes" "show sc interface Proxy0 -> up: yes (intent)"

# 6-10: route-pins
G=$(ndmc -c "show ip route" 2>&1); rc=$?
[ "$rc" = 0 ] && row "show ip route (рендер)" PASS || row "show ip route (рендер)" FAIL "rc=$rc"
G=$(ndmc -c "ip route 203.0.113.10 ISP" 2>&1); rc=$?
if [ "$rc" -ne 0 ]; then row "ip route 203.0.113.10 ISP (pin)" FAIL "rc=$rc: $G"
elif ip route show 2>/dev/null | grep -q "203.0.113.10"; then row "pin add (kernel /32)" PASS
elif grep -qxF "203.0.113.10" "$KGATE_STATE_DIR/routes" 2>/dev/null; then row "pin add (lab-degrade: записан в файл)" DEGRADE "нет NET_ADMIN"
else row "pin add" FAIL "ни kernel, ни файл"
fi
G=$(ndmc -c "show ip route" 2>&1)
case "$G" in *203.0.113.10*) row "show ip route -> pin виден" PASS ;; *) row "show ip route -> pin виден" FAIL ;; esac
G=$(ndmc -c "no ip route 203.0.113.10 ISP" 2>&1); rc=$?
[ "$rc" = 0 ] && row "no ip route (pin del, silence)" PASS || row "no ip route (pin del)" FAIL "rc=$rc: $G"
G=$(ndmc -c "show ip route" 2>&1)
lacks "203.0.113.10" "show ip route -> pin снят"

# 11-13: running-config / save / reapply (destroy-cleanliness surface)
G=$(ndmc -c "show running-config" 2>&1)
has "interface Proxy0" "show running-config -> token Proxy0 (пока up)"
G=$(ndmc -c "system configuration save" 2>&1); rc=$?
[ "$rc" = 0 ] && row "system configuration save" PASS "$G" || row "system configuration save" FAIL "rc=$rc"
G=$(ndmc -c "kgate reapply" 2>&1); rc=$?
[ "$rc" = 0 ] && row "kgate reapply (procd/hotplug-хук)" PASS || row "kgate reapply" FAIL "rc=$rc: $G"

# 14-17: policy-v2 вербы — ЯВНЫЕ заглушки Phase 2 (не generic unknown)
stub "show ip hotspot"                            "stub: show ip hotspot -> Phase 2 error"
stub "show ip policy"                             "stub: show ip policy -> Phase 2 error"
stub "ip policy VPN"                              "stub: ip policy VPN -> Phase 2 error"
stub "ip hotspot host aa:bb:cc:dd:ee:ff policy VPN" "stub: ip hotspot host .. policy -> Phase 2 error"
stub "ip hotspot policy Bridge0 NO-VPN" "stub: ip hotspot policy .. -> Phase 2 error"

# 18: destroy-поверхность политик остаётся рабочей (Phase 1)
G=$(ndmc -c "no ip policy VPN-TV" 2>&1); rc=$?
[ "$rc" = 0 ] && row "no ip policy VPN-TV (state drop)" PASS || row "no ip policy VPN-TV" FAIL "rc=$rc"

# 19: неизвестный verb — явная ошибка, exit 1 (ndmcFailed() читает этот surface)
G=$(ndmc -c "совсем неизвестное" 2>&1); rc=$?
case "$G" in *"system failed"*) p=1 ;; *) p=0 ;; esac
[ "$rc" -ne 0 ] && [ "$p" = 1 ] && row "unknown verb -> clear error" PASS || row "unknown verb -> clear error" FAIL "rc=$rc"

# 20: снятие тумблера возвращает down (чистый финал контейнера)
G=$(ndmc -c "interface Proxy0 down" 2>&1); rc=$?
[ "$rc" = 0 ] || row "interface Proxy0 down" FAIL "rc=$rc: $G"
G=$(ndmc -c "show interface Proxy0" 2>&1)
has "state: down" "show interface Proxy0 (после down) -> state"

echo
echo "=== итог матрицы: PASS=$PASS DEGRADE=$DEG FAIL=$FAIL ==="
[ -n "$FAILED" ] && echo "  FAIL:$FAILED"
[ "$FAIL" -eq 0 ]
