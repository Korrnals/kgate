#!/bin/sh
# {routerctl} ndm-конфиг policy-v2 (design: docs/dev/policy-v2-design.md).
# Модель v1.5: РОВНО ДВЕ политики — VPN (туннель) и NO-VPN (напрямую).
# ЧЕСТНЫЙ ДЕФОЛТ: Proxy0 ip global 1200 > ISP 1000 → дефолтный маршрут дома
# = ISP. Устройство БЕЗ привязки ходит НАПРЯМУЮ; туннель включается ТОЛЬКО
# явной привязкой (kgate policy set device … / kgate policy all-vpn).
# Deploy НЕ создаёт ни device-, ни segment-привязок: дом остаётся fail-safe
# прямым до явного решения владельца.
# Legacy: VPN-TV / VPN-Laptops-Phones / DIRECT-NOVPN (эскейпы v1) мигрируют —
# привязки ре-указываются на NO-VPN, затем объекты удаляются
# (migrate_legacy_policies). Устройства, которым нужен туннель, владелец
# вешает на VPN сам (kgate policy set device <MAC> VPN / all-vpn).
# IaC-деталь: застоявшийся статический `ip route 0.0.0.0/0 Proxy0` сносится
# (веб «Приоритеты доступов» возвращает его при каждом save) + финальный
# assert в конце скрипта.
# Парсинг (wave-1 D5): источник истины парсинга `show ip hotspot` — Go
# ParseHotspot (internal/policy); shell-копия живёт здесь (legacy_bound) для
# миграции одним скриптом. При расхождении чинить СНАЧАЛА Go-парсер,
# потом эту копию.
# Идемпотентно: повторный прогон пересоздаёт то же состояние; миграция на
# втором прогоне — no-op (legacy-политик уже нет).
# Выполняется НА РОУТЕРЕ: ndmc -c "<строка>" на каждую строку конфига.

# --- Proxy0 (туннель-переключатель; ndm создаёт интерфейс при первом set) ---
ndmc -c "interface Proxy0 description \"HYST VPN (sing-box)\""
ndmc -c "interface Proxy0"
ndmc -c "interface Proxy0 description \"HYST VPN (sing-box)\""
ndmc -c "interface Proxy0 security-level public"
# policy-v2: 1200 (было 800). Дефолт забирает интерфейс с МЕНЬШИМ приоритетом:
# ISP=1000 < 1200 → дефолт = ISP (честный дефолт). Политика VPN несёт дефолт
# через Proxy0 (permit global Proxy0) — привязанное устройство в туннеле даже
# при дефолте-ISP.
ndmc -c "interface Proxy0 ip global 1200"
ndmc -c "interface Proxy0 proxy protocol socks5"
ndmc -c "interface Proxy0 proxy upstream 127.0.0.1 1090"
ndmc -c "interface Proxy0 proxy connect via ISP"

# --- route-pins (без них трафик sing-box ловится политикой -> петля) ---
SERVER_IP="${KGATE_SERVER_IP:?KGATE_SERVER_IP is not set}"
ndmc -c "no ip route $SERVER_IP ISP"
ndmc -c "no ip route 77.88.8.8 ISP"
ndmc -c "ip route $SERVER_IP ISP"
ndmc -c "ip route 77.88.8.8 ISP"

# --- DNS: Яндекс напрямую (обход DNS-подавления ТСПУ) ---
ndmc -c "ip name-server 77.88.8.8"

# --- снос застоявшегося статического дефолта через Proxy0 ---
# Приоритетный флип (1200) не трогает СТАТИКУ: в конфиге может лежать старый
# `ip route 0.0.0.0/0 Proxy0` (осел при прошлых save). Веб-страница
# «Приоритеты доступов» строит состав дефолтной политики из этих маршрутов и
# при каждом сохранении опять галочит ОБЕ подключения — возвращая маршрут.
# Явный un-route (безвреден, если маршрута нет) — IaC-гарантия того, что
# дефолтная политика смотрит ТОЛЬКО на базовое подключение (ISP).
ndmc -c "no ip route 0.0.0.0/0 Proxy0"

# --- политики policy-v2 (ровно две; привязки — через kgate policy) ---
# VPN    (туннель):  permit Proxy0 + запрет ISP — таблица политики несёт
#                    дефолт через Proxy0.
# NO-VPN (напрямую): permit ISP + запрет Proxy0 — привязанное устройство
#                    напрямую, даже если владелец позже вернёт дефолт-туннель.
ndmc -c "ip policy VPN"
ndmc -c "ip policy VPN description \"policy-v2: через туннель (Proxy0). Привязка: kgate policy set device MAC VPN\""
ndmc -c "ip policy VPN permit global Proxy0"
ndmc -c "ip policy VPN no permit global ISP"

ndmc -c "ip policy NO-VPN"
ndmc -c "ip policy NO-VPN description \"policy-v2: напрямую (ISP). Привязка: kgate policy set device MAC NO-VPN\""
ndmc -c "ip policy NO-VPN permit global ISP"
ndmc -c "ip policy NO-VPN no permit global Proxy0"

# --- миграция legacy-политик v1 → policy-v2 (см. таблицу в design'е) ---
# Решение: все три legacy-политики были ISP-эскейпами, ближайшая v2-политика
# для их привязок = NO-VPN:
#   VPN-TV             → NO-VPN   (ре-бинд host/segment привязок, затем delete)
#   VPN-Laptops-Phones → NO-VPN   (…)
#   DIRECT-NOVPN       → NO-VPN   (…)
# Порядок обязателен: сначала ре-бинд, потом удаление (ndm не удалит политику
# с активными привязками). Трафик привязанных устройств при миграции не
# меняется: обе политики (старая и NO-VPN) — прямой ISP.

policy_exists() { # <name>: есть ли объект в show ip policy (формы "name: X" и "policy X")
	ndmc -c "show ip policy" | grep -Eq "(^|[[:space:]])name:[ \t]*$1([ \t]|\$)|(^|[[:space:]])policy[ \t]+$1([ \t]|\$)"
}

legacy_bound() { # <old-policy>: строки "host <mac>" / "segment <bridge>" с привязкой к ней.
	# show ip hotspot — ИСТОЧНИК ИСТИНЫ по привязкам (running-config не отражает
	# host-бинды). interface/access point открывают блок сегмента; mac якорит
	# host; policy внутри host-блока (mac непуст) — host-привязка, до первого
	# mac — segment-привязка. Имя сегмента берём как ПЕРВЫЙ токен после двоеточия
	# (ключ "access point:" двухсловный, и значение может нести примечание
	# вроде "Bridge0 (Home)").
	ndmc -c "show ip hotspot" | awk -v old="$1" '
		/[ \t]interface:/    { line=$0; sub(/^[^:]*:/, "", line); split(line, a, " "); seg=a[1]; mac="" }
		/[ \t]access point:/ { line=$0; sub(/^[^:]*:/, "", line); split(line, a, " "); seg=a[1]; mac="" }
		/[ \t]mac:/          { mac=tolower($2) }
		/[ \t]policy:/ {
			if ($2==old) {
				if (mac!="") print "host", mac
				else if (seg!="") print "segment", seg
			}
		}
	'
}

migrate_legacy_policies() {
	migrated=0
	for OLD in VPN-TV VPN-Laptops-Phones DIRECT-NOVPN; do
		policy_exists "$OLD" || continue
		tmp=$(mktemp /tmp/kgate-migrate.XXXXXX 2>/dev/null) || tmp="/tmp/kgate-migrate.$$"
		legacy_bound "$OLD" > "$tmp"
		repointed=0
		while read -r kind id; do
			[ -n "$id" ] || continue
			if [ "$kind" = "host" ]; then
				ndmc -c "ip hotspot host $id policy NO-VPN"
			else
				ndmc -c "ip hotspot $id policy NO-VPN"
			fi
			repointed=$((repointed + 1))
		done < "$tmp"
		rm -f "$tmp"
		ndmc -c "no ip policy $OLD"
		migrated=$((migrated + 1))
		echo "policy-v2 migration: $OLD -> NO-VPN (пере-указано привязок: $repointed; объект удалён)"
	done
	if [ "$migrated" -gt 0 ]; then
		ndmc -c "system configuration save"
		echo "policy-v2 migration: итого $migrated политик(ы) мигрировано, конфиг сохранён"
	else
		echo "policy-v2 migration: legacy-политик нет — уже policy-v2"
	fi
}
migrate_legacy_policies

# --- НИКАКИХ дефолтных привязок (device/segment) ---
# Дом остаётся прямым (дефолт-ISP) до решения владельца:
#   kgate policy all-vpn                          — весь активный трафик в туннель
#   kgate policy set device <MAC> VPN             — точечно
#   kgate policy set segment Bridge2 SMART NO-VPN — точечно по сегменту

# --- поднять туннель (тумблер ON) ---
ndmc -c "interface Proxy0 up"

# --- финальный assert: статического /0 через Proxy0 не существует ---
# Это и есть честный дефолт: дефолтная политика = только ISP. Если assert
# сработал — смотри веб «Приоритеты доступов» (он возвращает галку при save).
stale=$(ndmc -c "show ip route" | grep -c "0.0.0.0/0.*Proxy0")
if [ "$stale" != "0" ]; then
	echo "ВНИМАНИЕ: в таблице маршрутов остался 0.0.0.0/0 Proxy0 (дефолт может уйти в туннель) —"
	echo "прогони ещё раз: ndmc -c 'no ip route 0.0.0.0/0 Proxy0' и проверь веб «Приоритеты доступов»"
fi
