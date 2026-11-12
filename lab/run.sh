#!/bin/sh
# lab/run.sh — OpenWrt-лаба в podman (design §Lab, docs/dev/policy-v2-design.md).
#
# Три матрицы, всё самодостаточно (контейнеры --rm, артефакты в lab/work —
# gitignored, хост не загрязняется):
#   shim      — verb-покрытие ndm-shim (KGATE_LAB=1: rootless без NET_ADMIN,
#               привилегированные вербы честно degrade-ят в state-маркеры);
#               + policy-v2 заглушки обязаны отвечать явной Phase-2 ошибкой.
#   migration — НАСТОЯЩИЙ examples/ndm-commands.sh под busybox sh с mock-ndmc:
#               таблица решений back-compat миграции (ре-бинд legacy-привязок
#               на NO-VPN, удаление объектов, идемпотентность второго прогона).
#   install   — scripts/install.sh --platform=openwrt в чистом контейнере:
#               оффлайн-релиз через KGATE_RELEASE_BASE=<каталог>, sing-box
#               заглушка, ассерты раскладки (шим, procd, /opt-compat, intent).
#
# Образ docker.io/openwrt/rootfs:latest (x86_64 → бинарь собирается amd64).
# Требования на хосте: podman, go (сборка), POSIX sh. Без opkg-сети: prereqs
# внутри контейнера best-effort, nft/uci уже в образе.
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
LAB="$ROOT/lab"
WORK="$LAB/work"
IMAGE="${KGATE_LAB_IMAGE:-docker.io/openwrt/rootfs:latest}"
LAB_TAG="v0.0.0-lab"                # имя фейкового оффлайн-релиза для install-смоука

say() { printf '\n=== lab: %s ===\n' "$*"; }
die() { echo "lab: $*" >&2; exit 1; }
need_podman() { command -v podman >/dev/null 2>&1 || die "нужен podman (лаба не изолирует от него)"; }

# ---- build / release tree ------------------------------------------------------

cmd_build() {
	say "build: kgate amd64 (контейнер x86_64, design §Lab)"
	mkdir -p "$WORK"
	(cd "$ROOT" && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o "$WORK/kgate" .)
	echo "собран: $WORK/kgate"
}

# фейковый релиз той же раскладки, что кладёт goreleaser (для install-смоука)
cmd_release() {
	say "release: оффлайн-релиз $LAB_TAG"
	cmd_build
	R="$WORK/release"
	rm -rf "$R"
	mkdir -p "$R/pkg/platform/openwrt/init" "$R/pkg/platform/openwrt/hotplug" \
		"$R/pkg/examples/etc/sing-box/rulesets"
	cp -f "$WORK/kgate"                       "$R/pkg/kgate"
	cp -f "$ROOT/platform/openwrt/ndmc-shim"  "$R/pkg/platform/openwrt/ndmc-shim"
	cp -f "$ROOT/platform/openwrt/init/kgate.init"      "$R/pkg/platform/openwrt/init/kgate.init"
	cp -f "$ROOT/platform/openwrt/hotplug/50-kgate-pins" "$R/pkg/platform/openwrt/hotplug/50-kgate-pins"
	cp -f "$ROOT/examples/etc/sing-box/config.json"     "$R/pkg/examples/etc/sing-box/config.json"
	tar -czf "$R/kgate_0.0.0-lab_linux_amd64.tar.gz" -C "$R/pkg" \
		kgate platform examples
	(cd "$R" && sha256sum "kgate_0.0.0-lab_linux_amd64.tar.gz" > checksums-sha256.txt)
	echo "релиз: $R готов (архив + checksums в корне каталога — как ждёт install.sh)"
}

# ---- shim verb-покрытие --------------------------------------------------------

cmd_shim() {
	say "shim: verb-покрытие ($IMAGE)"
	need_podman
	cmd_release
	podman run --rm \
		-v "$ROOT:/kgate:ro" \
		-e LAB_IMAGE_TAG="$IMAGE" \
		"$IMAGE" /bin/sh /kgate/lab/matrix.sh
}

# ---- migration decision matrix -------------------------------------------------

cmd_migration() {
	say "migration: таблица решений policy-v2 (ndm-commands.sh на busybox sh)"
	need_podman
	mkdir -p "$WORK"
	rm -rf "$WORK/mock-state"        # свежий fixture: предыдущий прогон снёс legacy-политики
	rm -f "$WORK/migration.log" "$WORK/migration.out"
	podman run --rm \
		-v "$ROOT:/kgate:ro" -v "$WORK:/work" \
		-e PATH=/usr/bin:/bin:/sbin:/usr/sbin \
		-e KGATE_MOCK_LOG=/work/migration.log \
		-e KGATE_MOCK_STATE=/work/mock-state \
		-e KGATE_SERVER_IP=203.0.113.10 \
		"$IMAGE" /bin/sh -c '
		set -u
		mkdir -p /usr/bin
		cp /kgate/lab/mock-ndmc /usr/bin/mock-ndmc
		chmod 0755 /usr/bin/mock-ndmc
		ln -sf /usr/bin/mock-ndmc /bin/ndmc
		echo "=== run1 (legacy обнаружен: VPN-TV, VPN-Laptops-Phones, DIRECT-NOVPN) ===" >> "$KGATE_MOCK_LOG"
		sh /kgate/examples/ndm-commands.sh >> /work/migration.out 2>&1; echo "run1 rc=$?" >> /work/migration.out
		echo "=== run2 (идемпотентность: legacy уже снесён) ===" >> "$KGATE_MOCK_LOG"
		sh /kgate/examples/ndm-commands.sh >> /work/migration.out 2>&1; echo "run2 rc=$?" >> /work/migration.out
	'
	assert_migration
}

# хост-ассерты таблицы решений (grep по логу команд mock-ndmc)
assert_migration() {
	say "migration: ассерты таблицы решений"
	LOG="$WORK/migration.log"
	OUT="$WORK/migration.out"
	[ -f "$LOG" ] || die "нет лога миграции: $LOG"
	run1=$(awk '/^=== run1/{f=1;next} /^=== run2/{f=0} f' "$LOG")
	run2=$(awk '/^=== run2/{f=1;next} f' "$LOG")
	PASS=0; FAIL=0
	ck() { # <label> <haystack> <needle>
		case "$2" in *"$3"*) PASS=$((PASS+1)); printf '  %-58s PASS\n' "$1"; return 0 ;; esac
		FAIL=$((FAIL+1)); printf '  %-58s FAIL (нет: %s)\n' "$1" "$3"
	}
	ck_not() {
		case "$2" in *"$3"*)
			FAIL=$((FAIL+1)); printf '  %-58s FAIL (найдено: %s)\n' "$1" "$3"; return 0 ;;
		esac
		PASS=$((PASS+1)); printf '  %-58s PASS\n' "$1"
	}
	# deploy v2: ровно две политики + честный дефолт + un-route застоявшегося /0
	ck "v2: ip policy VPN создан"            "$run1" "ip policy VPN
"
	ck "v2: VPN permit Proxy0"               "$run1" "ip policy VPN permit global Proxy0"
	ck "v2: VPN no permit ISP"               "$run1" "ip policy VPN no permit global ISP"
	ck "v2: ip policy NO-VPN создан"         "$run1" "ip policy NO-VPN permit global ISP"
	ck "v2: NO-VPN no permit Proxy0"         "$run1" "ip policy NO-VPN no permit global Proxy0"
	ck "v2: Proxy0 ip global 1200"           "$run1" "interface Proxy0 ip global 1200"
	ck_not "v2: приоритет 800 снесён"        "$run1" "ip global 800"
	ck    "v2: un-route 0.0.0.0/0 Proxy0"    "$run1" "no ip route 0.0.0.0/0 Proxy0"
	# таблица решений: legacy -> NO-VPN (все три были ISP-эскейпами)
	ck "миграция: host tv (VPN-TV -> NO-VPN)"          "$run1" "ip hotspot host aa:bb:cc:dd:ee:01 policy NO-VPN"
	ck "миграция: host pc (DIRECT-NOVPN -> NO-VPN)"    "$run1" "ip hotspot host aa:bb:cc:dd:ee:02 policy NO-VPN"
	ck "миграция: offline host (VPN-Laptops -> NO-VPN)" "$run1" "ip hotspot host aa:bb:cc:dd:ee:03 policy NO-VPN"
	ck "миграция: segment Bridge2 (access point!)"     "$run1" "ip hotspot policy Bridge2 NO-VPN"
	ck "миграция: delete VPN-TV"             "$run1" "no ip policy VPN-TV"
	ck "миграция: delete VPN-Laptops-Phones" "$run1" "no ip policy VPN-Laptops-Phones"
	ck "миграция: delete DIRECT-NOVPN"       "$run1" "no ip policy DIRECT-NOVPN"
	ck "миграция: save после миграции"       "$run1" "system configuration save"
	ck "дефолт: sensor (без привязки) НЕ тронут — привязок ровно 4" \
		"$(printf '%s' "$run1" | grep -c 'policy NO-VPN$')" "4"
	ck_not "дефолт: никаких привязок кроме миграционных" \
		"$(printf '%s' "$run1" | grep '^ip hotspot' | grep -v 'policy NO-VPN')" "ip hotspot"
	# идемпотентность второго прогона: миграция no-op
	ck_not "идемпотентность: run2 без delete политик"  "$run2" "no ip policy"
	ck_not "идемпотентность: run2 без привязок"        "$run2" "ip hotspot host"
	ck    "идемпотентность: run2 rc=0"                 "$(cat "$OUT" 2>/dev/null)" "run2 rc=0"
	printf '\n=== миграционная матрица: PASS=%s FAIL=%s ===\n' "$PASS" "$FAIL"
	[ "$FAIL" -eq 0 ]
}

# ---- install.sh smoke ----------------------------------------------------------

cmd_install() {
	say "install: install.sh --platform=openwrt в чистом контейнере (оффлайн)"
	need_podman
	cmd_release
	# -i: скрипт смоука передаётся на stdin (sh -s); вывод пишем в файл, хост
	# проверяет sentinel INSTALL-SMOKE-PASS — пустой stdin не изобразит "зелёный" прогон
	podman run --rm -i \
		-v "$ROOT:/kgate:ro" -v "$WORK:/work" \
		-e PATH=/sbin:/usr/sbin:/usr/bin:/bin \
		-e KGATE_VERSION="$LAB_TAG" \
		"$IMAGE" /bin/sh -s > "$WORK/install.log" 2>&1 <<'SMOKE'
set -eu
echo "--- prereqs (best-effort; nft/uci уже в образе) ---"
mkdir -p /var/lock   # в контейнере нет загрузочной tmpfs — procd-лок требует
grep -q " /var/lock " /proc/mounts 2>/dev/null || mount -t tmpfs tmpfs /var/lock 2>/dev/null || true
opkg update >/dev/null 2>&1 \
	&& opkg install ip-full curl ca-bundle iptables-nft ip6tables-nft >/dev/null 2>&1 \
	&& echo "opkg prereqs: установлены" \
	|| echo "opkg prereqs: пропущены (feeds недоступны) — продолжаю на образных nft/uci"
command -v nft >/dev/null || { echo "FAIL: nft отсутствует"; exit 1; }
command -v uci >/dev/null || { echo "FAIL: uci отсутствует"; exit 1; }
echo "prereqs: nft+uci на месте"
# sing-box заглушка: установщик видит существующий /usr/bin/sing-box и
# пропускает скачивание (оффлайн-смоук)
printf '#!/bin/sh\necho "sing-box version 1.11.15 (lab stub)"\n' > /usr/bin/sing-box
chmod 0755 /usr/bin/sing-box
echo "--- install.sh --platform=openwrt (KGATE_RELEASE_BASE=/work/release) ---"
KGATE_RELEASE_BASE=/work/release sh /kgate/scripts/install.sh --platform=openwrt
echo "--- asserts ---"
/usr/bin/kgate version
test -x /usr/bin/ndmc && test -L /bin/ndmc && echo "PASS shim: /usr/bin/ndmc + /bin/ndmc"
test -x /etc/init.d/kgate && ls /etc/rc.d 2>/dev/null | grep -q kgate && echo "PASS procd: init + enabled"
test -s /etc/kgate/kgate.yaml && echo "PASS config: /etc/kgate/kgate.yaml"
test -s /etc/kgate/sing-box/config.json && echo "PASS config: sing-box skeleton"
test "$(cat /etc/kgate/intent)" = "up" && echo "PASS intent: up"
test -L /opt/etc/kgate && test -L /opt/etc/sing-box && test -e /opt/var && echo "PASS /opt compat: kgate/sing-box/var"
/usr/bin/ndmc -c "kgate reapply" && echo "PASS shim: kgate reapply"
echo "INSTALL-SMOKE-PASS"
SMOKE
	rc=$?
	sed -n '/--- install.sh/,$p' "$WORK/install.log" | head -40 || true
	[ "$rc" -eq 0 ] || die "install smoke: контейнер rc=$rc — см. $WORK/install.log"
	grep -q "INSTALL-SMOKE-PASS" "$WORK/install.log" || die "install smoke: sentinel INSTALL-SMOKE-PASS не найден (пустой stdin или обрыв)"
	echo "install smoke: PASS (sentinel на месте)"
}

# ---- dispatch ------------------------------------------------------------------

case "${1:-}" in
	build)     cmd_build ;;
	release)   cmd_release ;;
	shim)      cmd_shim ;;
	migration) cmd_migration ;;
	install)   cmd_install ;;
	all)       cmd_shim; cmd_migration; cmd_install ;;
	clean)     rm -rf "$WORK"; echo "lab: work очищен" ;;
	*) die "usage: run.sh build|release|shim|migration|install|all|clean" ;;
esac
