#!/bin/sh
# kgate installer — two platform branches:
#
#   1. operator CLI (default):  downloads the latest CLI binary from GitHub
#      Releases and runs `kgate config create` (the primary onboarding path).
#      Usage:
#        curl -fsSL https://raw.githubusercontent.com/Korrnals/kgate/main/scripts/install.sh | sh
#
#   2. router stack (--platform=openwrt): runs ON the OpenWrt router as root
#      and installs the full stack — kgate + sing-box into /usr/bin, the ndm
#      shim (/usr/bin/ndmc + /bin/ndmc symlink, the daemon hardcodes /bin/ndmc),
#      the procd init (/etc/init.d/kgate, enabled), the hotplug pin-reapply
#      hook, state dir /etc/kgate, and the /opt compatibility symlinks the
#      Go daemon's hardcoded paths require (pidfile, intent file, iptables).
#      Usage (from the laptop or on the router):
#        ssh root@192.168.1.1 'curl -fsSL .../install.sh | sh -s -- --platform=openwrt'
#      No opkg dependency: prerequisites are checked and reported, never
#      installed (Entware is NOT required).
#      KGATE_RELEASE_BASE переопределяет источник релиза (зеркало/оффлайн):
#        https://…  — заменяет префикс https://github.com/<REPO>/releases/download
#        /path/to/dir — файловый оффлайн-режим: архив и checksums копируются из
#                      каталога (podman-лаба lab/run.sh, аэрогап-инсталляции).
#        http:// отклоняется fail-loud (архивы по открытому HTTP — supply-chain
#        риск; wave-1 B6).
#
# For rate-limited environments export GITHUB_TOKEN (optional; the repository
# is public — anonymous downloads work). KGATE_VERSION pins a release tag.
set -eu

REPO="Korrnals/kgate"
DEST="${KGATE_DEST:-$HOME/.local/bin}"
SINGBOX_VER=1.14.4   # pinned in the Makefile too; keep in sync
# pinned sha256 of the sing-box tarballs (supply-chain, wave-1 B6; source:
# https://github.com/SagerNet/sing-box/releases/download/v${SINGBOX_VER}/… —
# recompute with sha256sum when bumping SINGBOX_VER):
SINGBOX_SHA256_arm64="b95e25f921dc5e17a4cf13327243d1177642c7e35425bf5372862c477c359f56"
SINGBOX_SHA256_amd64="699a1b510aa4396b2176d32d1181920399ebf1e267835da6f3b598d0f7c24968"

PLATFORM=""
for a in "$@"; do
  case "$a" in
    --platform=*) PLATFORM="${a#--platform=}" ;;
  esac
done

# auto-route: running on OpenWrt without an explicit platform -> router install
if [ -z "$PLATFORM" ] && [ -f /etc/openwrt_release ]; then
  echo "kgate-install: OpenWrt detected (/etc/openwrt_release) — выполняю установку на роутер;"
  echo "kgate-install: нужен только CLI на ноутбук — запусти с --platform=cli на другой машине"
  PLATFORM="openwrt"
fi

die() { echo "kgate-install: $*" >&2; exit 1; }

fetch_to() { # <url> <file>
  if command -v curl >/dev/null 2>&1; then
    curl -fsSL --retry 3 -o "$2" "$1"
  elif command -v wget >/dev/null 2>&1; then
    wget -q -O "$2" "$1"
  elif command -v uclient-fetch >/dev/null 2>&1; then
    uclient-fetch -q -O "$2" "$1"
  else
    return 127
  fi
}

# ---- branch 2: OpenWrt router stack ------------------------------------------

install_openwrt() {
  [ "$(id -u)" = "0" ] || die "запусти на роутере под root (ssh root@<router>)"
  [ -f /etc/openwrt_release ] || die "это не OpenWrt (/etc/openwrt_release не найден) — ветка --platform=openwrt только для роутера"

  case "$(uname -m)" in
    aarch64 | arm64) GOARCH="arm64" ;;
    x86_64)          GOARCH="amd64" ;;
    *) die "неподдерживаемая архитектура: $(uname -m) (нужен aarch64 — см. docs/admin/requirements.md)" ;;
  esac

  # storage: binaries+configs live on the overlay (/usr, /etc)
  free_kb=$(df -k / 2>/dev/null | awk 'NR==2 {print $4}')
  if [ -n "$free_kb" ]; then
    if [ "$free_kb" -lt 61440 ]; then die "на / меньше 60 МБ — стек (kgate ~10МБ + sing-box ~31МБ + rulesets) не поместится"
    elif [ "$free_kb" -lt 122880 ]; then echo "kgate-install: WARNING: на / меньше 120 МБ — впритык (рекомендация docs/admin/requirements.md)"
    fi
  fi

  # hard requirements: nft (the Proxy0 switch), uci (pin persistence) — core on 23.05+
  command -v nft >/dev/null 2>&1 || die "nft не найден — нужен fw4/nftables (OpenWrt 22.03+; см. requirements)"
  command -v uci >/dev/null 2>&1 || die "uci не найден — это не OpenWrt?"

  # advisory prereqs — checked, reported, never installed (no opkg dependency)
  warn_missing=""
  [ -e /usr/sbin/iptables-nft ] || [ -e /sbin/iptables-nft ] || warn_missing="$warn_missing iptables-nft"
  [ -e /usr/sbin/ip6tables-nft ] || [ -e /sbin/ip6tables-nft ] || warn_missing="$warn_missing ip6tables-nft"
  [ -d /etc/ssl/certs ] || warn_missing="$warn_missing ca-bundle"
  # real check (was a no-op `… || true`, wave-1 B5): busybox ip route is used
  # by the shim/hotplug for pin reapply — if even busybox ip fails, say so
  busybox ip route >/dev/null 2>&1 || warn_missing="$warn_missing busybox-ip(route)"
  if [ -n "$warn_missing" ]; then
    echo "kgate-install: WARNING: рекомендованные пакеты не найдены:$warn_missing"
    echo "kgate-install:   LAN-DNS bypass демона (SBREDIRECT через /opt/sbin/iptables) требует iptables-nft/ip6tables-nft;"
    echo "kgate-install:   TLS наружу sing-box требует системные корни (ca-bundle). Ставить руками:"
    echo "kgate-install:   opkg install iptables-nft ip6tables-nft ca-bundle   # kmod-nft-tproxy — Phase 2 (tproxy-redirect)"
  fi
  command -v curl >/dev/null 2>&1 || command -v wget >/dev/null 2>&1 || command -v uclient-fetch >/dev/null 2>&1 \
    || die "нет curl/wget/uclient-fetch — чем качать? opkg install curl"

  # release resolution (KGATE_VERSION pins, e.g. KGATE_VERSION=v1.5.0)
  TMP=$(mktemp -d /tmp/kgate-install.XXXXXX)
  trap 'rm -rf "$TMP"' EXIT
  if [ -n "${KGATE_VERSION:-}" ]; then
    TAG="$KGATE_VERSION"
  else
    fetch_to "https://api.github.com/repos/${REPO}/releases/latest" "$TMP/meta.json" \
      || die "не смог получить список релизов (GitHub API) — задай KGATE_VERSION=<tag> и повтори"
    TAG=$(grep -o '"tag_name": *"[^"]*' "$TMP/meta.json" | head -1 | cut -d'"' -f4)
    [ -n "$TAG" ] || die "не смог распарсить tag_name — задай KGATE_VERSION=<tag> и повтори"
  fi
  ARCHIVE="kgate_${TAG#v}_linux_${GOARCH}.tar.gz"
  if [ -d "${KGATE_RELEASE_BASE:-}" ]; then
    # offline release dir (lab/mirror): cp instead of fetch — no network at all
    echo "kgate-install: локальный релиз: $KGATE_RELEASE_BASE/$ARCHIVE"
    cp -f "$KGATE_RELEASE_BASE/$ARCHIVE" "$TMP/$ARCHIVE" || die "архива нет в KGATE_RELEASE_BASE: $ARCHIVE"
    cp -f "$KGATE_RELEASE_BASE/checksums-sha256.txt" "$TMP/checksums" || die "checksums-sha256.txt нет в KGATE_RELEASE_BASE — ставить без проверки целостности отказываюсь (fail-loud, wave-1 B6)"
  else
    case "${KGATE_RELEASE_BASE:-}" in
      http://*) die "KGATE_RELEASE_BASE с http:// отклонён — только https:// или локальный каталог (wave-1 B6)" ;;
    esac
    BASE="${KGATE_RELEASE_BASE:-https://github.com/${REPO}/releases/download}"
    BASE="$BASE/$TAG"
    echo "kgate-install: downloading $BASE/$ARCHIVE"
    fetch_to "$BASE/$ARCHIVE" "$TMP/$ARCHIVE" || die "скачивание не удалось (https через busybox wget без libustream падает — opkg install curl)"
    fetch_to "$BASE/checksums-sha256.txt" "$TMP/checksums" || die "checksums-sha256.txt недоступен — ставить без проверки целостности отказываюсь (fail-loud, wave-1 B6)"
  fi
  [ -s "$TMP/checksums" ] || die "checksums-sha256.txt пуст — ставить без проверки целостности отказываюсь (wave-1 B6)"
  (cd "$TMP" && grep " $ARCHIVE\$" checksums | sha256sum -c -) \
    || die "checksum не сошёлся для $ARCHIVE — не ставлю"

  mkdir -p "$TMP/px"
  tar -xzf "$TMP/$ARCHIVE" -C "$TMP/px"
  # release must carry the platform files (first release with OpenWrt support and later)
  [ -f "$TMP/px/platform/openwrt/ndmc-shim" ] && [ -f "$TMP/px/platform/openwrt/init/kgate.init" ] \
    || die "релиз $TAG не содержит platform/openwrt/* — нужен релиз с поддержкой OpenWrt (Phase 1+)"

  # binaries
  mkdir -p /usr/bin
  mv -f "$TMP/px/kgate" /usr/bin/kgate
  chmod 0755 /usr/bin/kgate
  if [ -x /usr/bin/sing-box ]; then
    echo "kgate-install: существующий /usr/bin/sing-box сохранён: $(/usr/bin/sing-box version 2>/dev/null | head -1)"
  else
    SB="sing-box-${SINGBOX_VER}-linux-${GOARCH}-musl.tar.gz"  # static: runs on Keenetic without a loader
    echo "kgate-install: downloading SagerNet sing-box v${SINGBOX_VER} (${GOARCH})"
    fetch_to "https://github.com/SagerNet/sing-box/releases/download/v${SINGBOX_VER}/${SB}" "$TMP/$SB" \
      || die "sing-box скачать не удалось — поставь /usr/bin/sing-box руками (см. Makefile: SINGBOX_VER=${SINGBOX_VER}) и повтори"
    eval "want=\$SINGBOX_SHA256_${GOARCH}"
    [ -n "$want" ] || die "нет pinned sha256 для ${GOARCH} — обнови константы SINGBOX_SHA256_* в скрипте"
    echo "${want}  $TMP/$SB" | sha256sum -c - || die "sha256 sing-box не сошёлся с pinned-константой — не ставлю"
    tar -xzf "$TMP/$SB" -C "$TMP/px"
    mv -f "$TMP/px/sing-box-${SINGBOX_VER}-linux-${GOARCH}/sing-box" /usr/bin/sing-box
    chmod 0755 /usr/bin/sing-box
  fi

  # shim: /usr/bin/ndmc + /bin/ndmc (the daemon hardcodes /bin/ndmc)
  mv -f "$TMP/px/platform/openwrt/ndmc-shim" /usr/bin/ndmc
  chmod 0755 /usr/bin/ndmc
  mkdir -p /bin
  ln -sf /usr/bin/ndmc /bin/ndmc

  # init + hotplug
  mv -f "$TMP/px/platform/openwrt/init/kgate.init" /etc/init.d/kgate
  chmod 0755 /etc/init.d/kgate
  mkdir -p /etc/hotplug.d/iface
  mv -f "$TMP/px/platform/openwrt/hotplug/50-kgate-pins" /etc/hotplug.d/iface/50-kgate-pins
  chmod 0755 /etc/hotplug.d/iface/50-kgate-pins
  /etc/init.d/kgate enable

  # state dir + sing-box skeleton (never overwrite a live config — deploy lesson)
  # umask 077: приватные файлы под root не должны быть world-readable (wave-1 B7;
  # явный chmod 0600 на config.json ниже — belt and suspenders)
  umask 077
  mkdir -p /etc/kgate/sing-box/rulesets
  if [ -s /etc/kgate/sing-box/config.json ]; then
    echo "kgate-install: /etc/kgate/sing-box/config.json сохранён (существующий/подписочный)"
  else
    cp -f "$TMP/px/examples/etc/sing-box/config.json" /etc/kgate/sing-box/config.json
  fi
  chmod 0600 /etc/kgate/sing-box/config.json   # пароль внутри (wave-1 B7)
  cp -f "$TMP/px/examples/etc/sing-box/rulesets/"*.srs /etc/kgate/sing-box/rulesets/ 2>/dev/null || true

  if [ ! -s /etc/kgate/kgate.yaml ]; then
    cat > /etc/kgate/kgate.yaml <<'YAMLEOF'
# kgate.yaml — OpenWrt (ndm-shim, Phase 1 beta). Заполни host/server_ip и
# пароль в /etc/kgate/sing-box/config.json, затем: /etc/init.d/kgate start
host: 192.168.1.1
server_ip: 203.0.113.10  # IP hy2 exit-сервера (endpoint для route-pin)

api:
  port: 9443
  ca: /etc/kgate/ca.crt
  cert: /etc/kgate/client.crt
  key: /etc/kgate/client.key

daemon:
  singbox_bin: /usr/bin/sing-box
  singbox_config: /etc/kgate/sing-box/config.json
  singbox_log: /var/log/singbox.log
  rlimit_nofile: 8192
  supervisor_interval: 15s
  boot_autoup: true
  autoup_delay: 25s
  api_listen: ":9443"
  web_root: /etc/kgate
  log: /var/log/kgate.log
YAMLEOF
    echo "kgate-install: /etc/kgate/kgate.yaml создан (плейсхолдеры — заполни host/server_ip)"
  else
    echo "kgate-install: /etc/kgate/kgate.yaml сохранён (существующий)"
  fi

  # /opt compatibility: the Go daemon hardcodes /opt/var/run, /opt/etc/kgate,
  # /opt/etc/sing-box and /opt/sbin/{iptables,ip6tables} (Keenetic/Entware
  # layout). Zero daemon changes — the layout is provided here by construction.
  mkdir -p /opt/sbin /opt/etc
  if [ -d /opt/var ] && [ ! -L /opt/var ]; then
    mkdir -p /opt/var/run /opt/var/log   # Entware layout: real dirs (pidfile on flash — fine)
  else
    ln -sfn /var /opt/var                # /var -> tmpfs on OpenWrt: pidfiles stay in RAM
  fi
  ln -sfn /etc/kgate /opt/etc/kgate      # intent file + ca-bundle fallback live on persistent /etc
  ln -sfn /etc/kgate/sing-box /opt/etc/sing-box   # skeleton ruleset paths (/opt/etc/sing-box/rulesets) stay valid unmodified
  ipt_nft=$(command -v iptables-nft 2>/dev/null || { [ -e /usr/sbin/iptables-nft ] && echo /usr/sbin/iptables-nft; } || true)
  ip6_nft=$(command -v ip6tables-nft 2>/dev/null || { [ -e /usr/sbin/ip6tables-nft ] && echo /usr/sbin/ip6tables-nft; } || true)
  if [ -n "$ipt_nft" ]; then ln -sf "$ipt_nft" /opt/sbin/iptables; fi
  if [ -n "$ip6_nft" ]; then ln -sf "$ip6_nft" /opt/sbin/ip6tables; fi

  # dropbear: the operator key lands here (Keenetic flow uses /opt/etc/ssh —
  # on OpenWrt it is dropbear's authorized_keys; NEVER overwrite an existing one)
  if [ ! -e /etc/dropbear/authorized_keys ]; then
    mkdir -p /etc/dropbear
    touch /etc/dropbear/authorized_keys
    chmod 0600 /etc/dropbear/authorized_keys
    echo "kgate-install: /etc/dropbear/authorized_keys создан — добавь ПУБЛИЧНЫЙ ключ ноутбука:"
    echo "kgate-install:   echo '<ssh-ed25519 ...>' >> /etc/dropbear/authorized_keys"
  fi

  # operator intent: deploy seeds intent=up on Keenetic — same here (the
  # phase-1 nft table is an inert marker, so up is safe on a placeholder config)
  if [ ! -e /etc/kgate/intent ]; then
    echo up > /etc/kgate/intent
  fi
  /usr/bin/ndmc -c "kgate reapply" >/dev/null 2>&1 || true

  echo
  echo "kgate-install: стек установлен на OpenWrt ($TAG, Phase 1 beta, поле-необкатано):"
  echo "  /usr/bin/{kgate,sing-box,ndmc} + /bin/ndmc (symlink)"
  echo "  /etc/init.d/kgate (procd, enabled) · /etc/hotplug.d/iface/50-kgate-pins"
  echo "  /etc/kgate/{kgate.yaml,sing-box/} · intent=/etc/kgate/intent (up)"
  echo "  /opt compat: /opt/var->/var · /opt/etc/{kgate,sing-box}->/etc/kgate/... · /opt/sbin/{iptables,ip6tables}->*-nft"
  echo
  echo "далее:"
  echo "  1. заполни /etc/kgate/kgate.yaml (host, server_ip) и сервер/пароль в /etc/kgate/sing-box/config.json"
  echo "  2. mTLS-серты: на ноутбуке 'kgate certs' -> scp ~/.kgate/{ca.crt,server.crt,server.key} root@<router>:/etc/kgate/"
  echo "     (или сгенерируй на роутере: kgate certs -c /etc/kgate/kgate.yaml, затем забери client.* + ca.crt на ноутбук)"
  echo "  3. /etc/init.d/kgate start && /etc/init.d/kgate stack"
  echo "  4. Phase 1: демон/пины/self-heal/state работают; transparent client redirect (tproxy) — Phase 2 (см. docs/admin/install.md)"
}

# ---- branch 1: operator CLI ----------------------------------------------------

if [ "$PLATFORM" = "openwrt" ]; then
  install_openwrt
  exit 0
fi
if [ -n "$PLATFORM" ] && [ "$PLATFORM" != "cli" ]; then
  die "неизвестная платформа: $PLATFORM (разрешены: cli — по умолчанию, openwrt)"
fi

case "$(uname -m)" in
  x86_64)          ARCH="amd64" ;;
  aarch64 | arm64) ARCH="arm64" ;;
  *) echo "kgate-install: unsupported architecture: $(uname -m)" >&2; exit 1 ;;
esac

META=$(curl -sS ${GITHUB_TOKEN:+-H "Authorization: Bearer ${GITHUB_TOKEN}"} \
      "https://api.github.com/repos/${REPO}/releases/latest")
URL=$(printf '%s' "$META" | grep -o '"browser_download_url": *"[^"]*' \
      | grep "linux[-_]${ARCH}.tar.gz" | head -1 | cut -d'"' -f4)

[ -n "$URL" ] || { echo "kgate-install: archive for linux-${ARCH} not found in the latest release" >&2; exit 1; }

mkdir -p "$DEST"
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
echo "kgate-install: downloading $URL"
curl -sSL --retry 3 -o "$TMP/kgate.tar.gz" "$URL"
tar -xzf "$TMP/kgate.tar.gz" -C "$TMP"
mv -f "$TMP/kgate" "${DEST}/kgate"
chmod 0755 "${DEST}/kgate"

# shell completion (bash): генерится самим бинарем
COMPL_DIR="${KGATE_COMPL_DIR:-$HOME/.local/share/bash-completion/completions}"
if [ -x "${DEST}/kgate" ] && mkdir -p "$COMPL_DIR" 2>/dev/null \
   && "${DEST}/kgate" completion bash > "$COMPL_DIR/kgate" 2>/dev/null; then
  echo "kgate-install: bash-completion -> $COMPL_DIR/kgate (перелогинься или: source $COMPL_DIR/kgate)"
else
  echo "kgate-install: bash-completion НЕ установлен (не критично; руками: mkdir -p $COMPL_DIR && ${DEST}/kgate completion bash > $COMPL_DIR/kgate)"
fi

# man page: kgate.1 travels inside the release archive
if [ -f "$TMP/kgate.1" ]; then
  MANDIR="${KGATE_MANDIR:-$HOME/.local/share/man/man1}"
  mkdir -p "$MANDIR" && gzip -c "$TMP/kgate.1" > "$MANDIR/kgate.1.gz" 2>/dev/null \
    && echo "kgate-install: man page -> $MANDIR/kgate.1.gz (проверь MANPATH, если man не находит)"
fi

echo "kgate-install: installed to ${DEST}/kgate"
echo
echo "далее (primary path):"
if [ -t 0 ] && [ -x "${DEST}/kgate" ]; then
  # interactive terminal: run the wizard right here (piped stdin would starve the editor)
  "${DEST}/kgate" config create || echo "запусти вручную: ${DEST}/kgate config create"
else
  echo "  ${DEST}/kgate config create   # конфиг + редактор"
fi
echo "  kgate deploy                  # деплой на роутер"
