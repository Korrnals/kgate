#!/usr/bin/env bash
# build-ipk.sh <VERSION> <sing-box-arm64-binary>
# Собирает Entware .ipk. ФОРМАТ ВАЖЕН: ipk для Entware/opkg — это
# gzip(tar), внутри tar'а три файла:
#   ./debian-binary   (текст "2.0\n")
#   ./control.tar.gz  (control, conffiles, postinst)
#   ./data.tar.gz     (дерево /opt)
# Классический Debian ar-формат этим opkg НЕ читается («Malformed package»).
set -euo pipefail
VER=${1:?usage: build-ipk.sh <version> <kgate-arm64> <sing-box-arm64>}
KGATE_BIN=${2:?}
SB=${3:?}
RULESETS_DIR=${RULESETS_DIR:-}
ARCH="aarch64-3.10"
PKG="dist/kgate_${VER}-1_${ARCH}.ipk"

T=$(mktemp -d)
trap 'rm -rf "$T"' EXIT
mkdir -p "$T/debian-binary" "$T/control" "$T/data/opt/sbin" "$T/data/opt/etc/init.d" \
         "$T/data/opt/etc/kgate" "$T/data/opt/etc/sing-box/rulesets"

# 1) debian-binary
printf '2.0\n' > "$T/debian-binary/debian-binary"

# 2) control
cat > "$T/control/control" <<EOF
Package: kgate
Version: ${VER}-1
Architecture: ${ARCH}
Maintainer: Korrnals
Depends: iptables, openssh-server, ca-bundle, curl
Description: VPN-stack supervisor for Netcraze/Keenetic (sing-box + tolerant socks relay + mTLS API)
EOF
cat > "$T/control/conffiles" <<EOF
/opt/etc/kgate/kgate.yaml
/opt/etc/sing-box/config.json
EOF
cat > "$T/control/postinst" <<'EOF'
#!/bin/sh
echo "kgate: отредактируйте /opt/etc/kgate/kgate.yaml и /opt/etc/sing-box/config.json,"
echo "затем: /opt/etc/init.d/S99kgate start"
EOF
chmod 0755 "$T/control/postinst"

# 3) data
cp "$KGATE_BIN" "$T/data/opt/sbin/kgate"
cp "$SB"      "$T/data/opt/sbin/sing-box"
# init script: REQUIRED, single source of truth = examples/ (deploy/S99kgate was
# an empty legacy placeholder — never ship it silently)
test -f examples/S99kgate || { echo "FATAL: examples/S99kgate missing" >&2; exit 1; }
[ -s examples/S99kgate ] || { echo "FATAL: examples/S99kgate is empty" >&2; exit 1; }
cp examples/S99kgate "$T/data/opt/etc/init.d/S99kgate" && chmod 0755 "$T/data/opt/etc/init.d/S99kgate"
if [ -f local/etc/sing-box/config.json ]; then cp local/etc/sing-box/config.json "$T/data/opt/etc/sing-box/config.json"; fi
if [ -f examples/etc/sing-box/config.json ] && [ ! -f "$T/data/opt/etc/sing-box/config.json" ]; then cp examples/etc/sing-box/config.json "$T/data/opt/etc/sing-box/config.json"; fi
if [ -d local/etc/sing-box/rulesets ]; then cp local/etc/sing-box/rulesets/*.srs "$T/data/opt/etc/sing-box/rulesets/" 2>/dev/null || true
elif [ -n "$RULESETS_DIR" ] && [ -d "$RULESETS_DIR" ]; then cp "$RULESETS_DIR"/*.srs "$T/data/opt/etc/sing-box/rulesets/" 2>/dev/null || true; fi
if [ -f local/etc/kgate/kgate.yaml ]; then cp local/etc/kgate/kgate.yaml "$T/data/opt/etc/kgate/kgate.yaml";
elif [ -f examples/kgate.yaml.example ]; then cp examples/kgate.yaml.example "$T/data/opt/etc/kgate/kgate.yaml"; fi
chmod 0755 "$T/data/opt/sbin/kgate"

# 4) tar внутри tar: control.tar.gz, data.tar.gz
tar --format=ustar --owner=0 --group=0 -czf "$T/control.tar.gz" -C "$T/control" control conffiles postinst
tar --format=ustar --owner=0 --group=0 -czf "$T/data.tar.gz" -C "$T/data" opt

# 5) внешний tar + gzip = итоговый .ipk
mkdir -p dist
tar --format=ustar --owner=0 --group=0 -czf "$PKG" -C "$T" ./debian-binary ./control.tar.gz ./data.tar.gz

echo "IPK: $PKG ($(stat -c%s "$PKG") байт)"
