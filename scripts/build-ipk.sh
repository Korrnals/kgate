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
OUT_DIR=${IPK_DIR:-dist}
PKG="${OUT_DIR}/kgate_${VER}-1_${ARCH}.ipk"

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
Depends: iptables, openssh-server
Description: VPN-stack supervisor for Netcraze/Keenetic (sing-box + tolerant socks relay + mTLS API)
EOF
cat > "$T/control/conffiles" <<'EOF'
EOF
cat > "$T/control/postinst" <<'EOF'
#!/bin/sh
# First install: seed live configs from the shipped templates. Files created
# here are NOT opkg-owned, so package remove/reinstall never clobbers them.
[ -f /opt/etc/kgate/kgate.yaml ] || cp /opt/etc/kgate/kgate.yaml.example /opt/etc/kgate/kgate.yaml
[ -f /opt/etc/sing-box/config.json ] || cp /opt/etc/sing-box/config.json.example /opt/etc/sing-box/config.json
echo "kgate: fill in the real server/password in /opt/etc/sing-box/config.json"
echo "kgate: (placeholders HY2_PASSWORD / hy2.example.com WILL NOT work),"
echo "kgate: then: /opt/etc/init.d/S99kgate start"
EOF
chmod 0755 "$T/control/postinst"

# CA pool fallback: firmware normally ships /etc/ssl/certs, but Entware
# firmware variants without it still get working TLS (sing-box + kgate update)
# via SSL_CERT_FILE. Vendored by `make update-ca-bundle`, refreshed on release.
test -f assets/ca-bundle.crt || { echo "FATAL: assets/ca-bundle.crt missing (make update-ca-bundle)" >&2; exit 1; }
[ -s assets/ca-bundle.crt ] || { echo "FATAL: assets/ca-bundle.crt is empty" >&2; exit 1; }
cp assets/ca-bundle.crt "$T/data/opt/etc/kgate/ca-bundle.crt"

# 3) data — binaries + init + ndm script + TEMPLATES (as *.example) + rulesets.
# Live configs are never shipped as package files: postinst seeds them from the
# templates on first install, so remove/reinstall cannot destroy user configs.
cp "$KGATE_BIN" "$T/data/opt/sbin/kgate"
cp "$SB"      "$T/data/opt/sbin/sing-box"
# init script: REQUIRED, single source of truth = examples/ (deploy/S99kgate was
# an empty legacy placeholder — never ship it silently)
test -f examples/S99kgate || { echo "FATAL: examples/S99kgate missing" >&2; exit 1; }
[ -s examples/S99kgate ] || { echo "FATAL: examples/S99kgate is empty" >&2; exit 1; }
cp examples/S99kgate "$T/data/opt/etc/init.d/S99kgate" && chmod 0755 "$T/data/opt/etc/init.d/S99kgate"
# ndm config script: REQUIRED (Proxy0/pins/DNS/policies), applied via kgate apply
# or manually with KGATE_SERVER_IP=<ip> sh /opt/etc/ndm-commands.sh
test -f examples/ndm-commands.sh || { echo "FATAL: examples/ndm-commands.sh missing" >&2; exit 1; }
[ -s examples/ndm-commands.sh ] || { echo "FATAL: examples/ndm-commands.sh is empty" >&2; exit 1; }
cp examples/ndm-commands.sh "$T/data/opt/etc/ndm-commands.sh" && chmod 0755 "$T/data/opt/etc/ndm-commands.sh"
# sing-box config template (sanitized placeholders in a clean checkout)
if [ -f local/etc/sing-box/config.json ]; then
  cp local/etc/sing-box/config.json "$T/data/opt/etc/sing-box/config.json.example"
elif [ -f examples/etc/sing-box/config.json ]; then
  cp examples/etc/sing-box/config.json "$T/data/opt/etc/sing-box/config.json.example"
else
  echo "FATAL: no sing-box config template found (local/etc or examples/etc)" >&2; exit 1
fi
# operator/daemon yaml template
test -f examples/kgate.yaml.example || { echo "FATAL: examples/kgate.yaml.example missing" >&2; exit 1; }
cp examples/kgate.yaml.example "$T/data/opt/etc/kgate/kgate.yaml.example"
# rulesets: real local copies first, then RULESETS_DIR override, then vendored
if [ -d local/etc/sing-box/rulesets ]; then
  cp local/etc/sing-box/rulesets/*.srs "$T/data/opt/etc/sing-box/rulesets/" 2>/dev/null || true
elif [ -n "$RULESETS_DIR" ] && [ -d "$RULESETS_DIR" ]; then
  cp "$RULESETS_DIR"/*.srs "$T/data/opt/etc/sing-box/rulesets/" 2>/dev/null || true
elif [ -d examples/etc/sing-box/rulesets ]; then
  cp examples/etc/sing-box/rulesets/*.srs "$T/data/opt/etc/sing-box/rulesets/" 2>/dev/null || true
fi
chmod 0755 "$T/data/opt/sbin/kgate"

# 4) tar внутри tar: control.tar.gz, data.tar.gz
tar --format=ustar --owner=0 --group=0 -czf "$T/control.tar.gz" -C "$T/control" control conffiles postinst
tar --format=ustar --owner=0 --group=0 -czf "$T/data.tar.gz" -C "$T/data" opt

# 5) внешний tar + gzip = итоговый .ipk
mkdir -p "$OUT_DIR"
tar --format=ustar --owner=0 --group=0 -czf "$PKG" -C "$T" ./debian-binary ./control.tar.gz ./data.tar.gz

echo "IPK: $PKG ($(stat -c%s "$PKG") байт)"
