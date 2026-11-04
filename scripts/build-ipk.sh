#!/usr/bin/env bash
# build-ipk.sh <VERSION> <sing-box-arm64-binary>
# Собирает Entware .ipk: бинарник kgate + init-скрипт + конфиги + rulesets.
set -euo pipefail
VER=${1:?usage: build-ipk.sh <version> <sing-box-binary>}
SB=${2:?}
ARCH="aarch64-3.10"
PKG="dist/kgate_${VER}-1_${ARCH}.ipk"
RULESETS_URL="${RULESETS_URL:-https://github.com/runetfreedom/ru-sing-box/releases/latest/download/sing-box.zip}"

command -v ar >/dev/null || { echo "нужен ar (binutils)"; exit 1; }

rm -rf build/ipk
mkdir -p build/ipk/CONTROL build/ipk/opt/sbin build/ipk/opt/etc/init.d \
         build/ipk/opt/etc/kgate build/ipk/opt/etc/sing-box/rulesets build/root/opt/etc/ssh

# data
cp "$SB" build/ipk/opt/sbin/kgate && chmod 0755 build/ipk/opt/sbin/kgate
cp examples/S99kgate build/ipk/opt/etc/init.d/S99kgate && chmod 0755 build/ipk/opt/etc/init.d/S99kgate
cp examples/kgate.yaml.example build/ipk/opt/etc/kgate/kgate.yaml
cp examples/etc/sing-box/config.json build/ipk/opt/etc/sing-box/config.json
cp "${ETC_DIR:-examples/etc}/ssh/authorized_keys" build/root/opt/etc/ssh/authorized_keys 2>/dev/null || true

# rulesets (для локальных rule_set в конфиге); тянем свежие с runetfreedom
if curl -sSL --max-time 60 -o build/rulesets.zip "$RULESETS_URL"; then
  unzip -o -j build/rulesets.zip '*.srs' -d build/ipk/opt/etc/sing-box/rulesets/ >/dev/null 2>&1 || true
fi
N=$(find build/ipk/opt/etc/sing-box/rulesets -name '*.srs' 2>/dev/null | wc -l)
echo "rulesets в пакете: $N"

# CONTROL
cat > build/ipk/CONTROL/control <<EOF
Package: kgate
Version: ${VER}-1
Architecture: ${ARCH}
Maintainer: Korrnals
Section: net
Priority: optional
Depends: iptables, openssh-server, ca-bundle, curl, unzip
Description: VPN-stack supervisor for Netcraze/Keenetic (sing-box + tolerant socks relay + mTLS API)
 kgate supervises the home VPN stack: runs sing-box, keeps DNS rules applied,
 auto-raises the ndm Proxy0 tunnel, exposes an mTLS API for the kgate CLI.
EOF
cat > build/ipk/CONTROL/conffiles <<EOF
/opt/etc/kgate/kgate.yaml
/opt/etc/sing-box/config.json
EOF
cat > build/ipk/CONTROL/postinst <<'EOF'
#!/bin/sh
echo "kgate: отредактируйте /opt/etc/kgate/kgate.yaml и /opt/etc/sing-box/config.json,"
echo "затем: /opt/etc/init.d/S99kgate start"
EOF
chmod 0755 build/ipk/CONTROL/postinst
printf '2.0\n' > build/ipk/debian-binary

(cd build/ipk/CONTROL && tar -czf ../control.tar.gz .)
(cd build/ipk && tar -czf data.tar.gz ./opt ./CONTROL/conffiles)
(cd build/ipk && ar rc kgate.ipk debian-binary control.tar.gz data.tar.gz)
mv build/ipk/kgate.ipk "$PKG"
rm -rf build/ipk
echo "IPK: $PKG"
