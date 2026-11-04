#!/usr/bin/env bash
# build-feed.sh — собирает opkg-фид (Packages-индекс + .ipk) из dist/.
# Формат индекса совместим с opkg (Entware): стanze Package/Version/Architecture/
# Filename/SHA256sum/Size/Description, файлы Packages и Packages.gz рядом с .ipk.
# Публикация: содержимое out-dir на любой HTTP-хостинг (gh-pages, web-server),
# на роутере: src/gz kgate https://<host>/<путь>/ && opkg update && opkg install kgate
set -euo pipefail
SRC=${1:-dist}
OUT=${2:-feed}
ARCH_FILTER=${ARCH_FILTER:-aarch64-3.10}

command -v ar >/dev/null || { echo "нужен ar (binutils)"; exit 1; }
mkdir -p "$OUT"
rm -f "$OUT"/Packages "$OUT"/Packages.gz "$OUT"/kgate_*.ipk

count=0
{
for ipk in "$SRC"/kgate_*_${ARCH_FILTER}.ipk; do
  [ -f "$ipk" ] || continue
  tmp=$(mktemp -d)
  ar p "$ipk" control.tar.gz | tar -xzf - -C "$tmp" 2>/dev/null
  pkg=$(grep -E '^Package:'    "$tmp/control" | cut -d' ' -f2-)
  ver=$(grep -E '^Version:'    "$tmp/control" | cut -d' ' -f2-)
  arch=$(grep -E '^Architecture:' "$tmp/control" | cut -d' ' -f2-)
  desc=$(grep -E '^Description:' "$tmp/control" | cut -d' ' -f2-)
  size=$(stat -c%s "$ipk")
  sha=$(sha256sum "$ipk" | awk '{print $1}')
  fn="./$(basename "$ipk")"
  cp -f "$ipk" "$OUT/"
  cat <<EOF
Package: $pkg
Version: $ver
Architecture: $arch
Maintainer: Korrnals
Depends: iptables, openssh-server, ca-bundle
Filename: $fn
SHA256sum: $sha
Size: $size
Description: $desc

EOF
  rm -rf "$tmp"
  count=$((count+1))
done
} > "$OUT/Packages"

if [ "$count" -eq 0 ]; then
  echo "нет .ipk для архитектуры $ARCH_FILTER в $SRC" >&2
  exit 1
fi
gzip -kf "$OUT/Packages"
echo "feed: $OUT — Packages, Packages.gz, ipk: $count (arch: $ARCH_FILTER)"
