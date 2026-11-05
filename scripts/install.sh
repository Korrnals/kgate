#!/bin/sh
# kgate installer — downloads the latest CLI binary from GitHub Releases
# and runs `kgate config create` (the primary onboarding path).
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/Korrnals/kgate/main/scripts/install.sh | sh
# For rate-limited environments export GITHUB_TOKEN (optional; the repository
# is public — anonymous downloads work).
set -eu

REPO="Korrnals/kgate"
DEST="${KGATE_DEST:-$HOME/.local/bin}"

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
