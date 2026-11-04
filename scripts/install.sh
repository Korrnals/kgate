#!/bin/sh
# kgate installer — downloads the latest CLI binary from GitHub Releases.
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/Korrnals/kgate/main/scripts/install.sh | sh
# For a PRIVATE repository export GITHUB_TOKEN with repo scope first.
set -eu

REPO="Korrnals/kgate"
DEST="${KGATE_DEST:-$HOME/.local/bin}"

case "$(uname -m)" in
  x86_64)          ARCH="amd64" ;;
  aarch64 | arm64) ARCH="arm64" ;;
  *) echo "kgate-install: unsupported architecture: $(uname -m)" >&2; exit 1 ;;
esac

AUTH=""
[ -n "${GITHUB_TOKEN:-}" ] && AUTH="-H \"Authorization: Bearer ${GITHUB_TOKEN}\""

META=$(curl -sS ${GITHUB_TOKEN:+-H "Authorization: Bearer ${GITHUB_TOKEN}"} \
      "https://api.github.com/repos/${REPO}/releases/latest")
URL=$(printf '%s' "$META" | grep -o '"browser_download_url": *"[^"]*' \
      | grep "linux-${ARCH}\"" | head -1 | cut -d'"' -f4)

[ -n "$URL" ] || { echo "kgate-install: asset for linux-${ARCH} not found in the latest release" >&2; exit 1; }

mkdir -p "$DEST"
echo "kgate-install: downloading $URL"
curl -sSL --retry 3 -o "${DEST}/kgate" "$URL"
chmod 0755 "${DEST}/kgate"

if [ ! -f "${HOME}/.kgate/kgate.yaml" ] && [ -w "${HOME}" ]; then
  curl -sSL --retry 3 -o "${HOME}/.kgate/kgate.yaml" \
    "https://raw.githubusercontent.com/${REPO}/main/examples/kgate.yaml.example" 2>/dev/null || true
fi

echo "kgate-install: installed to ${DEST}/kgate"
echo "next: kgate version && kgate status -c kgate.yaml"
