#!/usr/bin/env bash
# Optional Debian package signing (dpkg-sig / debsigs). Never commits keys.
# Lab: exits 0 when SIGN_DEB unset. Production: set SIGN_DEB=1 + GPG key material.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
PKG_DIR="${1:-$ROOT/dist/agent-packages}"

if [[ "${SIGN_DEB:-}" != "1" && "${SIGN_DEB:-}" != "true" && "${SIGN_DEB:-}" != "yes" ]]; then
  echo "sign_deb: SIGN_DEB not set — skipping package signing (scaffold only)."
  exit 0
fi

shopt -s nullglob
DEBS=("$PKG_DIR"/*.deb)
if [[ ${#DEBS[@]} -eq 0 ]]; then
  echo "sign_deb: no .deb under $PKG_DIR"
  exit 0
fi

if ! command -v dpkg-sig >/dev/null 2>&1 && ! command -v debsigs >/dev/null 2>&1; then
  echo "sign_deb: install dpkg-sig or debsigs" >&2
  exit 1
fi

# Import key from CI secret file if provided (base64-decoded by workflow).
if [[ -n "${GPG_PRIVATE_KEY_FILE:-}" && -f "$GPG_PRIVATE_KEY_FILE" ]]; then
  gpg --batch --import "$GPG_PRIVATE_KEY_FILE"
fi

KEY_ID="${GPG_KEY_ID:-}"
for deb in "${DEBS[@]}"; do
  echo "Signing $deb"
  if command -v dpkg-sig >/dev/null 2>&1; then
    if [[ -n "$KEY_ID" ]]; then
      dpkg-sig --sign builder -k "$KEY_ID" "$deb"
    else
      dpkg-sig --sign builder "$deb"
    fi
  else
    debsigs --sign=origin "$deb"
  fi
done
echo "sign_deb: done"
