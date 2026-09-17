#!/usr/bin/env bash
# Optional RPM package signing (rpmsign). Never commits keys.
# Lab: exits 0 when SIGN_RPM unset. Production: set SIGN_RPM=1 + GPG key material.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
PKG_DIR="${1:-$ROOT/dist/agent-packages}"

if [[ "${SIGN_RPM:-}" != "1" && "${SIGN_RPM:-}" != "true" && "${SIGN_RPM:-}" != "yes" ]]; then
  echo "sign_rpm: SIGN_RPM not set — skipping package signing (scaffold only)."
  exit 0
fi

shopt -s nullglob
RPMS=("$PKG_DIR"/*.rpm)
if [[ ${#RPMS[@]} -eq 0 ]]; then
  echo "sign_rpm: no .rpm under $PKG_DIR"
  exit 0
fi

if ! command -v rpmsign >/dev/null 2>&1 && ! command -v rpm >/dev/null 2>&1; then
  echo "sign_rpm: install rpm-sign / rpmdevtools" >&2
  exit 1
fi

if [[ -n "${GPG_PRIVATE_KEY_FILE:-}" && -f "$GPG_PRIVATE_KEY_FILE" ]]; then
  gpg --batch --import "$GPG_PRIVATE_KEY_FILE"
elif [[ -n "${GPG_PRIVATE_KEY:-}" ]]; then
  echo "$GPG_PRIVATE_KEY" | gpg --batch --import
fi

KEY_ID="${GPG_KEY_ID:-}"
for rpm in "${RPMS[@]}"; do
  echo "Signing $rpm"
  if [[ -n "$KEY_ID" ]]; then
    rpmsign --addsign -k "$KEY_ID" "$rpm" 2>/dev/null || rpm --addsign -k "$KEY_ID" "$rpm"
  else
    rpmsign --addsign "$rpm" 2>/dev/null || rpm --addsign "$rpm"
  fi
done
echo "sign_rpm: done"
