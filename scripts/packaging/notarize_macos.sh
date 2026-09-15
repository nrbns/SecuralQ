#!/usr/bin/env bash
# Optional macOS notarization scaffold (Apple notarization service).
# Lab: exits 0 when NOTARIZE_MACOS unset. Requires Apple ID app-specific password
# and Developer ID Application cert already used to codesign the .dmg/.pkg.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
PKG_DIR="${1:-$ROOT/dist/agent-packages}"

if [[ "${NOTARIZE_MACOS:-}" != "1" && "${NOTARIZE_MACOS:-}" != "true" && "${NOTARIZE_MACOS:-}" != "yes" ]]; then
  echo "notarize_macos: NOTARIZE_MACOS not set — skipping (scaffold only)."
  exit 0
fi

if [[ "$(uname -s)" != "Darwin" ]]; then
  echo "notarize_macos: must run on macOS" >&2
  exit 1
fi

: "${APPLE_ID:?APPLE_ID required}"
: "${APPLE_TEAM_ID:?APPLE_TEAM_ID required}"
: "${APPLE_APP_PASSWORD:?APPLE_APP_PASSWORD required (app-specific password)}"

shopt -s nullglob
ARTIFACTS=("$PKG_DIR"/*.dmg "$PKG_DIR"/*.pkg)
if [[ ${#ARTIFACTS[@]} -eq 0 ]]; then
  echo "notarize_macos: no .dmg/.pkg under $PKG_DIR"
  exit 0
fi

# Optional: codesign first if IDENTITY set
if [[ -n "${CODESIGN_IDENTITY:-}" ]]; then
  for a in "${ARTIFACTS[@]}"; do
    echo "codesign $a"
    codesign --force --options runtime --sign "$CODESIGN_IDENTITY" "$a" || true
  done
fi

for a in "${ARTIFACTS[@]}"; do
  echo "notarize $a"
  xcrun notarytool submit "$a" \
    --apple-id "$APPLE_ID" \
    --team-id "$APPLE_TEAM_ID" \
    --password "$APPLE_APP_PASSWORD" \
    --wait
  xcrun stapler staple "$a" || true
done
echo "notarize_macos: done"
