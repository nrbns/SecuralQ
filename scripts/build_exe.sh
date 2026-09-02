#!/usr/bin/env bash
# Build a standalone SecuraIQ binary (Linux/macOS) from the same PyInstaller
# spec the Windows build uses (packaging/securaiq.spec). Requires the project
# venv from ./scripts/start.sh (or ./scripts/run_proper.sh) — run that once
# first if .venv doesn't exist yet.
#
# NOTE: PyInstaller does not cross-compile. Run this script ON the OS you
# want a binary for — a Linux box produces a Linux binary, a Mac produces a
# macOS binary. Build on each target platform separately (or in CI, one
# runner per OS) if you need all three.
set -euo pipefail
cd "$(dirname "$0")/.."

ONEFILE=0
for arg in "$@"; do
  case "$arg" in
    --onefile|-OneFile) ONEFILE=1 ;;
  esac
done

PY=".venv/bin/python"
if [ ! -x "$PY" ]; then
  echo "Missing .venv. Run ./scripts/start.sh once, then re-run this script." >&2
  exit 1
fi

echo "Installing PyInstaller..."
"$PY" -m pip install -q "pyinstaller>=6.3"

SPEC="packaging/securaiq.spec"
echo "Building from $SPEC (this can take several minutes)..."
if [ "$ONEFILE" -eq 1 ]; then
  echo "Note: --onefile is not used; the spec is onedir so RAG/torch start in seconds, not minutes."
fi
"$PY" -m PyInstaller --noconfirm --clean "$SPEC"

BIN="dist/SecuraIQ/SecuraIQ"
if [ ! -f "$BIN" ]; then
  echo "Build finished but $BIN was not created." >&2
  exit 1
fi
chmod +x "$BIN"

echo ""
echo "Built: $BIN"
echo "Run it: ./dist/SecuraIQ/SecuraIQ   (keep the whole dist/SecuraIQ folder together)"
if [ "$(uname -s)" = "Darwin" ]; then
  echo "First launch on macOS: the binary is unsigned, so Gatekeeper will block a"
  echo "double-click. Either run it from Terminal (above), or right-click ->"
  echo "Open -> Open once in Finder to approve it."
fi
echo "UI: http://127.0.0.1:8080 — data and .env are created next to the binary."
