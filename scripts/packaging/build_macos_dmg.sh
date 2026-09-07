#!/usr/bin/env bash
# Build SecuraIQ-Agent.app + .dmg on macOS (requires macOS host or CI macos-*).
# Does not produce a fake DMG on other platforms — exit non-zero if not Darwin.
#
# Usage (from repo root):
#   bash scripts/packaging/build_macos_dmg.sh
#   bash scripts/packaging/build_macos_dmg.sh --version 1.1.0 --arch arm64
#
# Optional: SECURAIQ_AGENT_SIGN_IDENTITY for codesign (ad-hoc "-" is default).

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
VERSION=""
ARCH=""
OUT_DIR="${ROOT}/dist/agent-packages"
SIGN_IDENTITY="${SECURAIQ_AGENT_SIGN_IDENTITY:--}"

while [ $# -gt 0 ]; do
  case "$1" in
    --version) VERSION="$2"; shift 2 ;;
    --arch) ARCH="$2"; shift 2 ;;
    --out-dir) OUT_DIR="$2"; shift 2 ;;
    *) echo "Unknown: $1" >&2; exit 2 ;;
  esac
done

if [ "$(uname -s)" != "Darwin" ]; then
  echo "build_macos_dmg.sh must run on macOS (got $(uname -s))." >&2
  echo "Use GitHub Actions macos-* or a Mac. Windows/Linux hosts produce a macos .tar.gz interim only." >&2
  exit 1
fi

if [ -z "$VERSION" ]; then
  VERSION="$(python3 - <<'PY'
import re, pathlib
text = pathlib.Path("scripts/securaiq_agent.py").read_text(encoding="utf-8")
m = re.search(r'AGENT_VERSION\s*=\s*"([^"]+)"', text)
print(m.group(1) if m else "0.0.0")
PY
)"
fi
if [ -z "$ARCH" ]; then
  case "$(uname -m)" in
    arm64|aarch64) ARCH="arm64" ;;
    x86_64|amd64) ARCH="x64" ;;
    *) ARCH="$(uname -m)" ;;
  esac
fi

cd "$ROOT"
PY="${ROOT}/.venv/bin/python"
if [ ! -x "$PY" ]; then PY="$(command -v python3)"; fi

"$PY" -m pip install -q "pyinstaller>=6.3"
"$PY" -m PyInstaller --noconfirm --clean packaging/securaiq_agent.spec

BIN="${ROOT}/dist/SecuraIQ-Agent"
if [ ! -f "$BIN" ]; then
  echo "PyInstaller did not produce $BIN" >&2
  exit 1
fi

STAGE="${OUT_DIR}/_macos_stage"
APP_NAME="SecuraIQ Agent.app"
APP="${STAGE}/${APP_NAME}"
rm -rf "$STAGE"
mkdir -p "${APP}/Contents/MacOS" "${APP}/Contents/Resources"

cp "$BIN" "${APP}/Contents/MacOS/SecuraIQ-Agent"
chmod +x "${APP}/Contents/MacOS/SecuraIQ-Agent"
cp "${ROOT}/scripts/packaging/agent.env.example" "${APP}/Contents/Resources/agent.env.example"
cp "${ROOT}/scripts/packaging/QUICKSTART.md" "${APP}/Contents/Resources/QUICKSTART.md"

# First-run helper: if agent.env missing in Resources, print hint then exec
cat > "${APP}/Contents/MacOS/SecuraIQ-Agent-Launcher" <<'LAUNCH'
#!/bin/bash
DIR="$(cd "$(dirname "$0")" && pwd)"
RES="$(cd "$DIR/../Resources" && pwd)"
export SECURAIQ_AGENT_BUNDLE_RESOURCES="$RES"
# Prefer config next to the .app (user-writable) then Resources
APP_DIR="$(cd "$DIR/../.." && pwd)"
for cand in \
  "$HOME/Library/Application Support/SecuraIQ/agent.env" \
  "$APP_DIR/agent.env" \
  "$RES/agent.env"
do
  if [ -f "$cand" ]; then
    set -a
    # shellcheck disable=SC1090
    . "$cand"
    set +a
    break
  fi
done
exec "$DIR/SecuraIQ-Agent" "$@"
LAUNCH
chmod +x "${APP}/Contents/MacOS/SecuraIQ-Agent-Launcher"

cat > "${APP}/Contents/Info.plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleName</key>
  <string>SecuraIQ Agent</string>
  <key>CFBundleDisplayName</key>
  <string>SecuraIQ Agent</string>
  <key>CFBundleIdentifier</key>
  <string>com.securaiq.agent</string>
  <key>CFBundleVersion</key>
  <string>${VERSION}</string>
  <key>CFBundleShortVersionString</key>
  <string>${VERSION}</string>
  <key>CFBundleExecutable</key>
  <string>SecuraIQ-Agent-Launcher</string>
  <key>CFBundlePackageType</key>
  <string>APPL</string>
  <key>LSMinimumSystemVersion</key>
  <string>11.0</string>
  <key>NSHighResolutionCapable</key>
  <true/>
</dict>
</plist>
EOF

# Ad-hoc or developer identity (unsigned builds still open after Gatekeeper allow)
if command -v codesign >/dev/null 2>&1; then
  codesign --force --deep --sign "$SIGN_IDENTITY" "$APP" || true
fi

mkdir -p "$OUT_DIR"
DMG_NAME="SecuraIQ-Agent-${VERSION}-macos-${ARCH}.dmg"
DMG_PATH="${OUT_DIR}/${DMG_NAME}"
rm -f "$DMG_PATH"

VOL="SecuraIQ-Agent"
TMP_DMG="${OUT_DIR}/_tmp_${VOL}.dmg"
rm -f "$TMP_DMG"
hdiutil create -volname "$VOL" -srcfolder "$STAGE" -ov -format UDRW "$TMP_DMG"
hdiutil convert "$TMP_DMG" -format UDZO -o "$DMG_PATH"
rm -f "$TMP_DMG"
rm -rf "$STAGE"

echo "Built: $DMG_PATH"
ls -lh "$DMG_PATH"
echo "Gatekeeper: ad-hoc/unsigned builds may need System Settings → Privacy & Security → Open Anyway"
echo "  or: xattr -dr com.apple.quarantine \"/Applications/SecuraIQ Agent.app\""
