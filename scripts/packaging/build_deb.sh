#!/usr/bin/env bash
# Build a .deb that wraps an existing SecuraIQ-Agent linux tar.gz / binary.
# Requires: dpkg-deb (Debian/Ubuntu). Package signing (dpkg-sig) is a separate CI step.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
PKG_DIR="${ROOT}/dist/agent-packages"
OUT_DIR="${OUT_DIR:-$PKG_DIR}"
VERSION="${1:-}"
ARCH="${2:-amd64}"

mkdir -p "$OUT_DIR"
TGZ="$(ls -1t "$PKG_DIR"/SecuraIQ-Agent-*-linux-*.tar.gz 2>/dev/null | head -1 || true)"
if [[ -z "$TGZ" || ! -f "$TGZ" ]]; then
  echo "No linux tar.gz in $PKG_DIR — run: python scripts/build_agent_packages.py --platform linux" >&2
  exit 2
fi
if [[ -z "$VERSION" ]]; then
  VERSION="$(basename "$TGZ" | sed -n 's/SecuraIQ-Agent-\([0-9.]*\)-linux.*/\1/p')"
fi
VERSION="${VERSION:-0.0.0}"

STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT
NAME="securaiq-agent"
DEB_ROOT="$STAGE/${NAME}_${VERSION}_${ARCH}"
mkdir -p "$DEB_ROOT/DEBIAN" \
  "$DEB_ROOT/usr/bin" \
  "$DEB_ROOT/etc/securaiq" \
  "$DEB_ROOT/var/lib/securaiq" \
  "$DEB_ROOT/var/log/securaiq" \
  "$DEB_ROOT/lib/systemd/system"

tar -xzf "$TGZ" -C "$STAGE"
# Find binary or script layout
BIN="$(find "$STAGE" -maxdepth 3 -type f \( -name 'SecuraIQ-Agent' -o -name 'securaiq_agent.py' \) | head -1)"
if [[ -z "$BIN" ]]; then
  echo "Could not find agent binary/script inside $TGZ" >&2
  exit 1
fi
install -m 0755 "$BIN" "$DEB_ROOT/usr/bin/securaiq-agent"
cp "$ROOT/scripts/packaging/agent.env.example" "$DEB_ROOT/etc/securaiq/agent.env.example"

cat > "$DEB_ROOT/lib/systemd/system/securaiq-agent.service" <<'UNIT'
[Unit]
Description=SecuraIQ Agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
EnvironmentFile=-/etc/securaiq/agent.env
ExecStart=/usr/bin/securaiq-agent
Restart=on-failure
RestartSec=5
User=root

[Install]
WantedBy=multi-user.target
UNIT

cat > "$DEB_ROOT/DEBIAN/control" <<EOF
Package: ${NAME}
Version: ${VERSION}
Section: admin
Priority: optional
Architecture: ${ARCH}
Maintainer: SecuraIQ <ops@securaiq.local>
Description: SecuraIQ endpoint agent (authorized labs / owned hosts)
 Inventory, controls, and telemetry agent for the SecuraIQ control plane.
EOF

cat > "$DEB_ROOT/DEBIAN/postinst" <<'EOF'
#!/bin/sh
set -e
if command -v systemctl >/dev/null 2>&1; then
  systemctl daemon-reload || true
  systemctl enable securaiq-agent.service || true
fi
echo "SecuraIQ Agent installed. Copy /etc/securaiq/agent.env.example to agent.env and set SECURAIQ_SERVER + token."
EOF
chmod 0755 "$DEB_ROOT/DEBIAN/postinst"

if ! command -v dpkg-deb >/dev/null 2>&1; then
  echo "dpkg-deb not found — scaffold written under $DEB_ROOT but .deb not built." >&2
  exit 2
fi

OUT="$OUT_DIR/SecuraIQ-Agent-${VERSION}-linux-${ARCH}.deb"
dpkg-deb --build "$DEB_ROOT" "$OUT"
echo "Built DEB: $OUT"
echo "Sign next (optional): dpkg-sig --sign builder \"$OUT\""
