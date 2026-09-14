#!/usr/bin/env bash
# Build an .rpm wrapping SecuraIQ-Agent linux tar.gz. Requires rpmbuild or fpm.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
PKG_DIR="${ROOT}/dist/agent-packages"
OUT_DIR="${OUT_DIR:-$PKG_DIR}"
VERSION="${1:-}"
ARCH="${2:-x86_64}"

mkdir -p "$OUT_DIR"
TGZ="$(ls -1t "$PKG_DIR"/SecuraIQ-Agent-*-linux-*.tar.gz 2>/dev/null | head -1 || true)"
if [[ -z "$TGZ" || ! -f "$TGZ" ]]; then
  echo "No linux tar.gz in $PKG_DIR" >&2
  exit 2
fi
if [[ -z "$VERSION" ]]; then
  VERSION="$(basename "$TGZ" | sed -n 's/SecuraIQ-Agent-\([0-9.]*\)-linux.*/\1/p')"
fi
VERSION="${VERSION:-0.0.0}"

if command -v fpm >/dev/null 2>&1; then
  STAGE="$(mktemp -d)"
  trap 'rm -rf "$STAGE"' EXIT
  tar -xzf "$TGZ" -C "$STAGE"
  BIN="$(find "$STAGE" -maxdepth 3 -type f \( -name 'SecuraIQ-Agent' -o -name 'securaiq_agent.py' \) | head -1)"
  mkdir -p "$STAGE/root/usr/bin" "$STAGE/root/etc/securaiq" "$STAGE/root/lib/systemd/system"
  install -m 0755 "$BIN" "$STAGE/root/usr/bin/securaiq-agent"
  cp "$ROOT/scripts/packaging/agent.env.example" "$STAGE/root/etc/securaiq/agent.env.example"
  cat > "$STAGE/root/lib/systemd/system/securaiq-agent.service" <<'UNIT'
[Unit]
Description=SecuraIQ Agent
After=network-online.target
[Service]
Type=simple
EnvironmentFile=-/etc/securaiq/agent.env
ExecStart=/usr/bin/securaiq-agent
Restart=on-failure
[Install]
WantedBy=multi-user.target
UNIT
  OUT="$OUT_DIR/SecuraIQ-Agent-${VERSION}-linux-${ARCH}.rpm"
  fpm -s dir -t rpm -n securaiq-agent -v "$VERSION" -a "$ARCH" \
    --description "SecuraIQ endpoint agent" \
    -C "$STAGE/root" \
    -p "$OUT" \
    usr etc lib
  echo "Built RPM: $OUT"
  exit 0
fi

echo "fpm not found. Install fpm (gem install fpm) or use build_deb.sh on Debian hosts." >&2
echo "RPM scaffold expects an existing linux tar.gz from build_agent_packages.py." >&2
exit 2
