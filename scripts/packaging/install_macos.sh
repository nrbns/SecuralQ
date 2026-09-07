#!/usr/bin/env bash
# SecuraIQ Agent — macOS LaunchDaemon installer (package layout).
#
# Prefers SecuraIQ-Agent binary; falls back to securaiq_agent.py + python3.
#
# Usage:
#   sudo ./install.sh --server https://securaiq.example.com --token <agent_id>.<agent_key>

set -euo pipefail

SERVER=""
TOKEN=""
INTERVAL=60
SENTINEL_INTERVAL=10
INSECURE=0
LABEL="com.securaiq.agent"
INSTALL_DIR="/usr/local/securaiq/agent"
PLIST="/Library/LaunchDaemons/${LABEL}.plist"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

while [ $# -gt 0 ]; do
  case "$1" in
    --server) SERVER="$2"; shift 2 ;;
    --token) TOKEN="$2"; shift 2 ;;
    --interval) INTERVAL="$2"; shift 2 ;;
    --sentinel-interval) SENTINEL_INTERVAL="$2"; shift 2 ;;
    --insecure) INSECURE=1; shift ;;
    *) echo "Unknown argument: $1" >&2; exit 2 ;;
  esac
done

if [ "$(id -u)" -ne 0 ]; then
  echo "This installer needs root (writes to /Library/LaunchDaemons). Re-run with sudo." >&2
  exit 1
fi
if [ -z "$SERVER" ] || [ -z "$TOKEN" ]; then
  echo "Usage: sudo $0 --server https://securaiq.example.com --token <agent_id>.<agent_key>" >&2
  exit 2
fi

MODE=""
PROG_ARGS=()
if [ -f "$HERE/SecuraIQ-Agent" ]; then
  MODE="binary"
  install -d "$INSTALL_DIR"
  install -m 0755 "$HERE/SecuraIQ-Agent" "$INSTALL_DIR/SecuraIQ-Agent"
  PROG_ARGS=("$INSTALL_DIR/SecuraIQ-Agent")
elif [ -f "$HERE/securaiq_agent.py" ]; then
  MODE="python"
  PY3="$(command -v python3 || true)"
  [ -n "$PY3" ] || { echo "python3 not found — install Python 3.8+ or use a binary package." >&2; exit 1; }
  install -d "$INSTALL_DIR"
  install -m 0755 "$HERE/securaiq_agent.py" "$INSTALL_DIR/securaiq_agent.py"
  PROG_ARGS=("$PY3" "$INSTALL_DIR/securaiq_agent.py")
else
  echo "Neither SecuraIQ-Agent nor securaiq_agent.py found in $HERE" >&2
  exit 1
fi

[ -f "$HERE/QUICKSTART.md" ] && install -m 0644 "$HERE/QUICKSTART.md" "$INSTALL_DIR/QUICKSTART.md"
[ -f "$HERE/agent.env.example" ] && install -m 0644 "$HERE/agent.env.example" "$INSTALL_DIR/agent.env.example"

ARGS_XML=""
for a in "${PROG_ARGS[@]}"; do
  ARGS_XML="${ARGS_XML}
        <string>${a}</string>"
done
ARGS_XML="${ARGS_XML}
        <string>--interval</string>
        <string>${INTERVAL}</string>
        <string>--sentinel-interval</string>
        <string>${SENTINEL_INTERVAL}</string>"
if [ "$INSECURE" = "1" ]; then
  ARGS_XML="${ARGS_XML}
        <string>--insecure</string>"
fi

cat > "$PLIST" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>${LABEL}</string>
    <key>ProgramArguments</key>
    <array>${ARGS_XML}
    </array>
    <key>EnvironmentVariables</key>
    <dict>
        <key>SECURAIQ_SERVER</key>
        <string>${SERVER}</string>
        <key>SECURAIQ_TOKEN</key>
        <string>${TOKEN}</string>
    </dict>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>/var/log/securaiq-agent.log</string>
    <key>StandardErrorPath</key>
    <string>/var/log/securaiq-agent.err.log</string>
</dict>
</plist>
EOF
chmod 600 "$PLIST"
chown root:wheel "$PLIST"

launchctl unload "$PLIST" >/dev/null 2>&1 || true
launchctl load -w "$PLIST"

echo ""
echo "SecuraIQ agent installed as LaunchDaemon ($MODE)."
echo "  Status:  sudo launchctl list | grep securaiq"
echo "  Logs:    tail -f /var/log/securaiq-agent.log"
echo "  Stop:    sudo launchctl unload $PLIST"
echo "  Remove:  sudo launchctl unload $PLIST && sudo rm -f $PLIST && sudo rm -rf $INSTALL_DIR"
