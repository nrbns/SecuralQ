#!/usr/bin/env bash
# SecuraIQ agent — macOS launchd installer (DEVELOPER FALLBACK).
#
# Prefer the packaged *.tar.gz / *.dmg from dist/agent-packages/ (embeds install.sh).
# This script remains for labs without a built package.
#
# Installs the agent as a LaunchDaemon: starts at boot, restarts
# automatically if it exits, runs unattended (no logged-in user needed) —
# the same operating model as the Wazuh agent.
#
# Usage (run as root, e.g. with sudo, on the Mac you want to monitor):
#   sudo ./install_agent_macos.sh --server https://securaiq.example.com --token <agent_id>.<agent_key>

set -euo pipefail

SERVER=""
TOKEN=""
INTERVAL=60
SENTINEL_INTERVAL=10
LABEL="com.securaiq.agent"
INSTALL_DIR="/usr/local/securaiq/agent"
PLIST="/Library/LaunchDaemons/${LABEL}.plist"
SCRIPT_SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/securaiq_agent.py"

while [ $# -gt 0 ]; do
  case "$1" in
    --server) SERVER="$2"; shift 2 ;;
    --token) TOKEN="$2"; shift 2 ;;
    --interval) INTERVAL="$2"; shift 2 ;;
    --sentinel-interval) SENTINEL_INTERVAL="$2"; shift 2 ;;
    *) echo "Unknown argument: $1" >&2; exit 2 ;;
  esac
done

if [ "$(id -u)" -ne 0 ]; then
  echo "This installer needs root (it writes to /Library/LaunchDaemons). Re-run with sudo." >&2
  exit 1
fi
if [ -z "$SERVER" ] || [ -z "$TOKEN" ]; then
  echo "Usage: sudo $0 --server https://securaiq.example.com --token <agent_id>.<agent_key>" >&2
  exit 2
fi
if [ ! -f "$SCRIPT_SRC" ]; then
  echo "Could not find securaiq_agent.py next to this installer at $SCRIPT_SRC" >&2
  echo "Download both files together, e.g.:" >&2
  echo "  curl -fsSL <server>/api/agents/install-script -o securaiq_agent.py" >&2
  echo "  curl -fsSL <server>/api/agents/install-script/macos -o install_agent_macos.sh" >&2
  exit 1
fi
PY3="$(command -v python3 || true)"
[ -n "$PY3" ] || { echo "python3 not found on PATH — install Python 3.8+ (e.g. via Xcode CLT or Homebrew) first." >&2; exit 1; }

mkdir -p "$INSTALL_DIR"
install -m 0755 "$SCRIPT_SRC" "$INSTALL_DIR/securaiq_agent.py"

cat > "$PLIST" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>${LABEL}</string>
    <key>ProgramArguments</key>
    <array>
        <string>${PY3}</string>
        <string>${INSTALL_DIR}/securaiq_agent.py</string>
        <string>--interval</string>
        <string>${INTERVAL}</string>
        <string>--sentinel-interval</string>
        <string>${SENTINEL_INTERVAL}</string>
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
# The token lives inside this plist — restrict it to root, same as the
# systemd installer's env file.
chmod 600 "$PLIST"
chown root:wheel "$PLIST"

launchctl unload "$PLIST" >/dev/null 2>&1 || true
launchctl load -w "$PLIST"

echo ""
echo "SecuraIQ agent installed and running as a LaunchDaemon."
echo "  Status:  sudo launchctl list | grep securaiq"
echo "  Logs:    tail -f /var/log/securaiq-agent.log"
echo "  Stop:    sudo launchctl unload $PLIST"
echo "  Remove:  sudo launchctl unload $PLIST && sudo rm -f $PLIST && sudo rm -rf $INSTALL_DIR"
