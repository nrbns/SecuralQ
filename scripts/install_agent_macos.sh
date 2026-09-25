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
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCRIPT_SRC="$HERE/securaiq_agent.py"
BIN_SRC="$HERE/SecuraIQ-Agent"

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
case "$SERVER" in
  *localhost*|*127.0.0.1*|*[::1]*)
    echo "WARNING: --server is localhost. On another Mac that means THIS machine, not SecuraIQ." >&2
    echo "Use the SecuraIQ LAN IP (e.g. http://192.168.x.x:8080) and start the console with LAN bind." >&2
    ;;
esac
USE_BIN=0
if [ -x "$BIN_SRC" ] || [ -f "$BIN_SRC" ]; then
  USE_BIN=1
elif [ ! -f "$SCRIPT_SRC" ]; then
  echo "Neither SecuraIQ-Agent nor securaiq_agent.py is next to this installer." >&2
  echo "On the customer Mac copy the macOS package from Agents, not only this .sh." >&2
  exit 1
fi
PY3="$(command -v python3 || true)"
if [ "$USE_BIN" -eq 0 ] && [ -z "$PY3" ]; then
  echo "python3 not found and no SecuraIQ-Agent binary. Install Python 3.8+ or use the packaged .tar.gz/.dmg." >&2
  exit 1
fi

mkdir -p "$INSTALL_DIR"
if [ "$USE_BIN" -eq 1 ]; then
  install -m 0755 "$BIN_SRC" "$INSTALL_DIR/SecuraIQ-Agent"
  PROG="$INSTALL_DIR/SecuraIQ-Agent"
  ARG1=""
else
  install -m 0755 "$SCRIPT_SRC" "$INSTALL_DIR/securaiq_agent.py"
  PROG="$PY3"
  ARG1="$INSTALL_DIR/securaiq_agent.py"
fi

# launchd needs a static argv; include the python script only when not using the binary.
if [ -n "${ARG1}" ]; then
  PROG_ARGS="        <string>${PROG}</string>
        <string>${ARG1}</string>"
else
  PROG_ARGS="        <string>${PROG}</string>"
fi

cat > "$PLIST" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>${LABEL}</string>
    <key>ProgramArguments</key>
    <array>
${PROG_ARGS}
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
