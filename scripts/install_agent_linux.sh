#!/usr/bin/env bash
# SecuraIQ agent — Linux systemd service installer (DEVELOPER FALLBACK).
#
# Prefer the packaged *.tar.gz from dist/agent-packages/ (embeds install.sh).
# This script remains for labs without a built package.
#
# Installs the agent as a real systemd service: starts on boot, restarts
# automatically if it crashes, runs unattended (no logged-in user needed) —
# the same operating model as the Wazuh agent.
#
# Usage (run as root on the server you want to monitor):
#   sudo ./install_agent_linux.sh --server https://securaiq.example.com --token <agent_id>.<agent_key>
#
# The token is stored in a root-only-readable env file (chmod 600), passed
# to the service via systemd's EnvironmentFile — never embedded in the unit
# file or visible in `ps aux`.

set -euo pipefail

SERVER=""
TOKEN=""
INTERVAL=60
SENTINEL_INTERVAL=10
INSTALL_DIR="/opt/securaiq/agent"
ENV_FILE="/etc/securaiq/agent.env"
UNIT_FILE="/etc/systemd/system/securaiq-agent.service"
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
  echo "This installer needs root (it writes to /opt, /etc, and manages systemd). Re-run with sudo." >&2
  exit 1
fi
if [ -z "$SERVER" ] || [ -z "$TOKEN" ]; then
  echo "Usage: sudo $0 --server https://securaiq.example.com --token <agent_id>.<agent_key>" >&2
  exit 2
fi
case "$SERVER" in
  *localhost*|*127.0.0.1*|*[::1]*)
    echo "WARNING: --server is localhost. On another host that means THIS machine, not SecuraIQ." >&2
    echo "Use the SecuraIQ LAN IP (e.g. http://192.168.x.x:8080) and start the console with LAN bind." >&2
    ;;
esac
USE_BIN=0
if [ -x "$BIN_SRC" ] || [ -f "$BIN_SRC" ]; then
  USE_BIN=1
elif [ ! -f "$SCRIPT_SRC" ]; then
  echo "Neither SecuraIQ-Agent nor securaiq_agent.py is next to this installer." >&2
  echo "On the customer host copy the Linux package from Agents, not only this .sh." >&2
  exit 1
fi
if [ "$USE_BIN" -eq 0 ]; then
  command -v python3 >/dev/null 2>&1 || { echo "python3 not found and no SecuraIQ-Agent binary. Install Python 3.8+ or use the packaged tarball." >&2; exit 1; }
fi

mkdir -p "$INSTALL_DIR"
if [ "$USE_BIN" -eq 1 ]; then
  install -m 0755 "$BIN_SRC" "$INSTALL_DIR/SecuraIQ-Agent"
  EXEC_START="$INSTALL_DIR/SecuraIQ-Agent --interval $INTERVAL --sentinel-interval $SENTINEL_INTERVAL"
else
  install -m 0755 "$SCRIPT_SRC" "$INSTALL_DIR/securaiq_agent.py"
  EXEC_START="$(command -v python3) $INSTALL_DIR/securaiq_agent.py --interval $INTERVAL --sentinel-interval $SENTINEL_INTERVAL"
fi

mkdir -p "$(dirname "$ENV_FILE")"
umask 077
cat > "$ENV_FILE" <<EOF
SECURAIQ_SERVER=$SERVER
SECURAIQ_TOKEN=$TOKEN
EOF
chmod 600 "$ENV_FILE"

cat > "$UNIT_FILE" <<EOF
[Unit]
Description=SecuraIQ native agent (telemetry check-in + Sentinel real-time threat watcher)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
EnvironmentFile=$ENV_FILE
ExecStart=$EXEC_START
Restart=always
RestartSec=10
User=root
NoNewPrivileges=false
# NoNewPrivileges/root: Sentinel reads /proc for every process on the host
# (behavioral detection) — an unprivileged user can't see other users'
# process cmdlines on most distros, which would silently blind that check.

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now securaiq-agent

echo ""
echo "SecuraIQ agent installed and running as a systemd service."
echo "  Status:  systemctl status securaiq-agent"
echo "  Logs:    journalctl -u securaiq-agent -f"
echo "  Stop:    systemctl stop securaiq-agent"
echo "  Remove:  systemctl disable --now securaiq-agent && rm -f $UNIT_FILE $ENV_FILE && rm -rf $INSTALL_DIR"
