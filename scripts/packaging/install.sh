#!/usr/bin/env bash
# SecuraIQ Agent — Linux package installer (systemd when available).
#
# Prefers a packaged SecuraIQ-Agent binary in this directory; falls back to
# securaiq_agent.py + python3.
#
# Usage:
#   sudo ./install.sh --server https://securaiq.example.com --token <agent_id>.<agent_key>

set -euo pipefail

SERVER=""
TOKEN=""
INTERVAL=60
SENTINEL_INTERVAL=10
INSECURE=0
INSTALL_DIR="/opt/securaiq-agent"
ENV_FILE="/etc/securaiq/agent.env"
UNIT_FILE="/etc/systemd/system/securaiq-agent.service"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

while [ $# -gt 0 ]; do
  case "$1" in
    --server) SERVER="$2"; shift 2 ;;
    --token) TOKEN="$2"; shift 2 ;;
    --interval) INTERVAL="$2"; shift 2 ;;
    --sentinel-interval) SENTINEL_INTERVAL="$2"; shift 2 ;;
    --insecure) INSECURE=1; shift ;;
    --install-dir) INSTALL_DIR="$2"; shift 2 ;;
    *) echo "Unknown argument: $1" >&2; exit 2 ;;
  esac
done

if [ "$(id -u)" -ne 0 ]; then
  echo "This installer needs root (writes to /opt and /etc). Re-run with sudo." >&2
  exit 1
fi
if [ -z "$SERVER" ] || [ -z "$TOKEN" ]; then
  echo "Usage: sudo $0 --server https://securaiq.example.com --token <agent_id>.<agent_key>" >&2
  exit 2
fi

BIN_SRC=""
MODE=""
if [ -x "$HERE/SecuraIQ-Agent" ] || [ -f "$HERE/SecuraIQ-Agent" ]; then
  BIN_SRC="$HERE/SecuraIQ-Agent"
  MODE="binary"
elif [ -f "$HERE/securaiq_agent.py" ]; then
  BIN_SRC="$HERE/securaiq_agent.py"
  MODE="python"
  command -v python3 >/dev/null 2>&1 || { echo "python3 not found — install Python 3.8+ or use a binary package." >&2; exit 1; }
else
  echo "Neither SecuraIQ-Agent nor securaiq_agent.py found in $HERE" >&2
  exit 1
fi

mkdir -p "$INSTALL_DIR"
if [ "$MODE" = "binary" ]; then
  install -m 0755 "$BIN_SRC" "$INSTALL_DIR/SecuraIQ-Agent"
  EXEC_START="$INSTALL_DIR/SecuraIQ-Agent --interval $INTERVAL --sentinel-interval $SENTINEL_INTERVAL"
else
  install -m 0755 "$BIN_SRC" "$INSTALL_DIR/securaiq_agent.py"
  EXEC_START="$(command -v python3) $INSTALL_DIR/securaiq_agent.py --interval $INTERVAL --sentinel-interval $SENTINEL_INTERVAL"
fi
if [ "$INSECURE" = "1" ]; then
  EXEC_START="$EXEC_START --insecure"
fi

[ -f "$HERE/QUICKSTART.md" ] && install -m 0644 "$HERE/QUICKSTART.md" "$INSTALL_DIR/QUICKSTART.md"
[ -f "$HERE/agent.env.example" ] && install -m 0644 "$HERE/agent.env.example" "$INSTALL_DIR/agent.env.example"

mkdir -p "$(dirname "$ENV_FILE")"
umask 077
cat > "$ENV_FILE" <<EOF
SECURAIQ_SERVER=$SERVER
SECURAIQ_TOKEN=$TOKEN
EOF
chmod 600 "$ENV_FILE"

if command -v systemctl >/dev/null 2>&1; then
  cat > "$UNIT_FILE" <<EOF
[Unit]
Description=SecuraIQ native agent (telemetry + Sentinel + Agent Gateway)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
EnvironmentFile=$ENV_FILE
ExecStart=$EXEC_START
Restart=always
RestartSec=10
User=root

[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
  systemctl enable --now securaiq-agent
  echo ""
  echo "SecuraIQ agent installed and running as systemd service."
  echo "  Status:  systemctl status securaiq-agent"
  echo "  Logs:    journalctl -u securaiq-agent -f"
  echo "  Stop:    systemctl stop securaiq-agent"
  echo "  Remove:  systemctl disable --now securaiq-agent && rm -f $UNIT_FILE $ENV_FILE && rm -rf $INSTALL_DIR"
else
  echo "systemd not found — files installed under $INSTALL_DIR; start manually:"
  echo "  set -a; . $ENV_FILE; set +a; $EXEC_START"
fi
