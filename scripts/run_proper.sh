#!/usr/bin/env bash
# One-command setup + start for SecuraIQ (Linux/macOS)
# Secure localhost by default; pass --lan for Wi-Fi devices
set -euo pipefail
cd "$(dirname "$0")/.."
. scripts/common.sh

LAN=0
for arg in "$@"; do
  case "$arg" in
    --lan|-Lan) LAN=1 ;;
  esac
done

echo "SecuraIQ setup"
ensure_venv
echo "Installing / verifying Python packages..."
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
if ! python -c "import fastapi, uvicorn" >/dev/null 2>&1; then
  echo "ERROR: fastapi still missing after install. Try: rm -rf .venv && ./run_proper.sh" >&2
  exit 1
fi
ensure_env

if command -v ollama >/dev/null 2>&1; then
  echo "Ollama found — scans work without it. Chat stays optional (DEMO_DISABLE_AI in .env)."
  bash scripts/use_ollama.sh >/dev/null || true
else
  echo "Ollama not found — leaving MODEL_BACKEND as in .env. Do not auto-install HuggingFace (laptop lag)."
fi

echo "Indexing RAG knowledge base (optional)..."
python scripts/ingest_rag.py || echo "RAG index skipped — Re-index in the UI later."

if [ "$LAN" -eq 1 ]; then
  set_env_value HOST 0.0.0.0
  set_env_value CORS_ORIGINS "*"
  set_env_value WORKSPACE_ZERO_START false
  set_env_value ALLOW_OPEN_LAN true
  set_env_value LAN_AUTO_SCAN false
else
  set_env_value HOST 127.0.0.1
  set_env_value CORS_ORIGINS "http://127.0.0.1:8080,http://localhost:8080"
  set_env_value WORKSPACE_ZERO_START false
  set_env_value ALLOW_OPEN_LAN false
  set_env_value LAN_AUTO_SCAN false
fi

stop_port_8080

echo ""
if [ "$LAN" -eq 1 ]; then
  echo "Starting SecuraIQ (LAN mode) at http://0.0.0.0:8080"
  echo "  Or: ./start_lan.sh"
else
  echo "Starting SecuraIQ (secure — localhost) at http://127.0.0.1:8080"
  echo "For phones: ./start_lan.sh"
fi
# Same opening path as start.sh (wait for /api/alive, then open the browser).
if [ "$LAN" -eq 1 ]; then
  exec bash scripts/start.sh --lan
else
  exec bash scripts/start.sh
fi
