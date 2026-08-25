#!/usr/bin/env bash
# Start SecuraIQ (Linux/macOS) — zero-config, no manual .env; --lan for Wi-Fi devices
set -euo pipefail
cd "$(dirname "$0")/.."

LAN=0
for arg in "$@"; do
  case "$arg" in
    --lan|-Lan) LAN=1 ;;
  esac
done

find_python() {
  local cand
  for cand in python3 python; do
    if command -v "$cand" >/dev/null 2>&1; then
      if "$cand" -c "import sys; raise SystemExit(0 if sys.version_info >= (3, 11) else 1)" 2>/dev/null; then
        echo "$cand"
        return 0
      fi
    fi
  done
  echo "Python 3.11+ not found. Install python3.11+ and retry." >&2
  exit 1
}

PY="$(find_python)"

if [ ! -d .venv ] || [ ! -x .venv/bin/python ]; then
  echo "Creating virtual environment..."
  "$PY" -m venv .venv
fi

# Repair half-created venvs (folder exists but fastapi never installed)
if ! .venv/bin/python -c "import fastapi, uvicorn" 2>/dev/null; then
  echo "Installing dependencies (first run or repair)..."
  .venv/bin/python -m pip install --upgrade pip
  .venv/bin/python -m pip install -r requirements.txt
  if ! .venv/bin/python -c "import fastapi, uvicorn" 2>/dev/null; then
    echo "ERROR: fastapi/uvicorn still missing. Delete .venv and re-run." >&2
    exit 1
  fi
  echo "Dependencies ready."
fi

if [ ! -f .env.example ]; then
  echo "Missing .env.example - clone the full SecuraIQ repo." >&2
  exit 1
fi
if [ ! -f .env ]; then
  cp .env.example .env
  echo "Created .env from .env.example (no manual editing needed)"
fi

set_env() {
  local key="$1" val="$2"
  if grep -q "^${key}=" .env 2>/dev/null; then
    # Portable in-place edit (GNU sed + BSD/macOS sed)
    if sed --version >/dev/null 2>&1; then
      sed -i "s|^${key}=.*|${key}=${val}|" .env
    else
      sed -i.bak "s|^${key}=.*|${key}=${val}|" .env && rm -f .env.bak
    fi
  else
    echo "${key}=${val}" >> .env
  fi
}

if [ "$LAN" -eq 1 ]; then
  set_env HOST 0.0.0.0
  set_env CORS_ORIGINS "*"
  set_env WORKSPACE_ZERO_START false
  set_env ALLOW_OPEN_LAN true
  set_env LAN_AUTO_SCAN true
else
  set_env HOST 127.0.0.1
  set_env CORS_ORIGINS "http://127.0.0.1:8080,http://localhost:8080"
  set_env WORKSPACE_ZERO_START false
  set_env ALLOW_OPEN_LAN false
  set_env LAN_AUTO_SCAN false
fi
set_env AUTH_ALLOW_REGISTER false
if command -v ollama >/dev/null 2>&1; then
  set_env MODEL_BACKEND ollama
fi

echo ""
if [ "$LAN" -eq 1 ]; then
  echo "Starting SecuraIQ (LAN mode — other devices on Wi‑Fi can open)"
  echo "  This PC:     http://127.0.0.1:8080"
  # Portable LAN URL detection (Linux + macOS) via Python — avoid hostname -I (Linux-only)
  .venv/bin/python -c "
from app.platform_info import platform_info
for u in platform_info().get('lan_urls') or []:
    print('  Phone/other:', u)
" 2>/dev/null || true
  echo "  Live share:  same assets/scans on every device; this host auto-scans on start"
else
  echo "Starting SecuraIQ (localhost)"
  echo "  Open:  http://127.0.0.1:8080"
  echo "  LAN:   ./start_lan.sh   or   ./scripts/start.sh --lan"
fi
echo "No .env editing required. Optional keys: Settings in the UI."
.venv/bin/python run.py
