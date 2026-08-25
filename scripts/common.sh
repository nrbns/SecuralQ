#!/usr/bin/env bash
# Shared shell helpers for Linux/macOS scripts.
set -euo pipefail

project_root() {
  cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd
}

python_cmd() {
  local cand
  for cand in python3 python; do
    if command -v "$cand" >/dev/null 2>&1; then
      if "$cand" -c "import sys; raise SystemExit(0 if sys.version_info >= (3, 11) else 1)" 2>/dev/null; then
        echo "$cand"
        return 0
      fi
    fi
  done
  echo "Python 3.11+ is required." >&2
  exit 1
}

ensure_venv() {
  local py
  py="$(python_cmd)"
  if [ ! -d ".venv" ]; then
    echo "Creating .venv..."
    "$py" -m venv .venv
  fi
  # shellcheck disable=SC1091
  . .venv/bin/activate
  if ! python -c "import fastapi, uvicorn" >/dev/null 2>&1; then
    echo "Installing Python packages (fastapi missing or incomplete venv)..."
    python -m pip install --upgrade pip
    python -m pip install -r requirements.txt
  fi
  if ! python -c "import fastapi, uvicorn" >/dev/null 2>&1; then
    echo "ERROR: fastapi still missing. Fix: rm -rf .venv && ./start.sh" >&2
    exit 1
  fi
}

ensure_env() {
  if [ ! -f ".env" ]; then
    cp .env.example .env
  fi
}

set_env_value() {
  local key="$1"
  local value="$2"
  ensure_env
  awk -v key="$key" -v value="$value" '
    BEGIN { found = 0 }
    $0 ~ "^" key "=" { print key "=" value; found = 1; next }
    { print }
    END { if (!found) print key "=" value }
  ' .env > .env.tmp
  mv .env.tmp .env
}

stop_port_8080() {
  if command -v lsof >/dev/null 2>&1; then
    pids="$(lsof -ti tcp:8080 || true)"
    if [ -n "${pids:-}" ]; then
      kill $pids 2>/dev/null || true
    fi
  elif command -v fuser >/dev/null 2>&1; then
    fuser -k 8080/tcp 2>/dev/null || true
  fi
}