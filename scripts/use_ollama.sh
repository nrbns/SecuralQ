#!/usr/bin/env bash
# Configure Ollama backend (Linux/macOS)
set -euo pipefail
cd "$(dirname "$0")/.."
. scripts/common.sh

set_env_value MODEL_BACKEND ollama
set_env_value OLLAMA_BASE_URL http://localhost:11434
set_env_value OLLAMA_MODEL tinyllama

echo "Configured .env for Ollama + tinyllama."
echo "Run: ollama pull tinyllama"
echo "Then start: bash scripts/start.sh"