#!/usr/bin/env bash
# Configure LM Studio/OpenAI-compatible backend (Linux/macOS)
set -euo pipefail
cd "$(dirname "$0")/.."
. scripts/common.sh

set_env_value MODEL_BACKEND openai_compat
set_env_value OPENAI_COMPAT_BASE_URL http://localhost:1234/v1
set_env_value OPENAI_COMPAT_MODEL local-model
set_env_value OPENAI_COMPAT_API_KEY lm-studio

echo "Configured .env for LM Studio / OpenAI-compatible local server."
echo "Start LM Studio local server, then run: bash scripts/start.sh"