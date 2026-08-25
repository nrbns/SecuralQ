#!/usr/bin/env bash
# Configure Unsloth backend (Linux/macOS/WSL)
set -euo pipefail
cd "$(dirname "$0")/.."
. scripts/common.sh

set_env_value MODEL_BACKEND unsloth
set_env_value UNSLOTH_MODEL unsloth/Qwen2.5-0.5B-Instruct-bnb-4bit
set_env_value UNSLOTH_ADAPTER_DIR ./models/securaiq-unsloth
set_env_value UNSLOTH_MAX_SEQ_LENGTH 2048
set_env_value UNSLOTH_LOAD_IN_4BIT true
# Ensure key exists (blank = unset)
if ! grep -q '^HF_TOKEN=' .env 2>/dev/null; then
  set_env_value HF_TOKEN ""
fi

echo "Configured .env for Unsloth backend."
echo ""
echo "Install (GPU + CUDA recommended):"
echo "  .venv/bin/pip install unsloth"
echo "  .venv/bin/pip install datasets trl peft accelerate bitsandbytes"
echo ""
echo "Set HF_TOKEN in the UI Settings panel (or .env) for gated models."
echo "Train: python -m app.fine_tune.train_unsloth --epochs 1"
echo "  or use Settings → Start Unsloth train in the UI"
echo "Run: bash scripts/start.sh"
echo ""
echo "Repo: https://github.com/unslothai/unsloth"
