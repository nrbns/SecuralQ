#!/usr/bin/env bash
# Configure direct HuggingFace backend (Linux/macOS)
set -euo pipefail
cd "$(dirname "$0")/.."
. scripts/common.sh

set_env_value MODEL_BACKEND huggingface
set_env_value HF_MODEL Qwen/Qwen2.5-0.5B-Instruct

echo "Configured .env for direct HuggingFace local inference."
echo "Install optional packages if needed: .venv/bin/python -m pip install torch transformers accelerate"
echo "Then start: bash scripts/start.sh"