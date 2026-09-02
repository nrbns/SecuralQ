#!/usr/bin/env bash
# Build a standalone SecuraIQ binary for this OS (Linux/macOS).
set -euo pipefail
cd "$(dirname "$0")"
exec bash scripts/build_exe.sh "$@"
