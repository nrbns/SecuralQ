#!/usr/bin/env python3
"""In-process restart reclaim drill — flip a running probe job to pending.

Usage:
  python scripts/restart_reclaim_drill.py
  python scripts/restart_reclaim_drill.py --record
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--record", action="store_true", help="Append timings to data/ops/restart_reclaim_measurements.jsonl")
    args = ap.parse_args()
    from app.db import init_schema
    from app.restart_recovery import run_restart_reclaim_drill
    from app.tenancy import ensure_tenant_schema

    init_schema()
    ensure_tenant_schema()
    result = run_restart_reclaim_drill(persist=args.record)
    print(json.dumps(result, indent=2))
    return 0 if result.get("ok") else 1


if __name__ == "__main__":
    raise SystemExit(main())
