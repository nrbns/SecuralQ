#!/usr/bin/env python3
"""Prove launch plan + world-class 1–5 + master-build 1–46 + checklists.

Usage:
  python scripts/complete_launch_all.py
"""

from __future__ import annotations

import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

LOG = _ROOT / "data" / "ops" / "complete_launch_all.jsonl"

SUITES = [
    "tests/test_total_phase.py",
    "tests/test_all_phases.py",
    "tests/test_all_checklists.py",
    "tests/test_launch_plan.py",
    "tests/test_p0_launch_all.py",
    "tests/test_measured_ops.py",
    "tests/test_phase1_ops_remaining.py",
    "tests/test_product_close.py",
    "tests/test_launch_loop.py",
    "tests/test_world_class_remaining.py",
    "tests/test_launch_complete.py",
    "tests/test_commercial_truth.py",
]


def main() -> int:
    print("=== COMPLETE SECURAIQ LAUNCH + ALL PHASES ===", flush=True)
    tests = subprocess.run(
        [sys.executable, "-m", "pytest", "-q", *SUITES, "--tb=line"],
        cwd=str(_ROOT),
    )
    from app.launch_complete import launch_complete_board

    board = launch_complete_board()
    print(json.dumps(board, indent=2), flush=True)
    overall = tests.returncode == 0 and bool(board.get("engineering_complete"))
    LOG.parent.mkdir(parents=True, exist_ok=True)
    with LOG.open("a", encoding="utf-8") as f:
        f.write(
            json.dumps(
                {
                    "ts_utc": datetime.now(timezone.utc).isoformat(),
                    "ok": overall,
                    "tests_rc": tests.returncode,
                    "engineering_complete": board.get("engineering_complete"),
                    "launch": board.get("launch"),
                    "world_class": board.get("world_class"),
                    "total_phase": board.get("total_phase"),
                    "checklists": board.get("checklists"),
                    "disclaimer": board.get("disclaimer"),
                }
            )
            + "\n"
        )
    print(
        "RESULT:",
        "LAUNCH + ALL PHASES LAB COMPLETE" if overall else "LAUNCH / PHASES INCOMPLETE",
        flush=True,
    )
    return 0 if overall else 1


if __name__ == "__main__":
    raise SystemExit(main())
