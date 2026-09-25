"""Prove the total phase board (world-class 1–5 + master-build 1–46).

Usage:
  python scripts/complete_total_phase.py
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

LOG = _ROOT / "data" / "ops" / "complete_total_phase.jsonl"


def main() -> int:
    print("=== COMPLETE TOTAL PHASE ===", flush=True)
    tests = subprocess.run(
        [
            sys.executable,
            "-m",
            "pytest",
            "-q",
            "tests/test_total_phase.py",
            "tests/test_all_phases.py",
            "tests/test_all_checklists.py",
            "tests/test_launch_plan.py",
            "tests/test_p0_launch_all.py",
            "tests/test_measured_ops.py",
            "tests/test_launch_complete.py",
            "tests/test_phase1_ops_remaining.py",
            "--tb=line",
        ],
        cwd=str(_ROOT),
    )
    from app.total_phase_board import total_phase_board

    board = total_phase_board()
    print(
        json.dumps(
            {
                "all_lab": board.get("all_lab"),
                "ok": board.get("ok"),
                "master_build_count": board.get("master_build_count"),
                "world_class": [
                    {k: p.get(k) for k in ("id", "status", "ops_blocked")}
                    for p in (board.get("world_class") or {}).get("phases") or []
                ],
                "master_build": [
                    {k: p.get(k) for k in ("id", "name", "status")}
                    for p in board.get("master_build") or []
                ],
            },
            indent=2,
        ),
        flush=True,
    )
    overall = tests.returncode == 0 and bool(board.get("all_lab"))
    LOG.parent.mkdir(parents=True, exist_ok=True)
    with LOG.open("a", encoding="utf-8") as f:
        f.write(
            json.dumps(
                {
                    "ts_utc": datetime.now(timezone.utc).isoformat(),
                    "ok": overall,
                    "tests_rc": tests.returncode,
                    "all_lab": board.get("all_lab"),
                    "disclaimer": board.get("disclaimer"),
                }
            )
            + "\n"
        )
    print("RESULT:", "TOTAL PHASE LAB COMPLETE" if overall else "TOTAL PHASE INCOMPLETE", flush=True)
    return 0 if overall else 1


if __name__ == "__main__":
    raise SystemExit(main())
