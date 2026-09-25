"""Prove every world-class phase is lab-complete.

Usage:
  python scripts/complete_all_phases.py
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

LOG = _ROOT / "data" / "ops" / "complete_all_phases.jsonl"


def main() -> int:
    print("=== COMPLETE ALL PHASES ===", flush=True)
    tests = subprocess.run(
        [
            sys.executable,
            "-m",
            "pytest",
            "-q",
            "tests/test_all_phases.py",
            "tests/test_total_phase.py",
            "tests/test_product_close.py",
            "tests/test_phase1_ops_remaining.py",
            "tests/test_master_checklist_phases.py",
            "--tb=line",
        ],
        cwd=str(_ROOT),
    )
    from app.phase_board import all_phases_board

    board = all_phases_board()
    print(
        json.dumps(
            {
                "all_lab": board.get("all_lab"),
                "ok": board.get("ok"),
                "phases": [{k: p.get(k) for k in ("id", "status", "ops_blocked")} for p in board.get("phases") or []],
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
    print("RESULT:", "ALL PHASES LAB COMPLETE" if overall else "PHASES INCOMPLETE", flush=True)
    return 0 if overall else 1


if __name__ == "__main__":
    raise SystemExit(main())
