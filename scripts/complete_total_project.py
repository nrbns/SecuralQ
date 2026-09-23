"""Close remaining lab-unblocked product rows (never fake ops).

Usage:
  python scripts/complete_total_project.py
  python scripts/complete_total_project.py --live-verify
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

_ROOT = Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

LOG = _ROOT / "data" / "ops" / "complete_total_project.jsonl"


def _append(row: dict[str, Any]) -> None:
    LOG.parent.mkdir(parents=True, exist_ok=True)
    with LOG.open("a", encoding="utf-8") as f:
        f.write(json.dumps(row, default=str) + "\n")


def _run(args: list[str], timeout: int = 180) -> dict[str, Any]:
    proc = subprocess.run(args, cwd=str(_ROOT), capture_output=True, text=True, timeout=timeout)
    return {
        "ok": proc.returncode == 0,
        "returncode": proc.returncode,
        "tail": ((proc.stdout or "") + (proc.stderr or ""))[-400:],
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--live-verify", action="store_true")
    args = ap.parse_args()
    steps: list[dict[str, Any]] = []
    print("=== COMPLETE TOTAL PROJECT (lab-closable) ===", flush=True)

    s = _run([sys.executable, "-m", "pytest", "-q", "tests/test_product_close.py", "--tb=line"])
    s["name"] = "product_close_tests"
    steps.append(s)
    print(f"  [{'PASS' if s['ok'] else 'FAIL'}] {s['name']}", flush=True)

    s = _run([sys.executable, str(_ROOT / "scripts" / "backup_restore_drill.py")])
    s["name"] = "backup_restore_drill"
    steps.append(s)
    print(f"  [{'PASS' if s['ok'] else 'FAIL'}] {s['name']}", flush=True)

    s = _run([sys.executable, str(_ROOT / "scripts" / "remaining_ops_complete.py")])
    s["name"] = "remaining_ops"
    steps.append(s)
    print(f"  [{'PASS' if s['ok'] else 'FAIL'}] {s['name']}", flush=True)

    if args.live_verify:
        s = _run(
            [
                sys.executable,
                str(_ROOT / "scripts" / "live_lab_verify.py"),
                "--spawn-isolated",
                "--i-own-this-host",
            ],
            timeout=400,
        )
        s["name"] = "live_lab_verify"
        steps.append(s)
        print(f"  [{'PASS' if s['ok'] else 'FAIL'}] {s['name']}", flush=True)

    from app.phase1_ops_remaining import phase1_ops_remaining

    board = phase1_ops_remaining()
    steps.append(
        {
            "name": "phase1_board",
            "ok": bool(board.get("code_unblocked_complete")) and not board.get("ops_still_open"),
            "ops_still_open": board.get("ops_still_open"),
        }
    )
    overall = all(bool(x.get("ok")) for x in steps)
    row = {
        "ts_utc": datetime.now(timezone.utc).isoformat(),
        "ok": overall,
        "steps": [{k: v for k, v in s.items() if k != "tail"} for s in steps],
        "disclaimer": (
            "Engineering leftovers that this host can close. EV Authenticode, "
            "cloud Object Lock, Postgres HA, production IdP, C3PAO, and 5k–100k "
            "HTTP remain ops / unmeasured."
        ),
    }
    _append(row)
    print(json.dumps({k: v for k, v in row.items() if k != "steps"}, indent=2), flush=True)
    print("RESULT:", "TOTAL LAB COMPLETE" if overall else "TOTAL LAB INCOMPLETE", flush=True)
    return 0 if overall else 1


if __name__ == "__main__":
    raise SystemExit(main())
