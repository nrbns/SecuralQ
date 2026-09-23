"""Complete + test every in-repo checklist.

Usage:
  python scripts/complete_all_checklists.py
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

LOG = _ROOT / "data" / "ops" / "complete_all_checklists.jsonl"

SUITES = [
    "tests/test_master_checklist_p0.py",
    "tests/test_master_checklist_phases.py",
    "tests/test_close_all_partials.py",
    "tests/test_all_phases.py",
    "tests/test_product_close.py",
    "tests/test_all_checklists.py",
    "tests/test_tenancy_rbac.py",
    "tests/test_cross_tenant_isolation.py",
    "tests/test_auth_and_investigation.py",
    "tests/test_ai_security.py",
    "tests/test_engagement_scope.py",
    "tests/test_rag_tenancy.py",
]


def main() -> int:
    print("=== COMPLETE ALL CHECKLISTS ===", flush=True)
    proc = subprocess.run(
        [sys.executable, "-m", "pytest", "-q", *SUITES, "--tb=line"],
        cwd=str(_ROOT),
    )
    from app.checklist_board import all_checklists_board

    board = all_checklists_board()
    print(
        json.dumps(
            {
                "all_complete": board.get("all_complete"),
                "ok": board.get("ok"),
                "checklists": [
                    {k: c.get(k) for k in ("id", "complete", "engineering_complete", "ops_blocked")}
                    for c in board.get("checklists") or []
                ],
            },
            indent=2,
        ),
        flush=True,
    )
    overall = proc.returncode == 0 and bool(board.get("all_complete"))
    LOG.parent.mkdir(parents=True, exist_ok=True)
    with LOG.open("a", encoding="utf-8") as f:
        f.write(
            json.dumps(
                {
                    "ts_utc": datetime.now(timezone.utc).isoformat(),
                    "ok": overall,
                    "tests_rc": proc.returncode,
                    "all_complete": board.get("all_complete"),
                    "disclaimer": board.get("disclaimer"),
                }
            )
            + "\n"
        )
    print(
        "RESULT:",
        "ALL CHECKLISTS COMPLETE" if overall else "CHECKLISTS INCOMPLETE",
        flush=True,
    )
    return 0 if overall else 1


if __name__ == "__main__":
    raise SystemExit(main())
