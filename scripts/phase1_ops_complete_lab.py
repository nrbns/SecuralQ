"""Close all code-unblocked Phase-1 leftovers (never fake ops gates).

Runs:
  1) Sentinel pipeline self-test
  2) Multiworker / remaining full proof (lab Authenticode PFX)
  3) Soft check-in ladder 100/250/500/1000 (truncated)
  4) Phase-1 remaining board dump

Optional:
  --http-ladder  Live HTTP measure against --server (fills capacity jsonl)
  --owned-host   Set SECURAIQ_OWNED_HOST=1 for this process only

Usage:
  python scripts/phase1_ops_complete_lab.py
  python scripts/phase1_ops_complete_lab.py --http-ladder --server http://127.0.0.1:8080 --max-agents 500 --workers 8
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

_ROOT = Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

LOG = _ROOT / "data" / "ops" / "phase1_ops_complete.jsonl"


def _append(row: dict[str, Any]) -> None:
    LOG.parent.mkdir(parents=True, exist_ok=True)
    with LOG.open("a", encoding="utf-8") as f:
        f.write(json.dumps(row, default=str) + "\n")


def step_sentinel() -> dict[str, Any]:
    proc = subprocess.run(
        [sys.executable, str(_ROOT / "scripts" / "sentinel_failover_measure.py"), "--pipeline-self-test"],
        cwd=str(_ROOT),
        capture_output=True,
        text=True,
        timeout=120,
    )
    return {
        "name": "sentinel_pipeline_self_test",
        "ok": proc.returncode == 0,
        "returncode": proc.returncode,
        "tail": (proc.stdout or proc.stderr or "")[-400:],
    }


def step_remaining_full() -> dict[str, Any]:
    proc = subprocess.run(
        [sys.executable, str(_ROOT / "scripts" / "realtime_remaining_full_proof.py")],
        cwd=str(_ROOT),
        capture_output=True,
        text=True,
        timeout=180,
    )
    return {
        "name": "remaining_full_proof",
        "ok": proc.returncode == 0,
        "returncode": proc.returncode,
        "tail": (proc.stdout or "")[-500:],
    }


def step_soft_ladder() -> dict[str, Any]:
    from tests._http_test_utils import configure_isolated_settings

    class _MP:
        def setattr(self, target, name=None, value=None, raising=True):
            if isinstance(target, str) and value is None and name is not None:
                import importlib

                mod_name, _, attr = target.rpartition(".")
                obj = importlib.import_module(mod_name)
                setattr(obj, attr, name)
                return
            setattr(target, name, value)

    td = Path(tempfile.mkdtemp(prefix="p1-soft-"))
    configure_isolated_settings(_MP(), td)
    from app.capacity_soft import soft_checkin_ladder
    from app.db import reset_conn_for_tests
    from app.tenancy import ensure_tenant_schema

    ensure_tenant_schema()
    try:
        out = soft_checkin_ladder("phase1-ops", [100, 250, 500, 1000])
    finally:
        reset_conn_for_tests()
    return {
        "name": "soft_checkin_ladder",
        "ok": bool(out.get("ok")),
        "detail": {
            "http_500_measured": out.get("http_500_measured"),
            "rungs": [
                {
                    "agents": r.get("agents"),
                    "success_pct": r.get("success_pct"),
                    "checkin_p95_ms": r.get("checkin_p95_ms"),
                }
                for r in (out.get("rungs") or [])
            ],
        },
        "disclaimer": out.get("note"),
    }


def step_board() -> dict[str, Any]:
    from app.phase1_ops_remaining import phase1_ops_remaining

    board = phase1_ops_remaining()
    return {
        "name": "phase1_ops_board",
        "ok": bool(board.get("code_unblocked_complete")),
        "board": board,
    }


def step_http_ladder(server: str, token: str, max_agents: int, workers: int) -> dict[str, Any]:
    cmd = [
        sys.executable,
        str(_ROOT / "scripts" / "realtime_load_test.py"),
        "--server",
        server,
        "--ladder",
        "--max-agents",
        str(max_agents),
        "--workers",
        str(workers),
        "--persist",
        "--sse-sample",
    ]
    if token:
        cmd.extend(["--admin-token", token])
    proc = subprocess.run(cmd, cwd=str(_ROOT), capture_output=True, text=True, timeout=7200)
    return {
        "name": "http_capacity_ladder",
        "ok": proc.returncode == 0,
        "returncode": proc.returncode,
        "tail": (proc.stdout or "")[-800:],
        "disclaimer": "Live HTTP measure — see data/ops/capacity_measurements.jsonl",
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--http-ladder", action="store_true")
    ap.add_argument("--server", default="http://127.0.0.1:8080")
    ap.add_argument("--admin-token", default=os.environ.get("SECURAIQ_ADMIN_TOKEN", ""))
    ap.add_argument("--max-agents", type=int, default=500)
    ap.add_argument("--workers", type=int, default=8)
    ap.add_argument("--owned-host", action="store_true")
    ap.add_argument("--skip-soft", action="store_true")
    args = ap.parse_args()

    if args.owned_host:
        os.environ["SECURAIQ_OWNED_HOST"] = "1"

    steps: list[dict[str, Any]] = []
    print("=== Phase-1 ops complete (lab / code-unblocked) ===", flush=True)
    for fn in (step_sentinel, step_remaining_full):
        s = fn()
        steps.append(s)
        print(f"  [{'PASS' if s['ok'] else 'FAIL'}] {s['name']}", flush=True)

    if not args.skip_soft:
        s = step_soft_ladder()
        steps.append(s)
        print(f"  [{'PASS' if s['ok'] else 'FAIL'}] {s['name']}", flush=True)

    if args.http_ladder:
        s = step_http_ladder(args.server, args.admin_token, args.max_agents, args.workers)
        steps.append(s)
        print(f"  [{'PASS' if s['ok'] else 'FAIL'}] {s['name']}", flush=True)

    s = step_board()
    steps.append(s)
    print(f"  [{'PASS' if s['ok'] else 'FAIL'}] {s['name']}", flush=True)
    ops_open = (s.get("board") or {}).get("ops_still_open") or []
    print(f"  ops_still_open: {ops_open}", flush=True)

    overall = all(bool(x.get("ok")) for x in steps)
    row = {
        "ts_utc": datetime.now(timezone.utc).isoformat(),
        "ok": overall,
        "steps": [{k: v for k, v in s.items() if k != "board"} for s in steps],
        "ops_still_open": ops_open,
        "disclaimer": (
            "Code-unblocked complete ≠ commercial HA / EV Authenticode / "
            "owned-host mutation / cloud WORM"
        ),
    }
    _append(row)
    print(json.dumps({k: v for k, v in row.items() if k != "steps"}, indent=2), flush=True)
    print(
        "RESULT:",
        "CODE-UNBLOCKED COMPLETE" if overall else "INCOMPLETE",
        flush=True,
    )
    return 0 if overall else 1


if __name__ == "__main__":
    raise SystemExit(main())
