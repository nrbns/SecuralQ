#!/usr/bin/env python3
"""Remaining ops proofs that do not require Docker or signing secrets.

Runs CI-safe coverage for what was still listed as "not claimed":
  - Sentinel measurement pipeline self-test (simulated, labeled)
  - Multi-worker in-process SSE soak
  - Once-only / XAUTOCLAIM simulation
  - Signing/notarization scaffold presence
  - Commercial profile status report

Live Docker Sentinel inject + Authenticode with org certs remain ops/secrets steps.

Usage:
  python scripts/realtime_ops_remaining_proof.py
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

PY = sys.executable


def _run(args: list[str]) -> tuple[int, str]:
    proc = subprocess.run(
        [PY, *args],
        cwd=str(_ROOT),
        capture_output=True,
        text=True,
        timeout=180,
    )
    out = (proc.stdout or "") + (proc.stderr or "")
    return proc.returncode, out


def main() -> int:
    steps: list[dict] = []

    # 1. Sentinel dry-run + pipeline self-test
    code, out = _run(["scripts/sentinel_failover_measure.py", "--dry-run"])
    steps.append(
        {
            "name": "sentinel_dry_run",
            "ok": code == 0,
            "detail": "dry-run exit 0" if code == 0 else out[-400:],
        }
    )
    code, out = _run(["scripts/sentinel_failover_measure.py", "--pipeline-self-test"])
    pipe_ok = code == 0 and "simulated" in out.lower()
    steps.append(
        {
            "name": "sentinel_pipeline_self_test",
            "ok": pipe_ok,
            "detail": "simulated measurement row written" if pipe_ok else out[-400:],
        }
    )

    # 2. Multi-worker soak
    code, out = _run(
        [
            "scripts/realtime_multiworker_smoke.py",
            "--inprocess-soak",
            "--subscribers",
            "3",
            "--events",
            "15",
        ]
    )
    soak_ok = code == 0 and '"ok": true' in out.replace(" ", "").lower().replace("True", "true")
    if code == 0:
        try:
            # last JSON object
            payload = json.loads(out[out.rfind("{") :])
            soak_ok = bool(payload.get("ok"))
        except Exception:
            soak_ok = code == 0
    steps.append(
        {
            "name": "multiworker_inprocess_soak",
            "ok": soak_ok,
            "detail": "3 subscribers × 15 events + dedupe" if soak_ok else out[-500:],
        }
    )

    # 3. Once-only simulate
    code, out = _run(["scripts/realtime_phase1_proof.py", "--simulate"])
    sim_ok = code == 0
    if code == 0:
        try:
            payload = json.loads(out[out.rfind("{") :])
            sim_ok = bool(payload.get("ok"))
        except Exception:
            pass
    steps.append(
        {
            "name": "once_only_xautoclaim_simulate",
            "ok": sim_ok,
            "detail": "duplicate delivery skipped + reclaim once" if sim_ok else out[-400:],
        }
    )

    # 4. Signing scaffolds
    from app.realtime.ops_proofs import verify_signing_scaffolds

    sig = verify_signing_scaffolds()
    steps.append(
        {
            "name": "signing_scaffolds_present",
            "ok": bool(sig.get("ok")),
            "detail": sig.get("note") or "",
            "data": {"missing": sig.get("missing")},
        }
    )

    # 5. Commercial profile status (lab: not enforced)
    from app.production_profile import production_profile_status

    st = production_profile_status()
    steps.append(
        {
            "name": "commercial_profile_status",
            "ok": bool(st.get("ok")),
            "detail": (
                f"production_ready={st.get('production_ready_agent_security')} "
                f"commercial_signing={st.get('commercial_ready_command_signing')}"
            ),
        }
    )

    passed = sum(1 for s in steps if s["ok"])
    overall = all(s["ok"] for s in steps)
    report = {
        "ok": overall,
        "passed": passed,
        "total": len(steps),
        "steps": steps,
        "disclaimer": (
            "CI-safe remaining ops proofs. Live docker compose --profile redis-ha "
            "--inject-stop --record and Authenticode/notarization with org secrets "
            "are still required for commercial HA / signed-release claims."
        ),
    }
    print("=== SECURAIQ REMAINING OPS PROOF ===")
    for s in steps:
        print(f"  [{'PASS' if s['ok'] else 'FAIL'}] {s['name']}: {s.get('detail', '')[:120]}")
    print(json.dumps(report, indent=2, default=str))
    print("RESULT:", "REMAINING OPS LAB-COMPLETE" if overall else "INCOMPLETE")
    return 0 if overall else 1


if __name__ == "__main__":
    raise SystemExit(main())
