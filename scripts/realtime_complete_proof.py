"""One-shot proof that SecuraIQ realtime product loop is lab-complete.

Runs:
  1) Firewall golden loop (FAIL → rem → approve → PASS → verify)
  2) Failure matrix (dedupe, gap, SSE, tenant, sig, cert, DLQ, metrics)

Usage:
  python scripts/realtime_complete_proof.py
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))


def main() -> int:
    from scripts.realtime_acceptance_demo import run_local_chain
    from scripts.realtime_failure_acceptance import run_failure_matrix

    print("=== SECURAIQ REALTIME COMPLETE PROOF ===")
    print("lab proofs — not Sentinel HA / Authenticode\n")

    # Golden loop needs enroll + user — reuse acceptance helper via --firewall path
    import tempfile
    from pathlib import Path as P

    from tests._http_test_utils import configure_isolated_settings

    class _MP:
        def __init__(self) -> None:
            self._u: list = []

        def setattr(self, target, name=None, value=None, raising=True):
            if isinstance(target, str) and value is None and name is not None:
                dotted, value = target, name
                mod_name, _, attr = dotted.rpartition(".")
                import importlib

                obj = importlib.import_module(mod_name)
                old = getattr(obj, attr)
                setattr(obj, attr, value)
                self._u.append(lambda: setattr(obj, attr, old))
                return
            old = getattr(target, name)
            setattr(target, name, value)
            self._u.append(lambda o=target, n=name, v=old: setattr(o, n, v))

    td = tempfile.mkdtemp()
    mp = _MP()
    configure_isolated_settings(mp, P(td))
    from app.agents import enroll_agent
    from app.auth import login, register_user
    from app.tenancy import ensure_tenant_schema

    ensure_tenant_schema()
    uname = f"rt_complete_{int(__import__('time').time())}"
    register_user(uname, "password123", role="admin")
    user, _ = login(uname, "password123")
    agent = enroll_agent(user.id, name="rt-complete-host")
    golden = run_local_chain(user.id, agent["agent_id"])
    g_ok = bool(golden.ok)
    g_pass = sum(1 for s in golden.steps if s.ok)
    g_total = len(golden.steps)
    print(f"[1] Golden firewall loop: {'PASS' if g_ok else 'FAIL'} {g_pass}/{g_total}")
    for s in golden.steps:
        print(f"    [{'PASS' if s.ok else 'FAIL'}] {s.name}")

    fail = run_failure_matrix(tmp_path=P(td) / "fail")
    f_ok = bool(fail.ok)
    f_pass = sum(1 for s in fail.steps if s.ok)
    f_total = len(fail.steps)
    print(f"\n[2] Failure matrix: {'PASS' if f_ok else 'FAIL'} {f_pass}/{f_total}")
    for s in fail.steps:
        print(f"    [{'PASS' if s.ok else 'FAIL'}] {s.name}")

    overall = g_ok and f_ok
    summary = {
        "ok": overall,
        "golden": {"ok": g_ok, "passed": g_pass, "total": g_total},
        "failure_matrix": {"ok": f_ok, "passed": f_pass, "total": f_total},
        "disclaimer": "lab proofs — not Sentinel HA / Authenticode",
        "definition": (
            "Endpoint change propagates agent→gateway→bus→control→evidence→"
            "risk→remediation→verify→SSE without browser refresh (lab)."
        ),
    }
    print("\n" + json.dumps(summary, indent=2))
    print("\nRESULT:", "REALTIME LAB COMPLETE" if overall else "INCOMPLETE")
    return 0 if overall else 1


if __name__ == "__main__":
    raise SystemExit(main())
