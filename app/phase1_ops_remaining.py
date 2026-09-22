"""Phase-1 ops leftovers — honest readiness board (code-closable vs ops-blocked).

Never marks live Sentinel inject, HTTP 500+, EV Authenticode, owned-host OS
mutation, or cloud WORM as done without measured proof.
"""

from __future__ import annotations

import os
import shutil
from pathlib import Path
from typing import Any


def owned_host_authorized() -> bool:
    """True when operator explicitly asserts an authorized owned host."""
    raw = (os.environ.get("SECURAIQ_OWNED_HOST") or "").strip().lower()
    return raw in {"1", "true", "yes", "on"}


def owned_host_status() -> dict[str, Any]:
    """True when operator explicitly asserts an authorized owned host."""
    ok_local = True  # local/CI acceptance always available
    live = owned_host_authorized()
    # Persist evidence if live verify recorded a successful owned-host pass.
    root = Path(__file__).resolve().parents[1]
    live_log = root / "data" / "ops" / "live_lab_verify.jsonl"
    live_proof = False
    if live_log.is_file():
        try:
            import json

            for line in live_log.read_text(encoding="utf-8").splitlines():
                if not line.strip():
                    continue
                row = json.loads(line)
                if not row.get("owned_host"):
                    continue
                for s in row.get("steps") or []:
                    if s.get("name") == "acceptance_server_owned" and s.get("ok"):
                        live_proof = True
                        break
        except Exception:
            pass
    status = "lab" if (live and live_proof) else ("ops" if not live else "partial")
    return {
        "id": "owned_host_acceptance",
        "code_unblocked": True,
        "local_ci_ok": ok_local,
        "live_mutation_authorized": live,
        "live_server_acceptance_ok": live_proof,
        "status": status,
        "env": "SECURAIQ_OWNED_HOST",
        "hint": (
            "Local: pytest tests/test_realtime_acceptance_local.py | "
            "Live: set SECURAIQ_OWNED_HOST=1 and "
            "python scripts/live_lab_verify.py --server http://HOST:8080 --i-own-this-host"
        ),
        "disclaimer": (
            "Live host-control OS mutation remains ops until authorized owned host "
            "and a recorded acceptance_server_owned pass"
        ),
    }


def sentinel_ha_status() -> dict[str, Any]:
    from app.realtime.sentinel_ops import sentinel_ready_report

    report = sentinel_ready_report()
    docker = shutil.which("docker") is not None
    configured = bool(report.get("sentinel_configured"))
    reachable = bool(report.get("reachable"))
    if configured and reachable:
        status = "lab"
        code = True
    elif docker:
        status = "ops"
        code = True  # scripts ready; inject not yet run
    else:
        status = "ops"
        code = True  # pipeline self-test exists without Docker
    return {
        "id": "redis_sentinel_ha",
        "code_unblocked": code,
        "pipeline_self_test": True,
        "docker_present": docker,
        "sentinel_configured": configured,
        "sentinel_reachable": reachable,
        "live_inject_measured": False,
        "status": status,
        "report": report,
        "hint": (
            "python scripts/sentinel_failover_measure.py --pipeline-self-test  # CI\n"
            "docker compose --profile redis-ha up -d && "
            "python scripts/sentinel_failover_measure.py --inject-stop --record  # ops"
        ),
        "disclaimer": "CI self-test ≠ measured live failover",
    }


def capacity_http_status() -> dict[str, Any]:
    """Inspect ops jsonl for measured HTTP 500+ (never invent)."""
    root = Path(__file__).resolve().parents[1]
    log = root / "data" / "ops" / "capacity_measurements.jsonl"
    measured_rungs: list[int] = []
    latest: dict[str, Any] | None = None
    if log.is_file():
        try:
            for line in log.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if not line:
                    continue
                import json

                row = json.loads(line)
                if row.get("tool") != "realtime_load_test":
                    continue
                latest = row
                for r in row.get("rungs") or []:
                    try:
                        n = int(r.get("agents") or 0)
                        if float(r.get("success_rate_pct") or 0) >= 99.0:
                            measured_rungs.append(n)
                    except Exception:
                        pass
        except Exception:
            pass
    top = max(measured_rungs) if measured_rungs else 0
    http_500 = top >= 500
    return {
        "id": "http_capacity_ladder",
        "code_unblocked": True,
        "soft_ladder": True,
        "http_top_measured": top,
        "http_500_measured": http_500,
        "http_1000_measured": top >= 1000,
        "status": "lab" if http_500 else ("partial" if top >= 100 else "ops"),
        "latest_tool_row": bool(latest),
        "hint": (
            "python scripts/realtime_load_test.py --server http://127.0.0.1:8080 "
            "--ladder --max-agents 1000 --workers 8 --persist --sse-sample"
        ),
        "disclaimer": (
            "Soft in-process ladder is not HTTP capacity. "
            "Never market unmeasured rungs."
        ),
    }


# Alias used by capacity_soft / older callers
capacity_status = capacity_http_status


def authenticode_status() -> dict[str, Any]:
    from app.realtime.ops_proofs import verify_signing_scaffolds

    scaffolds = verify_signing_scaffolds()
    root = Path(__file__).resolve().parents[1]
    lab_pfx = root / "tools" / "lab-certs" / "securaiq-lab-codesign.pfx"
    sign_env = (os.environ.get("SIGN_WINDOWS") or "").strip().lower() in {
        "1",
        "true",
        "yes",
    }
    return {
        "id": "authenticode_notarize",
        "code_unblocked": bool(scaffolds.get("ok")),
        "scaffolds": scaffolds,
        "lab_pfx_present": lab_pfx.is_file(),
        "sign_windows_env": sign_env,
        "ev_commercial": False,
        "status": "lab" if scaffolds.get("ok") else "partial",
        "hint": (
            "python scripts/realtime_remaining_full_proof.py  # lab self-signed PFX\n"
            "SIGN_WINDOWS=1 + EV cert → scripts/packaging/sign_windows.ps1"
        ),
        "disclaimer": "Lab self-signed ≠ EV Authenticode / SmartScreen trust",
    }


def worm_status() -> dict[str, Any]:
    try:
        from app.evidence_spine.worm import worm_backend_status

        w = worm_backend_status()
    except Exception as exc:
        w = {"configured": False, "error": str(exc)[:160]}
    cloud = bool(w.get("configured") and w.get("object_lock_enabled"))
    return {
        "id": "worm_object_lock",
        "code_unblocked": True,
        "local_markers": True,
        "cloud_object_lock": cloud,
        "backend": w,
        "status": "partial" if cloud else "lab",
        "disclaimer": "Local WORM markers ≠ cloud object-lock retention",
    }


def phase1_ops_remaining() -> dict[str, Any]:
    """Aggregate honest status for Phase-1 leftover gates."""
    items = [
        owned_host_status(),
        sentinel_ha_status(),
        capacity_http_status(),
        authenticode_status(),
        worm_status(),
    ]
    code_ok = all(bool(i.get("code_unblocked")) for i in items)
    ops_open = [i["id"] for i in items if i.get("status") in {"ops", "partial"}]
    return {
        "ok": code_ok,
        "code_unblocked_complete": code_ok,
        "ops_still_open": ops_open,
        "items": items,
        "freeze": (
            "Do not start Phase 5 twin / AI autonomy / cloud depth until "
            "owned-host + measured HA/load stay green."
        ),
        "disclaimer": (
            "code_unblocked_complete means scaffolds/CI/self-tests/readiness APIs "
            "are closed — not that commercial ops proofs are finished."
        ),
    }
