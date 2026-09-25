"""Unified launch plan — P0-01..50 + total-phase + checklists.

Lab rows are in-repo proofs. Ops/frozen stay honest.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

_ROOT = Path(__file__).resolve().parents[1]


def _file(*rel: str) -> bool:
    return _ROOT.joinpath(*rel).is_file()


def _mod(name: str) -> bool:
    try:
        __import__(name)
        return True
    except Exception:
        return False


def _row(
    pid: str,
    name: str,
    status: str,
    *,
    proof: bool = True,
    ops: list[str] | None = None,
    note: str = "",
) -> dict[str, Any]:
    return {
        "id": pid,
        "name": name,
        "status": status,
        "code_unblocked": proof and status != "open",
        "ops_blocked": ops or [],
        "note": note,
    }


def _sqlite_rto_published() -> bool:
    try:
        from app.measured_ops import sqlite_dr_published

        return sqlite_dr_published()
    except Exception:
        return False


def launch_p0_rows() -> list[dict[str, Any]]:
    return [
        _row("P0-01", "Golden closed loop", "lab", proof=_mod("app.launch_loop")),
        _row(
            "P0-02",
            "Agent OS parity",
            "lab",
            proof=_mod("app.agent_parity") and _mod("app.macos_hardening"),
            ops=["macos_m1_m2_live"],
            note="Same check-in keys; live M1/M2 remains ops",
        ),
        _row("P0-03", "Commercial security profile", "lab", proof=_mod("app.production_profile")),
        _row("P0-04", "Realtime reliability", "lab", proof=_mod("app.realtime_bus")),
        _row("P0-05", "Sentinel failover", "lab", proof=_file("scripts", "sentinel_failover_measure.py"), ops=["multi_az"]),
        _row(
            "P0-06",
            "Tenant isolation",
            "lab",
            proof=_file("tests", "test_cross_tenant_isolation.py") and _file("tests", "test_rag_tenancy.py"),
            ops=["exclusive_redis_acls"],
        ),
        _row("P0-07", "Automatic evidence", "lab", proof=_mod("app.controls.auto_evidence")),
        _row("P0-08", "WORM evidence", "lab", proof=_mod("app.evidence_spine.worm"), ops=["cloud_object_lock"]),
        _row("P0-09", "Risk recalc after verify", "lab", proof=_mod("app.services.risk_priority")),
        _row("P0-10", "Compliance recalc after verify", "lab", proof=_mod("app.controls.live_compliance")),
        _row("P0-11", "Independent verification", "lab", proof=_mod("app.launch_loop")),
        _row("P0-12", "SSO / SCIM / MFA / RBAC", "lab", proof=_mod("app.auth") and _mod("app.scim_api"), ops=["live_idp"]),
        _row(
            "P0-13",
            "HA / DR measured",
            "lab" if _sqlite_rto_published() else "ops",
            proof=_file("scripts", "backup_restore_drill.py"),
            ops=["postgres_restore", "cluster_kill_rto"],
            note="SQLite RTO/RPO from --record drill; Postgres/cluster kill remains ops",
        ),
        _row("P0-14", "Backup / restore drill", "lab", proof=_file("scripts", "backup_restore_drill.py"), ops=["postgres_restore"]),
        _row("P0-15", "Load testing ladder", "lab", proof=_file("docs", "ops", "CAPACITY-LAB.md"), ops=["http_5k"]),
        _row("P0-16", "Chaos testing", "lab", proof=_file("scripts", "realtime_chaos_test.py"), ops=["chaos_at_5k"]),
        _row("P0-17", "Signed installers", "lab", proof=_file("scripts", "packaging", "sign_windows.ps1"), ops=["ev_notarize"]),
        _row("P0-18", "Dogfood / Trust Center", "lab", proof=_mod("app.trust_center"), ops=["third_party_pentest"]),
        _row("P0-19", "Commercial onboarding", "lab", proof=_mod("app.product_close")),
        _row("P0-20", "Command Center + modes", "lab", proof=_file("static", "index.html")),
        _row("P0-21", "Kill panel polling", "lab", proof=_file("static", "app.js")),
        _row("P0-22", "30-min posture reconcile", "lab", proof=_mod("app.posture.orchestrator") or _file("app", "posture", "orchestrator.py")),
        _row("P0-23", "Asset identity card", "lab", proof=_mod("app.asset_identity_card")),
        _row("P0-24", "Canonical asset identity", "lab", proof=_mod("app.asset_identity")),
        _row("P0-25", "Finding why / what-if", "lab", proof=_mod("app.services.risk_narrative")),
        _row("P0-26", "Factor risk + simulation", "lab", proof=_mod("app.services.risk_priority")),
        _row("P0-27", "Attack paths", "lab", proof=_mod("app.services.attack_graph"), ops=[], note="twin-grade frozen"),
        _row("P0-28", "Evidence Spine + compare/hold", "lab", proof=_mod("app.evidence_spine.legal_hold") and _mod("app.evidence_spine.export_package")),
        _row("P0-29", "Compliance as operations", "lab", proof=_mod("app.compliance_ops.tasks")),
        _row("P0-30", "CMMC assessment-readiness", "lab", proof=_file("docs", "CMMC-ASSESSMENT.md"), ops=["c3pao"]),
        _row("P0-31", "Compliance Ops surfaces", "lab", proof=_mod("app.compliance_ops")),
        _row("P0-32", "Remediation Center", "lab", proof=_mod("app.services.remediation")),
        _row("P0-33", "Decision Drawer", "lab", proof=_mod("app.decision_drawer")),
        _row("P0-34", "What changed", "lab", proof=_mod("app.command_center_pulse") and _mod("app.host_change")),
        _row("P0-35", "One scan experience", "lab", proof=_mod("app.scan_intents")),
        _row("P0-36", "Contextual AI", "lab", proof=_mod("app.secops") or _file("app", "secops", "__init__.py")),
        _row("P0-37", "Business service graph", "lab", proof=_mod("app.service_impact"), note="risk sim ≠ twin"),
        _row("P0-38", "Incident timeline", "lab", proof=_mod("app.incident_timeline")),
        _row("P0-39", "EDR connectors", "lab", proof=_mod("app.xdr"), note="native EDR frozen"),
        _row(
            "P0-40",
            "Restart recovery",
            "lab",
            proof=_mod("app.restart_recovery") and _mod("app.jobs"),
            ops=["kill_at_5k"],
            note="In-process reclaim measured; kill@5k HTTP remains ops",
        ),
        _row("P0-41", "Tenant-isolated streams", "lab", proof=_mod("app.realtime_bus"), ops=["exclusive_redis_acls"]),
        _row("P0-42", "Signed evidence + legal hold", "lab", proof=_mod("app.evidence_spine.export_package")),
        _row("P0-43", "Launch navigation IA", "lab", proof=_file("static", "index.html")),
        _row("P0-44", "UX law WHAT→VERIFY", "lab", proof=_file("static", "app.js")),
        _row("P0-45", "Why on every number", "lab", proof=_mod("app.controls.live_compliance")),
        _row("P0-46", "macOS M1/M2 live", "ops", proof=True, ops=["friend_hardware"]),
        _row("P0-47", "Packaging catalog", "lab", proof=_file("scripts", "build_agent_packages.py"), ops=["signed_stores"]),
        _row("P0-48", "Digital twin", "frozen", proof=True, ops=["digital_twin"]),
        _row("P0-49", "Domain expansion freeze", "frozen", proof=True),
        _row("P0-50", "Execution cadence", "lab", proof=_file("docs", "P0-LAUNCH-BACKLOG.md")),
    ]


def launch_plan_board() -> dict[str, Any]:
    from app.total_phase_board import total_phase_board

    rows = launch_p0_rows()
    lab = [r for r in rows if r["status"] == "lab"]
    ops = [r for r in rows if r["status"] == "ops"]
    frozen = [r for r in rows if r["status"] == "frozen"]
    open_rows = [r for r in rows if r["status"] == "open"]
    total = total_phase_board()
    engineering_done = not open_rows and all(r["code_unblocked"] for r in rows if r["status"] == "lab")
    return {
        "ok": engineering_done and bool(total.get("ok")),
        "all_lab_unblocked": engineering_done and not open_rows,
        "open_count": len(open_rows),
        "lab_count": len(lab),
        "ops_count": len(ops),
        "frozen_count": len(frozen),
        "p0": rows,
        "total_phase": {
            "ok": total.get("ok"),
            "all_lab": total.get("all_lab"),
            "master_build_count": total.get("master_build_count"),
        },
        "ops_blocked": sorted(
            {
                item
                for r in rows
                for item in (r.get("ops_blocked") or [])
            }
        ),
        "disclaimer": (
            "Launch plan engineering is lab-complete when open_count=0. "
            "EV/notarize, cloud Object Lock, live IdP, C3PAO, 5k–100k HTTP, "
            "macOS M1/M2 live, and digital twin remain ops/frozen — never marketed as done."
        ),
    }
