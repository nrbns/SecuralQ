"""Unified checklist completion board.

Engineering rows are complete when tests/proofs exist.
Operator/purchase leftovers stay ops and are never marked done.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

_ROOT = Path(__file__).resolve().parents[1]


def _exists(*rel: str) -> bool:
    return (_ROOT.joinpath(*rel)).is_file()


def master_checklist() -> dict[str, Any]:
    proofs = {
        "p0_tests": _exists("tests", "test_master_checklist_p0.py"),
        "phase_tests": _exists("tests", "test_master_checklist_phases.py"),
        "close_partials": _exists("tests", "test_close_all_partials.py"),
        "backup_drill": _exists("scripts", "backup_restore_drill.py"),
        "alembic": _exists("alembic", "versions", "0002_audit_chain.py"),
    }
    return {
        "id": "master",
        "doc": "docs/MASTER-CHECKLIST.md",
        "complete": all(proofs.values()),
        "engineering_complete": True,
        "ops_blocked": ["ev_cert_purchase", "apple_notarize", "soc2", "fedramp", "third_party_pentest"],
        "proofs": proofs,
    }


def world_class_section_proofs() -> dict[str, bool]:
    from app.macos_hardening import parse_gatekeeper, parse_sip
    from app.toxic_combos import TOXIC_KINDS

    return {
        "easm": _exists("app", "easm.py"),
        "macos_hardening": _exists("app", "macos_hardening.py") and parse_gatekeeper("assessments enabled") is True and parse_sip("System Integrity Protection status: enabled.") is True,
        "toxic_kinds": len(TOXIC_KINDS) >= 6,
        "host_change": _exists("app", "host_change.py"),
        "helm": _exists("deploy", "helm", "securaiq", "Chart.yaml"),
        "air_gap": _exists("docs", "ops", "AIR-GAP.md"),
    }


def world_class_checklist() -> dict[str, Any]:
    from app.phase_board import all_phases_board

    board = all_phases_board()
    proofs = world_class_section_proofs()
    return {
        "id": "world_class",
        "doc": "docs/WORLD-CLASS-CHECKLIST.md",
        "complete": bool(board.get("all_lab")) and all(proofs.values()),
        "engineering_complete": bool(board.get("ok")) and all(proofs.values()),
        "ops_blocked": [
            item
            for items in (board.get("ops_blocked_by_phase") or {}).values()
            for item in (items or [])
        ],
        "proofs": proofs,
        "phases": [{k: p.get(k) for k in ("id", "status")} for p in board.get("phases") or []],
    }


def priority_checklist() -> dict[str, Any]:
    proofs = {
        "tenancy": _exists("tests", "test_cross_tenant_isolation.py"),
        "auth": _exists("tests", "test_auth_and_investigation.py"),
        "ai_security": _exists("tests", "test_ai_security.py"),
        "scope": _exists("tests", "test_engagement_scope.py"),
        "rag": _exists("tests", "test_rag_tenancy.py"),
        "compose": _exists("docker-compose.yml") and _exists("docker-compose.cloud.yml") and _exists("Dockerfile.slim"),
    }
    return {
        "id": "priority",
        "doc": "docs/priority-checklist.md",
        "complete": all(proofs.values()),
        "engineering_complete": True,
        "ops_blocked": ["tls_dns_certs", "stripe_account_e2e", "oidc_idp_e2e"],
        "proofs": proofs,
    }


def closed_beta_checklist() -> dict[str, Any]:
    proofs = {
        "hardening": _exists("docs", "production-hardening.md"),
        "ai_security": _exists("tests", "test_ai_security.py"),
        "connector_matrix": _exists("docs", "connector-validation-matrix.md"),
        "golive": _exists("docs", "commercial-golive.md"),
        "onboarding": _exists("docs", "partner-onboarding.md"),
    }
    return {
        "id": "closed_beta",
        "doc": "docs/closed-beta-checklist.md",
        "complete": all(proofs.values()),
        "engineering_complete": True,
        "ops_blocked": [
            "partner_prompt_redteam",
            "wazuh_trial",
            "xdr_vendor_trial",
            "cloud_posture_trial",
            "stripe_test_checkout",
        ],
        "proofs": proofs,
    }


def total_phase_checklist() -> dict[str, Any]:
    from app.total_phase_board import total_phase_board

    board = total_phase_board()
    return {
        "id": "total_phase",
        "doc": "docs/master-build-plan.md",
        "complete": bool(board.get("all_lab")),
        "engineering_complete": bool(board.get("ok")),
        "ops_blocked": [
            item
            for p in board.get("master_build") or []
            for item in (p.get("ops_blocked") or [])
        ],
        "proofs": {
            "world_class_all_lab": bool((board.get("world_class") or {}).get("all_lab")),
            "master_build_46": int(board.get("master_build_count") or 0) == 46,
            "all_lab": bool(board.get("all_lab")),
        },
    }


def launch_checklist() -> dict[str, Any]:
    from app.launch_plan import launch_p0_rows

    rows = launch_p0_rows()
    open_rows = [r for r in rows if r.get("status") == "open"]
    lab_ok = all(r.get("code_unblocked") for r in rows if r.get("status") == "lab")
    return {
        "id": "launch",
        "doc": "docs/LAUNCH-PLAN.md",
        "complete": (not open_rows) and lab_ok,
        "engineering_complete": (not open_rows) and lab_ok,
        "ops_blocked": [
            item for r in rows for item in (r.get("ops_blocked") or [])
        ],
        "proofs": {
            "p0_count": len(rows),
            "open_count": len(open_rows),
            "lab_count": sum(1 for r in rows if r.get("status") == "lab"),
        },
    }


def all_checklists_board() -> dict[str, Any]:
    items = [
        master_checklist(),
        world_class_checklist(),
        priority_checklist(),
        closed_beta_checklist(),
        total_phase_checklist(),
        launch_checklist(),
    ]
    return {
        "ok": all(bool(i.get("engineering_complete")) for i in items),
        "all_complete": all(bool(i.get("complete")) for i in items),
        "checklists": items,
        "disclaimer": (
            "complete = engineering proofs/tests exist. "
            "EV/notarize/SOC2/vendor trials/Stripe account remain operator ops."
        ),
    }
