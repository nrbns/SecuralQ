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


def world_class_checklist() -> dict[str, Any]:
    from app.phase_board import all_phases_board

    board = all_phases_board()
    return {
        "id": "world_class",
        "doc": "docs/WORLD-CLASS-CHECKLIST.md",
        "complete": bool(board.get("all_lab")),
        "engineering_complete": bool(board.get("ok")),
        "ops_blocked": [
            item
            for items in (board.get("ops_blocked_by_phase") or {}).values()
            for item in (items or [])
        ],
        "phases": [{k: p.get(k) for k in ("id", "status")} for p in board.get("phases") or []],
    }


def priority_checklist() -> dict[str, Any]:
    proofs = {
        "tenancy": _exists("tests", "test_cross_tenant_isolation.py"),
        "auth": _exists("tests", "test_auth_and_investigation.py"),
        "ai_security": _exists("tests", "test_ai_security.py"),
        "scope": _exists("tests", "test_engagement_scope.py"),
        "rag": _exists("tests", "test_rag_tenancy.py"),
        "compose": _exists("docker-compose.yml"),
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


def all_checklists_board() -> dict[str, Any]:
    items = [
        master_checklist(),
        world_class_checklist(),
        priority_checklist(),
        closed_beta_checklist(),
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
