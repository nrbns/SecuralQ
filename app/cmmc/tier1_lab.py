"""CMMC Tier-1 lab-production readiness — not C3PAO / SPRS submit.

Aggregates existing SSP / POA&M / SPRS-prep / audit-pack / management view
into one honest gate for control-plane status.
"""

from __future__ import annotations

from typing import Any


def tier1_lab_readiness(
    user_id: str,
    *,
    framework_id: str = "cmmc_l2",
) -> dict[str, Any]:
    """Return lab-production checklist for Tier-1 CMMC model surfaces."""
    from app.cmmc.audit_pack import build_cmmc_audit_pack_zip
    from app.cmmc.management_view import cmmc_management_view
    from app.cmmc.poam_items import list_poam_items
    from app.cmmc.poam_policy import poam_policy_for_framework
    from app.cmmc.sprs_prep import sprs_preparation_snapshot
    from app.cmmc.ssp_engine import ssp_engine_snapshot

    checks: dict[str, Any] = {}
    errors: list[str] = []

    try:
        ssp = ssp_engine_snapshot(user_id, framework_id)
        checks["ssp_engine"] = {
            "ok": True,
            "controls_total": ssp.get("controls_total") or (ssp.get("counts") or {}).get("total"),
        }
    except Exception as exc:
        checks["ssp_engine"] = {"ok": False, "error": str(exc)[:200]}
        errors.append("ssp_engine")

    try:
        policy = poam_policy_for_framework(framework_id)
        poams = list_poam_items(user_id, framework_id=framework_id)
        checks["poam"] = {
            "ok": True,
            "policy": policy.get("poam_permitted"),
            "items": len(poams),
        }
    except Exception as exc:
        checks["poam"] = {"ok": False, "error": str(exc)[:200]}
        errors.append("poam")

    try:
        sprs = sprs_preparation_snapshot(user_id, framework_id=framework_id)
        checks["sprs_prep"] = {
            "ok": True,
            "submits_to_sprs": False,
            "requirement_counts": sprs.get("requirement_counts"),
        }
    except Exception as exc:
        checks["sprs_prep"] = {"ok": False, "error": str(exc)[:200]}
        errors.append("sprs_prep")

    try:
        mv = cmmc_management_view(user_id, framework_id=framework_id)
        checks["management_view"] = {
            "ok": True,
            "assessment_readiness_percent": mv.get("assessment_readiness_percent"),
        }
    except Exception as exc:
        checks["management_view"] = {"ok": False, "error": str(exc)[:200]}
        errors.append("management_view")

    try:
        blob = build_cmmc_audit_pack_zip(user_id, framework_id=framework_id)
        checks["audit_pack"] = {"ok": True, "bytes": len(blob or b"")}
    except Exception as exc:
        checks["audit_pack"] = {"ok": False, "error": str(exc)[:200]}
        errors.append("audit_pack")

    ready = not errors and all(bool(c.get("ok")) for c in checks.values())
    return {
        "ok": ready,
        "framework_id": framework_id,
        "tier": "tier-1-lab",
        "lab_production": ready,
        "checks": checks,
        "errors": errors,
        "c3pao_submit": False,
        "sprs_submit": False,
        "note": (
            "Tier-1 lab-production: objectives/SSP/POA&M/SPRS-prep/audit-pack/management view. "
            "Not a C3PAO determination and SecuraIQ does not submit to SPRS."
        ),
    }
