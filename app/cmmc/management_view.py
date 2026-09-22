"""Executive / management CMMC readiness view — not 110 controls dumped.

Composes scope, requirements rollup, evidence freshness, POA&M, risk headline,
assessment readiness. Honest disclaimers; not SPRS submit or certification.
"""

from __future__ import annotations

from typing import Any

from app.db import now


def cmmc_management_view(
    user_id: str,
    *,
    framework_id: str = "cmmc_l2",
) -> dict[str, Any]:
    from app.cmmc.cui_program import list_cui_programs
    from app.cmmc.poam_items import list_poam_items
    from app.cmmc.readiness import framework_readiness_summary
    from app.cmmc.sprs_prep import sprs_preparation_snapshot
    from app.cmmc.versioning import framework_version_info
    from app.services.live_ssp import live_ssp_snapshot

    ver = framework_version_info(framework_id)
    ssp = live_ssp_snapshot(user_id, framework_id)
    sprs = sprs_preparation_snapshot(user_id, framework_id=framework_id)
    # Sample readiness for speed on full 110 — use full when small; cap compute
    readiness = framework_readiness_summary(user_id, framework_id)
    poams = list_poam_items(user_id, framework_id=framework_id, status="open")
    cui = list_cui_programs(user_id)

    env = ssp.get("environment") or {}
    req = sprs.get("requirement_counts") or {}
    bands = readiness.get("bands") or {}

    # Evidence currency heuristic from readiness freshness bands
    high = int(bands.get("HIGH") or 0)
    med = int(bands.get("MEDIUM") or 0)
    low = int(bands.get("LOW") or 0)
    scored = max(high + med + low, 1)
    evidence_current_pct = round(100.0 * (high + 0.5 * med) / scored, 1)

    # Assessment readiness bar from SPRS weighted met ratio when available
    weighted = sprs.get("weighted") or {}
    w_met = float(weighted.get("met") or 0)
    w_total = float(weighted.get("total") or 0) or 1.0
    assessment_readiness_pct = round(100.0 * w_met / w_total, 1)

    critical_poam = sum(
        1 for p in poams if (p.get("risk_level") or "").lower() in {"critical", "high"}
    )

    risk: dict[str, Any] = {}
    try:
        from app.services.risk_priority import compute_org_risk_score

        risk = compute_org_risk_score(user_id)
    except Exception:
        risk = {}

    exceptions_near: list[dict[str, Any]] = []
    try:
        from app.services.exceptions import list_exceptions

        for e in list_exceptions(user_id, status="approved", limit=100):
            days = e.get("days_until_expiry")
            if e.get("expired") or (days is not None and float(days) <= 30):
                exceptions_near.append(
                    {
                        "id": e.get("id"),
                        "title": e.get("title"),
                        "control_id": e.get("control_id"),
                        "days_until_expiry": days,
                        "expired": e.get("expired"),
                    }
                )
    except Exception:
        exceptions_near = []

    cui_asset_n = sum(int((p.get("scope_summary") or {}).get("assets") or 0) for p in cui)
    cui_system_n = sum(int((p.get("scope_summary") or {}).get("systems") or 0) for p in cui)

    return {
        "ok": True,
        "view": "cmmc_management_readiness",
        "framework": {
            "id": framework_id,
            "version": ver.get("version"),
            "status_note": ver.get("status_note"),
        },
        "scope": {
            "total_assets": env.get("total_assets"),
            "cmmc_scope": env.get("cmmc_scope"),
            "cui_programs": len(cui),
            "cui_assets": cui_asset_n,
            "cui_systems": cui_system_n,
        },
        "requirements": {
            "met": req.get("met") or 0,
            "partial": req.get("partial") or 0,
            "not_met": req.get("not_met") or 0,
            "unknown": req.get("unknown") or 0,
            "total": req.get("total") or 0,
        },
        "evidence": {
            "current_percent": evidence_current_pct,
            "readiness_bands": bands,
            "needs_review": readiness.get("needs_review"),
        },
        "poam": {
            "open": len(poams),
            "critical_or_high": critical_poam,
        },
        "exceptions_nearing_expiry": exceptions_near[:20],
        "risk": {
            "score": risk.get("score"),
            "band": risk.get("band"),
            "total_open": risk.get("total_open"),
        },
        "assessment_readiness_percent": assessment_readiness_pct,
        "affirmation": (sprs.get("affirmation") or {}),
        "computed_at": now(),
        "disclaimer": (
            "Management readiness view aggregates SecuraIQ local signals. "
            "Not a C3PAO finding, SPRS submission, or certification claim."
        ),
    }
