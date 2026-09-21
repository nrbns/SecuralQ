"""SPRS preparation snapshot — readiness pack, not SPRS submission."""

from __future__ import annotations

from typing import Any

from app.cmmc.objectives import list_objectives, seed_objectives_for_framework
from app.cmmc.poam_policy import poam_policy_for_framework
from app.cmmc.schema import ensure_cmmc_assessment_schema
from app.cmmc.versioning import framework_version_info
from app.controls.catalog import list_framework_controls
from app.db import get_conn, now


def _status_map(user_id: str) -> dict[str, str]:
    ensure_cmmc_assessment_schema()
    rows = get_conn().execute(
        "SELECT objective_id, status FROM cmmc_objective_status WHERE user_id = ?",
        (user_id,),
    ).fetchall()
    return {r["objective_id"]: r["status"] for r in rows}


def _rollup(obj_ids: list[str], stmap: dict[str, str]) -> str:
    met = partial = not_met = unknown = 0
    for oid in obj_ids:
        st = stmap.get(oid) or "unknown"
        if st == "met":
            met += 1
        elif st == "partial":
            partial += 1
        elif st == "not_met":
            not_met += 1
        else:
            unknown += 1
    if not_met:
        return "not_met"
    if partial or (met and unknown):
        return "partial"
    if met and not unknown:
        return "met"
    return "unknown"


def sprs_preparation_snapshot(
    user_id: str,
    *,
    framework_id: str = "cmmc_l2",
    org_id: str | None = None,
) -> dict[str, Any]:
    """Build SPRS *preparation* inputs from live data. Does not submit to SPRS."""
    ver = framework_version_info(framework_id)
    seed_objectives_for_framework(framework_id)
    policy = poam_policy_for_framework(framework_id)
    stmap = _status_map(user_id)

    by_ctrl: dict[str, list[str]] = {}
    for o in list_objectives(framework_id):
        by_ctrl.setdefault(o["control_id"], []).append(o["id"])

    controls_out = []
    weighted_met = 0
    weighted_total = 0
    met_n = partial_n = not_met_n = unknown_n = 0

    for c in list_framework_controls(framework_id):
        raw = c.raw or {}
        weight = int(raw.get("sprs_weight") or 1)
        weighted_total += weight
        rollup = _rollup(by_ctrl.get(c.id) or [], stmap)
        if rollup == "met":
            met_n += 1
            weighted_met += weight
        elif rollup == "partial":
            partial_n += 1
        elif rollup == "not_met":
            not_met_n += 1
        else:
            unknown_n += 1
        controls_out.append(
            {
                "control_id": c.id,
                "title": c.title,
                "domain": c.domain,
                "sprs_weight": weight,
                "cmmc_level1": bool(raw.get("cmmc_level1")),
                "poam_eligible": raw.get("poam_eligible"),
                "rollup_status": rollup,
            }
        )

    affirmation = None
    try:
        from app.services.cmmc_affirmation import latest_affirmation

        affirmation = latest_affirmation(user_id, framework_id=framework_id)
    except Exception:
        affirmation = None

    scope = None
    try:
        from app.cmmc_scoping import FULL_ASSESSMENT_CATEGORIES, scope_breakdown
        from app.enterprise import list_assets

        assets = list_assets(user_id, org_id=org_id, limit=2000)
        breakdown = scope_breakdown(assets)
        cui_n = sum(breakdown.get(k, 0) for k in FULL_ASSESSMENT_CATEGORIES)
        scope = {
            "breakdown": breakdown,
            "full_assessment_asset_count": cui_n,
            "total_assets": len(assets),
        }
    except Exception:
        scope = None

    open_poams = []
    try:
        from app.cmmc.poam_items import list_poam_items

        open_poams = list_poam_items(user_id, framework_id=framework_id, status="open")
    except Exception:
        open_poams = []

    score_prep = None
    if weighted_total:
        score_prep = {
            "weighted_met": weighted_met,
            "weighted_total": weighted_total,
            "note": (
                "Illustrative weighted rollup from objective scaffolds + SPRS catalog weights. "
                "Not an official SPRS score. Unknown/partial do not count as met."
            ),
        }

    return {
        "ok": True,
        "prepared_at": now(),
        "framework": ver,
        "poam_policy": policy,
        "scope": scope,
        "requirement_counts": {
            "met": met_n,
            "partial": partial_n,
            "not_met": not_met_n,
            "unknown": unknown_n,
            "total": len(controls_out),
        },
        "score_preparation": score_prep,
        "affirmation": affirmation,
        "open_poams": open_poams,
        "controls": controls_out,
        "disclaimer": (
            "SPRS Preparation only — SecuraIQ does not submit scores or affirmations to SPRS. "
            "Export this snapshot for your organization's official SPRS entry process."
        ),
    }
