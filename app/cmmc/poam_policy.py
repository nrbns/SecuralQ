"""POA&M policy — framework/version aware (not generic ignore).

CMMC Level 1: POA&Ms not permitted for unmet basic safeguarding.
CMMC Level 2 (self-assessment): POA&Ms permitted under catalog rules; close within 180 days.
Per-control ``poam_eligible`` from catalog is authoritative when present.
"""

from __future__ import annotations

from typing import Any

from app.controls.catalog import list_framework_controls
from app.gap_analysis import load_framework

# Official program guidance (catalog status_note also documents this): L2 self-assessment
# POA&Ms must be closed within 180 days when permitted.
L2_POAM_CLOSE_DAYS = 180


def poam_policy_for_framework(framework_id: str = "cmmc_l2") -> dict[str, Any]:
    fid = (framework_id or "cmmc_l2").strip().lower()
    fw = load_framework(fid)
    version = str(fw.get("version") or "")
    if "level 1" in version.lower() or fid in {"cmmc_l1", "cmmc_level1"}:
        return {
            "framework_id": fid,
            "version": version,
            "poam_permitted": False,
            "close_within_days": None,
            "rule": "CMMC Level 1 self-assessment does not permit POA&Ms for unmet practices.",
            "disclaimer": "Confirm on official DoD CMMC pages; SecuraIQ enforces catalog policy only.",
        }
    # Default L2 / 800-171 style
    return {
        "framework_id": fid,
        "version": version,
        "poam_permitted": True,
        "close_within_days": L2_POAM_CLOSE_DAYS,
        "rule": (
            f"POA&Ms permitted only for controls with catalog poam_eligible=true; "
            f"must close within {L2_POAM_CLOSE_DAYS} days when opened under L2 self-assessment rules."
        ),
        "disclaimer": "Not a SPRS filing. Confirm current DoD POA&M rules before contractual use.",
    }


def poam_policy_for_control(framework_id: str, control_id: str) -> dict[str, Any]:
    base = poam_policy_for_framework(framework_id)
    cid = (control_id or "").strip()
    eligible = None
    sprs_weight = None
    title = ""
    for c in list_framework_controls(framework_id):
        if c.id.upper() == cid.upper() or c.id == cid:
            raw = c.raw or {}
            eligible = raw.get("poam_eligible")
            sprs_weight = raw.get("sprs_weight")
            title = c.title
            break
    permitted = bool(base.get("poam_permitted"))
    if eligible is False:
        permitted = False
    elif eligible is True and base.get("poam_permitted"):
        permitted = True
    elif eligible is None and not base.get("poam_permitted"):
        permitted = False
    return {
        **base,
        "control_id": cid,
        "control_title": title,
        "catalog_poam_eligible": eligible,
        "sprs_weight": sprs_weight,
        "poam_permitted_for_control": permitted,
        "reason": (
            "Catalog marks poam_eligible=false (often Level-1 basic safeguarding / weighted)."
            if eligible is False
            else (
                "Framework does not permit POA&Ms."
                if not base.get("poam_permitted")
                else "POA&M permitted under catalog + framework policy."
            )
        ),
    }
