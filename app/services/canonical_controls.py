"""Canonical Control Registry -- the cross-framework control engine.

SecuraIQ's 14 framework catalogs (657 controls) each score independently
today: enabling MFA satisfies cmmc_l2's IA.L2-3.5.3 and iso27001's A.8.5 as
two unrelated facts, even though they're the same real-world control. This
module is the layer that connects them: data/frameworks/canonical_controls.json
defines ~20 real, universally-recognized security controls (MFA, encryption
at rest/in transit, vulnerability management, backups, ...), each mapped to
the specific control IDs that genuinely cover it in every framework where
that mapping is real (verified by reading the actual control text -- never
padded).

Two things live here:

1. Static registry lookups (list/get canonical controls, reverse-lookup
   "which canonical controls does framework X's control Y belong to").
2. REAL cross-framework impact computation: given a user's actual gap
   assessments, compute each canonical control's status per framework from
   the real scored control status in that assessment -- not a theoretical
   "this framework has a matching control" claim. A framework with no
   assessment yet is reported as not_assessed, never guessed at.

This is the foundation for the "implement once, satisfied in N frameworks"
feature and for wiring live findings to compliance status (canonical
controls are what a live control test or a real finding should eventually
update, instead of only a manually pasted-evidence gap assessment).
"""

from __future__ import annotations

import json
from functools import lru_cache
from typing import Any

from app.gap_analysis import get_assessment, list_assessments
from app.paths import resource_root

_REGISTRY_PATH = resource_root() / "data" / "frameworks" / "canonical_controls.json"

_STATUS_RANK = {"implemented": 3, "partial": 2, "missing": 1, "not_applicable": 0}


@lru_cache(maxsize=1)
def _load_registry_cached(mtime: float) -> dict[str, Any]:
    return json.loads(_REGISTRY_PATH.read_text(encoding="utf-8"))


def load_registry() -> dict[str, Any]:
    # Cache keyed on mtime so tests that rewrite the fixture (or a future
    # live edit) don't read a stale registry, without re-parsing the file on
    # every call in the common case.
    mtime = _REGISTRY_PATH.stat().st_mtime
    return _load_registry_cached(mtime)


def list_canonical_controls() -> list[dict[str, Any]]:
    return list(load_registry()["canonical_controls"])


def get_canonical_control(canonical_id: str) -> dict[str, Any] | None:
    for c in list_canonical_controls():
        if c["id"] == canonical_id:
            return c
    return None


def canonical_controls_for(framework_id: str, control_id: str) -> list[dict[str, Any]]:
    """Reverse lookup: which canonical control(s) does this specific
    framework control belong to? Used to show 'this also satisfies N other
    frameworks' inline next to a single control in Control Center."""
    control_id_upper = (control_id or "").strip().upper()
    out = []
    for c in list_canonical_controls():
        ids = c["frameworks"].get(framework_id) or []
        if any(i.strip().upper() == control_id_upper for i in ids):
            out.append(c)
    return out


def _latest_assessment_id_by_framework(user_id: str) -> dict[str, str]:
    """Most recent assessment id per framework_id for this user -- real gap
    analysis runs only, never fabricated. list_assessments is already
    ordered by created_at DESC, so the first row seen per framework is the
    latest one."""
    latest: dict[str, str] = {}
    for a in list_assessments(user_id):
        fw = a.get("framework_id")
        if fw and fw not in latest:
            latest[fw] = a["id"]
    return latest


def compute_canonical_status(user_id: str, canonical_id: str) -> dict[str, Any] | None:
    """Real, per-framework status for one canonical control, computed from
    the user's actual latest assessment per mapped framework -- not a
    static claim. A framework with no assessment yet is reported as
    not_assessed rather than guessed."""
    cc = get_canonical_control(canonical_id)
    if not cc:
        return None

    latest_ids_by_fw = _latest_assessment_id_by_framework(user_id)
    frameworks: dict[str, Any] = {}
    satisfied = 0
    assessed = 0

    for fw_id, control_ids in cc["frameworks"].items():
        assessment_id = latest_ids_by_fw.get(fw_id)
        assessment = get_assessment(user_id, assessment_id) if assessment_id else None
        if not assessment:
            frameworks[fw_id] = {
                "status": "not_assessed",
                "control_ids": control_ids,
                "assessment_id": None,
                "has_assessment": False,
            }
            continue

        assessed += 1
        results = assessment.get("results") or []
        by_id = {str(r.get("control_id") or "").strip().upper(): r for r in results}
        matched = [by_id[c.upper()] for c in control_ids if c.upper() in by_id]
        if not matched:
            # Assessment exists for this framework but the mapped control
            # id wasn't found in its results -- report honestly rather than
            # silently treating it as implemented or missing.
            frameworks[fw_id] = {
                "status": "unknown",
                "control_ids": control_ids,
                "assessment_id": assessment.get("id"),
                "has_assessment": True,
            }
            continue

        # Worst-case across the mapped controls in this framework: a
        # canonical control isn't satisfied by a framework until every
        # control that represents it there is implemented.
        worst = min(matched, key=lambda r: _STATUS_RANK.get(r.get("status"), 0))
        status = worst.get("status") or "missing"
        if status == "implemented":
            satisfied += 1
        frameworks[fw_id] = {
            "status": status,
            "control_ids": control_ids,
            "assessment_id": assessment.get("id"),
            "has_assessment": True,
        }

    total_mapped = len(cc["frameworks"])
    if assessed == 0:
        overall = "not_assessed"
    elif satisfied == assessed:
        overall = "implemented"
    elif satisfied > 0:
        overall = "partial"
    else:
        overall = "missing"

    return {
        "id": cc["id"],
        "name": cc["name"],
        "category": cc["category"],
        "description": cc["description"],
        "frameworks": frameworks,
        "frameworks_total_mapped": total_mapped,
        "frameworks_assessed": assessed,
        "frameworks_satisfied": satisfied,
        "overall_status": overall,
    }


def compute_all_canonical_statuses(user_id: str) -> list[dict[str, Any]]:
    return [compute_canonical_status(user_id, cc["id"]) for cc in list_canonical_controls()]
