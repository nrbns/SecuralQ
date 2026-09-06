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


def _live_signal_mfa_coverage(user_id: str) -> dict[str, Any]:
    """Real MFA enrollment coverage across every user account -- not a
    per-framework live test (control_testing.py's _CONTROL_TEST_MAP has no
    MFA entry today), but a genuine telemetry signal this product already
    has: app.auth.list_users_public() + app.mfa.mfa_status() per user.
    Unscoped by design -- list_users_public() already lists every account
    in this deployment (same precedent as app/scim_api.py)."""
    from app.auth import list_users_public
    from app.mfa import mfa_status

    users = list_users_public()
    total = len(users)
    if total == 0:
        return {
            "test": "mfa_coverage",
            "status": "fail",
            "summary": "No user accounts found -- no evidence to assess MFA coverage.",
            "detail": {"total_users": 0, "mfa_enabled": 0, "admins_without_mfa": 0},
        }

    enabled = 0
    admins_without_mfa = 0
    for u in users:
        st = mfa_status(u["id"])
        if st.get("enabled"):
            enabled += 1
        elif (u.get("role") or "").lower() == "admin":
            admins_without_mfa += 1

    pct = round(enabled / total * 100, 1)
    if admins_without_mfa > 0:
        status = "partial" if pct >= 50 else "fail"
        summary = f"{admins_without_mfa} admin account(s) without MFA enrolled -- highest-privilege accounts are the priority regardless of overall coverage."
    elif pct >= 100:
        status = "pass"
        summary = f"All {total} user accounts have MFA enabled."
    elif pct >= 50:
        status = "partial"
        summary = f"{enabled} of {total} user accounts ({pct}%) have MFA enabled."
    else:
        status = "fail"
        summary = f"Only {enabled} of {total} user accounts ({pct}%) have MFA enabled."

    return {
        "test": "mfa_coverage",
        "status": status,
        "summary": summary,
        "detail": {"total_users": total, "mfa_enabled": enabled, "coverage_pct": pct, "admins_without_mfa": admins_without_mfa},
    }


def _live_signal_logging_monitoring(user_id: str) -> dict[str, Any]:
    """Real signal for 'is logging/monitoring active' -- proxied by installed
    SecuraIQ agent checkin freshness (app.agents.list_agents already derives
    online/offline from last_checkin age; this is the same signal
    app.services.risk_priority.py uses as a compensating control). Not a full
    SIEM-coverage claim -- an agent that's online is actively reporting
    telemetry, which is the honest scope of what SecuraIQ can verify today."""
    from app.agents import list_agents

    try:
        agents = list_agents(user_id)
    except Exception:
        agents = []
    total = len(agents)
    if total == 0:
        return {
            "test": "logging_monitoring",
            "status": "fail",
            "summary": "No agents enrolled -- no evidence of active telemetry/logging collection.",
            "detail": {"total_agents": 0, "online": 0, "coverage_pct": None},
        }

    online = sum(1 for a in agents if (a.get("status") or "").lower() == "online")
    pct = round(online / total * 100, 1)
    if pct >= 80:
        status = "pass"
        summary = f"{online} of {total} enrolled agents ({pct}%) are actively checking in with telemetry."
    elif pct >= 40:
        status = "partial"
        summary = f"Only {online} of {total} enrolled agents ({pct}%) are actively checking in -- monitoring coverage has gaps."
    else:
        status = "fail"
        summary = f"Only {online} of {total} enrolled agents ({pct}%) are actively checking in -- monitoring is largely inactive."

    return {
        "test": "logging_monitoring",
        "status": status,
        "summary": summary,
        "detail": {"total_agents": total, "online": online, "coverage_pct": pct},
    }


def _live_signal_asset_inventory(user_id: str) -> dict[str, Any] | None:
    from app.services.control_testing import TEST_ASSET_INVENTORY, run_live_test

    return run_live_test(user_id, TEST_ASSET_INVENTORY)


def _live_signal_vulnerability_management(user_id: str) -> dict[str, Any] | None:
    from app.services.control_testing import TEST_VULNERABILITY_MANAGEMENT, run_live_test

    return run_live_test(user_id, TEST_VULNERABILITY_MANAGEMENT)


# Canonical-control-id -> live-signal test function. Deliberately small and
# explicit, same philosophy as control_testing.py's _CONTROL_TEST_MAP: only a
# canonical control with a REAL, verifiable telemetry source gets an entry
# here. A canonical control absent from this map simply has no live signal
# yet -- its status still comes from gap-assessment evidence only.
_CANONICAL_LIVE_TESTS = {
    "mfa": _live_signal_mfa_coverage,
    "logging_monitoring": _live_signal_logging_monitoring,
    "asset_inventory": _live_signal_asset_inventory,
    "vulnerability_management": _live_signal_vulnerability_management,
}


def compute_live_signal(user_id: str, canonical_id: str) -> dict[str, Any] | None:
    """Independent real-telemetry check for one canonical control, if this
    product has a genuine data source for it. Returned alongside (never
    blended into) overall_status -- this is deliberately additive, mirroring
    control_testing.py's own separation of 'pasted evidence describes the
    control' from 'real telemetry shows the control operating'. None means
    no live signal exists yet for this canonical control, not that it failed."""
    fn = _CANONICAL_LIVE_TESTS.get(canonical_id)
    if not fn:
        return None
    try:
        return fn(user_id)
    except Exception:
        return None


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
        # Independent real-telemetry check, if this canonical control has one
        # (see _CANONICAL_LIVE_TESTS). Never blended into overall_status --
        # that stays a pure function of pasted-evidence gap assessments so
        # the two signal types (declared evidence vs. observed telemetry)
        # are never silently conflated into one number.
        "live_signal": compute_live_signal(user_id, canonical_id),
    }


def compute_all_canonical_statuses(user_id: str) -> list[dict[str, Any]]:
    return [compute_canonical_status(user_id, cc["id"]) for cc in list_canonical_controls()]
