"""CMMC / NIST SP 800-171 documentation generators: System Security Plan
(SSP), Plan of Action & Milestones (POA&M), and a real SPRS score preview.

These are NOT templates filled with placeholder prose. Every section is
built strictly from data already in SecuraIQ for a specific gap assessment:
the control catalog (data/frameworks/cmmc_l2.json), the assessment's scored
results (app.gap_analysis), linked evidence (app.commercial_ext), and
remediation tracking (gap_remediations). Where the real data doesn't exist
yet -- no organization profile, no linked evidence, no remediation owner --
the document says so explicitly rather than inventing a plausible-looking
value. This mirrors the same honesty rules already applied to the audit
pack and exception workflow: no fabricated compliance claims.

Works for any framework, but the SPRS score preview and Level 1 marking are
only meaningful for cmmc_l2, since only that catalog carries `sprs_weight`
and `cmmc_level1` fields.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from app.commercial_ext import list_evidence_links, list_orgs
from app.db import get_conn, row_to_dict
from app.gap_analysis import get_assessment, load_framework


def _controls_from_assessment(data: dict[str, Any]) -> list[dict[str, Any]]:
    """Same extraction rule as app.evidence_workflow._controls_from_assessment
    -- assessments store the scored control list under 'results' (current
    schema) or 'controls' (older payloads)."""
    controls = data.get("controls") or data.get("results") or []
    if isinstance(controls, dict):
        controls = list(controls.values())
    return [c for c in controls if isinstance(c, dict)]

DOCUMENT_DISCLAIMER = (
    "This document is generated from SecuraIQ assessment data as an aid to preparing your own "
    "System Security Plan / POA&M -- it is not a certified SSP, not a POA&M accepted by any "
    "authority, and not proof of CMMC or NIST SP 800-171 compliance. Review, correct, and "
    "formally approve it through your organization's own process before submission or "
    "affirmation into SPRS."
)


def _org_name(user_id: str) -> str:
    try:
        orgs = list_orgs(user_id)
    except Exception:
        orgs = []
    if orgs:
        return orgs[0].get("name") or "Unnamed organization"
    return "Not set — no organization profile configured in SecuraIQ"


def _asset_environment_summary(user_id: str) -> dict[str, Any]:
    """Real counts from the assets table -- never invented environment prose."""
    rows = get_conn().execute(
        "SELECT asset_type, COUNT(*) AS n FROM assets WHERE user_id = ? GROUP BY asset_type",
        (user_id,),
    ).fetchall()
    by_type = {row_to_dict(r)["asset_type"]: row_to_dict(r)["n"] for r in rows}
    total = sum(by_type.values())
    return {"total": total, "by_type": by_type}


def _evidence_by_control(user_id: str, engagement_id: str | None) -> dict[str, list[dict[str, Any]]]:
    out: dict[str, list[dict[str, Any]]] = {}
    for link in list_evidence_links(user_id, engagement_id=engagement_id):
        cid = (link.get("control_id") or "").strip().upper()
        if not cid:
            continue
        out.setdefault(cid, []).append(link)
    return out


def _remediations_by_control(user_id: str, assessment_id: str) -> dict[str, dict[str, Any]]:
    rows = get_conn().execute(
        """
        SELECT control_id, title, status, owner, due_date, notes, recommendation, created_at, updated_at
        FROM gap_remediations WHERE assessment_id = ? AND user_id = ?
        """,
        (assessment_id, user_id),
    ).fetchall()
    out: dict[str, dict[str, Any]] = {}
    for r in rows:
        d = row_to_dict(r)
        out[(d.get("control_id") or "").strip().upper()] = d
    return out


def _control_catalog_by_id(framework_id: str) -> dict[str, dict[str, Any]]:
    fw = load_framework(framework_id)
    return {c["id"].upper(): c for c in fw.get("controls") or []}


def compute_sprs_preview(user_id: str, assessment_id: str) -> dict[str, Any] | None:
    """A real, computed SPRS-style score preview -- only for cmmc_l2 assessments
    whose catalog controls carry sprs_weight. Full credit for status=implemented,
    zero credit for missing/partial/not covered. This does NOT model the two
    official partial-credit exceptions (MFA 3.5.3, FIPS crypto 3.13.11) because
    SecuraIQ's per-control status doesn't capture that level of nuance -- the
    preview is conservative (scores lower than a nuanced official assessment
    might) rather than guessing at partial credit. Not a substitute for the
    DoD NIST SP 800-171 Assessment Methodology worksheet.

    Also reports whether the org would qualify for "Conditional" Level 2
    status under the DoD's published rule: score >= 88 out of 110 AND no
    open (unimplemented) control that is ineligible for a POA&M. Control
    eligibility comes from the catalog's `poam_eligible` field (added per
    control: false for every 5-point control, and for CA.L2-3.12.4 (the
    System Security Plan control), which the rule explicitly bars from POA&M
    deferral regardless of its own point weight). If the catalog doesn't
    carry `poam_eligible` yet, this section is omitted rather than guessed.
    """
    data = get_assessment(user_id, assessment_id)
    if not data or data.get("framework_id") != "cmmc_l2":
        return None
    catalog = _control_catalog_by_id("cmmc_l2")
    if not any("sprs_weight" in c for c in catalog.values()):
        return None
    has_poam_field = any("poam_eligible" in c for c in catalog.values())

    max_score = sum(c.get("sprs_weight", 0) for c in catalog.values())
    lost = 0
    unimplemented: list[dict[str, Any]] = []
    blocking_failures: list[dict[str, Any]] = []
    for r in _controls_from_assessment(data):
        cid = str(r.get("control_id") or r.get("id") or "").strip().upper()
        ctrl = catalog.get(cid)
        if not ctrl:
            continue
        status = (r.get("status") or "").lower()
        weight = ctrl.get("sprs_weight", 0)
        if status != "implemented" and status != "not_applicable":
            lost += weight
            if weight:
                unimplemented.append({"control_id": cid, "title": ctrl.get("title"), "weight": weight, "status": status})
            if has_poam_field and not ctrl.get("poam_eligible", True):
                blocking_failures.append({
                    "control_id": cid,
                    "title": ctrl.get("title"),
                    "weight": weight,
                    "status": status,
                    "reason": (
                        "System Security Plan (CA.L2-3.12.4) cannot be deferred to a POA&M"
                        if cid == "CA.L2-3.12.4"
                        else "5-point control cannot be deferred to a POA&M"
                    ),
                })
    score = max_score - lost
    unimplemented.sort(key=lambda x: -x["weight"])
    blocking_failures.sort(key=lambda x: (-x["weight"], x["control_id"]))

    result: dict[str, Any] = {
        "score": score,
        "max_score": max_score,
        "points_lost": lost,
        "method": "conservative_no_partial_credit",
        "disclaimer": (
            "Computed from this SecuraIQ assessment's control statuses using official DoD SPRS "
            "point weights, with full credit only for status=implemented. Does not apply the "
            "official MFA/FIPS partial-credit rules and is not a substitute for the DoD NIST SP "
            "800-171 Assessment Methodology worksheet used for actual SPRS submission."
        ),
        "top_point_losses": unimplemented[:10],
    }
    if has_poam_field:
        meets_88 = score >= 88
        result["conditional_certification"] = {
            "threshold": 88,
            "meets_score_threshold": meets_88,
            "blocking_failures": blocking_failures,
            "eligible": meets_88 and not blocking_failures,
            "disclaimer": (
                "Reflects the published DoD rule for Conditional Level 2 status (score >= 88/110 "
                "AND no open control ineligible for a POA&M). This is SecuraIQ's own read of that "
                "rule applied to your assessment data -- not an official eligibility determination "
                "and not a substitute for your C3PAO or the DoD Assessment Methodology worksheet."
            ),
        }
    return result


def generate_ssp_markdown(user_id: str, assessment_id: str) -> str:
    """CMMC/NIST-flavored System Security Plan. Thin wrapper kept for backward
    compatibility (existing routes/tests) -- the real, framework-generic
    implementation now lives in app.services.compliance_documents so every
    framework gets its own correctly-named document (SoA, SRA, readiness
    report, etc.) instead of everything being called an "SSP". Imported
    lazily to avoid a module-load-time circular import (compliance_documents
    imports the helper functions in this module)."""
    from app.services.compliance_documents import generate_report_markdown

    return generate_report_markdown(user_id, assessment_id)


def generate_poam_markdown(user_id: str, assessment_id: str) -> str:
    """CMMC/NIST-flavored POA&M. Thin wrapper -- see generate_ssp_markdown."""
    from app.services.compliance_documents import generate_action_plan_markdown

    return generate_action_plan_markdown(user_id, assessment_id)
