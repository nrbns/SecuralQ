"""Live System Security Plan (SSP) — Sprint 6 of the Control & Configuration
Engine roadmap (see docs/control-config-engine.md).

The existing SSP feature (app.services.cmmc_documents.generate_ssp_markdown /
app.services.compliance_documents.generate_report_markdown) produces a
point-in-time exported document. This module is different: it answers "what
does the SSP look like RIGHT NOW, synced to the real environment" as JSON,
recomputed on every call from the same real data sources this product
already trusts elsewhere — never a cached or manually-edited document.

Per control, three independent signals are surfaced side by side, never
blended into one fake number (same separation the rest of this product
already enforces between pasted-evidence status and live-telemetry status):

  - evidence_status: the pasted-evidence gap-assessment status
    (implemented/partial/missing/not_applicable), if an assessment exists.
  - live_status: the rolled-up result of any curated live control test
    (app.controls.results / app.services.control_testing), if one is mapped.
  - verifiability: machine/partial/human/unknown (app.controls.catalog).

This mirrors the CMMC deck's warning that an SSP must describe the real
boundary, asset inventory and implementation -- not generic prose -- by
building the document FROM the real asset/control/evidence/remediation
tables every time, instead of letting a written document drift out of sync
with them.

Honesty rules (same as the rest of this product):
  - Never invent an implementation statement. If no evidence, no live test,
    and no remediation exist for a control, implementation_summary says so
    plainly.
  - Never claim certification, SPRS submission, or third-party assessment.
  - "poam_eligible" is read from the catalog when present (cmmc_l2 only
    today) -- never guessed for a framework whose catalog lacks it.
"""

from __future__ import annotations

from typing import Any

from app.controls.catalog import framework_meta, list_framework_controls
from app.db import get_conn, now, row_to_dict
from app.gap_analysis import get_assessment, list_assessments, load_framework

LIVE_SSP_DISCLAIMER = (
    "This is a live view of SecuraIQ's own data -- assets, gap-assessment evidence status, "
    "curated live control tests, and open remediations -- recomputed on every request. It is "
    "not a certified System Security Plan, not proof of CMMC or NIST SP 800-171 compliance, and "
    "not a substitute for your organization's own reviewed and approved SSP. Export the formal "
    "SSP document (System Security Plan export) for that; this view exists so the exported "
    "document and the real environment cannot silently drift apart."
)


def _latest_assessment(user_id: str, framework_id: str) -> dict[str, Any] | None:
    for row in list_assessments(user_id):
        if row.get("framework_id") == framework_id:
            full = get_assessment(user_id, row["id"])
            if full:
                full["_assessment_id"] = row["id"]
                full["_assessment_title"] = row.get("title")
                full["_assessment_created_at"] = row.get("created_at")
            return full
    return None


def _evidence_status_by_control(data: dict[str, Any] | None) -> dict[str, dict[str, Any]]:
    if not data:
        return {}
    controls = data.get("controls") or data.get("results") or []
    if isinstance(controls, dict):
        controls = list(controls.values())
    out: dict[str, dict[str, Any]] = {}
    for r in controls:
        if not isinstance(r, dict):
            continue
        cid = str(r.get("control_id") or r.get("id") or "").strip().upper()
        if not cid:
            continue
        out[cid] = {
            "status": r.get("status") or "missing",
            "recommendation": r.get("recommendation") or "",
        }
    return out


def _remediations_by_control(user_id: str, assessment_id: str | None) -> dict[str, dict[str, Any]]:
    if not assessment_id:
        return {}
    rows = get_conn().execute(
        """
        SELECT control_id, title, status, owner, due_date, notes, updated_at
        FROM gap_remediations WHERE assessment_id = ? AND user_id = ?
        """,
        (assessment_id, user_id),
    ).fetchall()
    out: dict[str, dict[str, Any]] = {}
    for r in rows:
        d = row_to_dict(r)
        cid = (d.get("control_id") or "").strip().upper()
        if cid:
            out[cid] = d
    return out


def _evidence_links_by_control(user_id: str) -> dict[str, list[dict[str, Any]]]:
    try:
        from app.commercial_ext import list_evidence_links
    except Exception:
        return {}
    out: dict[str, list[dict[str, Any]]] = {}
    try:
        for link in list_evidence_links(user_id):
            cid = (link.get("control_id") or "").strip().upper()
            if cid:
                out.setdefault(cid, []).append(link)
    except Exception:
        return {}
    return out


def _asset_environment_summary(user_id: str) -> dict[str, Any]:
    """Real counts from the assets table -- the same honesty rule the rest
    of this product uses: never describe the environment except from what's
    actually stored."""
    rows = get_conn().execute(
        "SELECT asset_type, COUNT(*) AS n FROM assets WHERE user_id = ? GROUP BY asset_type",
        (user_id,),
    ).fetchall()
    by_type = {row_to_dict(r)["asset_type"]: row_to_dict(r)["n"] for r in rows}
    total = sum(by_type.values())

    scope_rows: list[dict[str, Any]] = []
    try:
        from app.cmmc_scoping import scope_breakdown

        all_assets = [
            row_to_dict(r)
            for r in get_conn()
            .execute("SELECT cmmc_asset_category FROM assets WHERE user_id = ?", (user_id,))
            .fetchall()
        ]
        breakdown = scope_breakdown(all_assets)
        scope_rows = [{"category": k or "unclassified", "count": v} for k, v in breakdown.items()]
    except Exception:
        scope_rows = []

    user_count = 0
    try:
        from app.auth import list_users_public

        user_count = len(list_users_public())
    except Exception:
        user_count = 0

    return {"total_assets": total, "by_type": by_type, "cmmc_scope": scope_rows, "user_count": user_count}


def _live_test_status(user_id: str, framework_id: str, control_id: str) -> dict[str, Any] | None:
    try:
        from app.controls.results import get_results_for_control
    except Exception:
        return None
    try:
        results = get_results_for_control(user_id, framework_id, control_id)
    except Exception:
        return None
    if not results:
        return None
    statuses = [str(r.get("status") or "unknown").lower() for r in results]
    if any(s == "fail" for s in statuses):
        rolled = "fail"
    elif any(s == "partial" for s in statuses):
        rolled = "partial"
    elif all(s == "pass" for s in statuses):
        rolled = "pass"
    else:
        rolled = "unknown"
    last_tested = max((r.get("tested_at") or 0) for r in results)
    return {"status": rolled, "tests": results, "last_tested": last_tested}


def live_ssp_snapshot(user_id: str, framework_id: str) -> dict[str, Any]:
    """The full live SSP for one framework -- recomputed now, every call."""
    fw = load_framework(framework_id)
    fid = str(fw.get("id") or framework_id)
    meta = framework_meta(fid)
    catalog_controls = list_framework_controls(fid)

    assessment = _latest_assessment(user_id, fid)
    evidence_status = _evidence_status_by_control(assessment)
    assessment_id = (assessment or {}).get("_assessment_id")
    remediations = _remediations_by_control(user_id, assessment_id)
    evidence_links = _evidence_links_by_control(user_id)
    environment = _asset_environment_summary(user_id)

    controls_out: list[dict[str, Any]] = []
    counts = {"implemented": 0, "partial": 0, "missing": 0, "not_assessed": 0}
    for c in catalog_controls:
        cid = c.id.upper()
        ev = evidence_status.get(cid)
        live = _live_test_status(user_id, fid, cid)
        rem = remediations.get(cid)
        links = evidence_links.get(cid, [])

        if ev:
            ev_status = (ev.get("status") or "missing").lower()
        else:
            ev_status = "not_assessed"
        bucket = ev_status if ev_status in counts else "not_assessed"
        counts[bucket] += 1

        if live:
            implementation_summary = f"Live control test: {live['status']}."
        elif ev:
            implementation_summary = f"Evidence-assessed: {ev_status}."
        else:
            implementation_summary = "Not yet assessed -- no evidence and no live test result on record."

        controls_out.append({
            "control_id": c.id,
            "title": c.title,
            "domain": c.domain,
            "verifiability": c.verifiability,
            "evidence_status": ev_status,
            "live_status": (live or {}).get("status"),
            "live_last_tested": (live or {}).get("last_tested"),
            "implementation_summary": implementation_summary,
            "owner": (rem or {}).get("owner") or "",
            "remediation_status": (rem or {}).get("status") or "",
            "due_date": (rem or {}).get("due_date") or "",
            "evidence_count": len(links),
            "poam_eligible": c.raw.get("poam_eligible"),
            "sprs_weight": c.raw.get("sprs_weight"),
        })

    return {
        "framework_id": fid,
        "framework_name": meta.name,
        "last_synchronized": now(),
        "environment": environment,
        "controls_total": meta.control_count,
        "counts": counts,
        "assessment_id": assessment_id,
        "assessment_title": (assessment or {}).get("_assessment_title"),
        "controls": controls_out,
        "disclaimer": LIVE_SSP_DISCLAIMER,
    }


def live_ssp_control_detail(user_id: str, framework_id: str, control_id: str) -> dict[str, Any] | None:
    """One control's live SSP entry, with full live-test history and evidence links."""
    fw = load_framework(framework_id)
    fid = str(fw.get("id") or framework_id)
    from app.controls.catalog import get_control

    c = get_control(fid, control_id)
    if not c:
        return None
    cid = c.id.upper()

    assessment = _latest_assessment(user_id, fid)
    evidence_status = _evidence_status_by_control(assessment)
    assessment_id = (assessment or {}).get("_assessment_id")
    rem = _remediations_by_control(user_id, assessment_id).get(cid)
    links = _evidence_links_by_control(user_id).get(cid, [])
    live = _live_test_status(user_id, fid, cid)
    ev = evidence_status.get(cid)

    return {
        "control_id": c.id,
        "title": c.title,
        "domain": c.domain,
        "description": c.description,
        "verifiability": c.verifiability,
        "evidence_status": (ev or {}).get("status") or "not_assessed",
        "evidence_recommendation": (ev or {}).get("recommendation") or "",
        "live_test": live,
        "owner": (rem or {}).get("owner") or "",
        "remediation": rem,
        "evidence_links": links,
        "poam_eligible": c.raw.get("poam_eligible"),
        "sprs_weight": c.raw.get("sprs_weight"),
        "last_synchronized": now(),
        "disclaimer": LIVE_SSP_DISCLAIMER,
    }
