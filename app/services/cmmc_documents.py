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
    """
    data = get_assessment(user_id, assessment_id)
    if not data or data.get("framework_id") != "cmmc_l2":
        return None
    catalog = _control_catalog_by_id("cmmc_l2")
    if not any("sprs_weight" in c for c in catalog.values()):
        return None

    max_score = sum(c.get("sprs_weight", 0) for c in catalog.values())
    lost = 0
    unimplemented: list[dict[str, Any]] = []
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
    score = max_score - lost
    unimplemented.sort(key=lambda x: -x["weight"])
    return {
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


def generate_ssp_markdown(user_id: str, assessment_id: str) -> str:
    data = get_assessment(user_id, assessment_id)
    if not data:
        raise ValueError("Assessment not found")

    framework_id = data.get("framework_id") or ""
    catalog = _control_catalog_by_id(framework_id)
    evidence_by_control = _evidence_by_control(user_id, data.get("engagement_id"))
    remediations = _remediations_by_control(user_id, assessment_id)
    org_name = _org_name(user_id)
    env = _asset_environment_summary(user_id)
    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    lines: list[str] = [
        "# System Security Plan (SSP)",
        "",
        f"**Organization:** {org_name}",
        f"**Framework:** {data.get('framework_name')} (`{framework_id}`)",
        f"**Based on assessment:** {data.get('title')} (`{assessment_id}`)",
        f"**Generated:** {generated}",
        "",
        f"> {DOCUMENT_DISCLAIMER}",
        "",
        "## 1. System identification and environment",
        "",
        f"SecuraIQ's asset inventory for this organization currently tracks **{env['total']}** "
        "registered asset(s)"
        + (
            ": " + ", ".join(f"{n} {t}" for t, n in sorted(env["by_type"].items(), key=lambda kv: -kv[1]))
            if env["by_type"]
            else " -- no assets have been registered yet in Assets."
        )
        + ".",
        "",
        "This scope reflects what has been entered into SecuraIQ, not an independently verified "
        "system boundary. Confirm and document the authorization boundary (CUI flow, external "
        "connections, and any out-of-scope segments) separately before formal submission.",
        "",
    ]

    if framework_id == "cmmc_l2":
        sprs = compute_sprs_preview(user_id, assessment_id)
        if sprs:
            lines += [
                "## 2. SPRS score preview",
                "",
                f"**Preview score:** {sprs['score']} / {sprs['max_score']}",
                "",
                f"> {sprs['disclaimer']}",
                "",
            ]
            if sprs["top_point_losses"]:
                lines += ["Largest point losses:", ""]
                for u in sprs["top_point_losses"]:
                    lines.append(f"- {u['control_id']} ({u['weight']} pts, {u['status']}): {u['title']}")
                lines.append("")

    section_num = 3 if framework_id == "cmmc_l2" else 2
    lines += [f"## {section_num}. Security requirements", ""]

    results = _controls_from_assessment(data)
    by_domain: dict[str, list[dict[str, Any]]] = {}
    for r in results:
        by_domain.setdefault(r.get("domain") or "Uncategorized", []).append(r)

    for domain in sorted(by_domain):
        lines.append(f"### {domain}")
        lines.append("")
        for r in sorted(by_domain[domain], key=lambda x: x.get("control_id", "")):
            cid = str(r.get("control_id") or "").strip()
            cid_up = cid.upper()
            ctrl = catalog.get(cid_up, {})
            status = r.get("status") or "missing"
            lines.append(f"**{cid} — {r.get('title')}** ({status})")
            weight = ctrl.get("sprs_weight")
            l1 = ctrl.get("cmmc_level1")
            tags = []
            if weight is not None:
                tags.append(f"SPRS weight {weight}")
            if l1:
                tags.append("CMMC Level 1")
            if tags:
                lines.append(f"_{' · '.join(tags)}_")
            lines.append("")
            ev_links = evidence_by_control.get(cid_up) or []
            accepted = [e for e in ev_links if (e.get("status") or "").lower() == "accepted"]
            if accepted:
                lines.append("Implementation evidence on file:")
                for e in accepted:
                    fname = e.get("filename") or "(file)"
                    note = f" — {e['notes']}" if e.get("notes") else ""
                    lines.append(f"- {fname}{note}")
            else:
                lines.append(
                    "Implementation description: not yet documented — no accepted evidence "
                    "linked to this control in SecuraIQ."
                )
            rem = remediations.get(cid_up)
            if rem:
                due = rem.get("due_date") or "no target date set"
                owner = rem.get("owner") or "unassigned"
                lines.append(f"Remediation owner: {owner} (target: {due}, status: {rem.get('status')})")
            lines.append("")

    lines += [
        "---",
        "_Generated by SecuraIQ. Review with your ISSO/ISSM before use as a submitted SSP._",
    ]
    return "\n".join(lines)


def generate_poam_markdown(user_id: str, assessment_id: str) -> str:
    data = get_assessment(user_id, assessment_id)
    if not data:
        raise ValueError("Assessment not found")

    framework_id = data.get("framework_id") or ""
    catalog = _control_catalog_by_id(framework_id)
    remediations = _remediations_by_control(user_id, assessment_id)
    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    results = _controls_from_assessment(data)
    open_items = [r for r in results if (r.get("status") or "").lower() in {"missing", "partial"}]
    open_items.sort(key=lambda x: (0 if x.get("status") == "missing" else 1, x.get("control_id", "")))

    lines: list[str] = [
        "# Plan of Action & Milestones (POA&M)",
        "",
        f"**Framework:** {data.get('framework_name')} (`{framework_id}`)",
        f"**Based on assessment:** {data.get('title')} (`{assessment_id}`)",
        f"**Generated:** {generated}",
        f"**Open items:** {len(open_items)} of {len(results)} controls",
        "",
        f"> {DOCUMENT_DISCLAIMER}",
        "",
        "| Control | Weakness | Status | Owner | Target date | Remediation status |",
        "|---|---|---|---|---|---|",
    ]

    for r in open_items:
        cid = str(r.get("control_id") or "").strip()
        rem = remediations.get(cid.upper())
        weakness = (r.get("recommendation") or r.get("title") or "").replace("|", "/").replace("\n", " ")
        owner = (rem.get("owner") if rem else "") or "_not assigned_"
        due = (rem.get("due_date") if rem else "") or "_no target date set_"
        rem_status = (rem.get("status") if rem else "") or "_no remediation created_"
        lines.append(
            f"| {cid} | {weakness[:160]} | {r.get('status')} | {owner} | {due} | {rem_status} |"
        )

    lines += ["", "## Milestones without an assigned owner or target date", ""]
    unowned = [
        r
        for r in open_items
        if not (remediations.get(str(r.get("control_id") or "").upper()) or {}).get("owner")
    ]
    if unowned:
        for r in unowned:
            lines.append(f"- {r.get('control_id')} — {r.get('title')}: create a remediation with an owner and target date.")
    else:
        lines.append("None — every open control has an assigned remediation owner.")

    if framework_id == "cmmc_l2":
        sprs = compute_sprs_preview(user_id, assessment_id)
        if sprs:
            lines += [
                "",
                "## SPRS score impact",
                "",
                f"Closing every item above would move the preview score from **{sprs['score']}** "
                f"toward **{sprs['max_score']}** (subject to the scoring caveats above).",
            ]

    lines += [
        "",
        "---",
        "_Generated by SecuraIQ. Not a POA&M accepted by any authority until reviewed and approved "
        "through your own process._",
    ]
    return "\n".join(lines)
