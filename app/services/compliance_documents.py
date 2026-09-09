"""Per-framework compliance documentation: a real-world-named report plus a
corrective/remediation action plan for ANY framework in the catalog, built
strictly from data already in SecuraIQ for a specific gap assessment -- the
control catalog (data/frameworks/*.json), the assessment's scored results
(app.gap_analysis), linked evidence (app.commercial_ext), and remediation
tracking (gap_remediations).

This generalizes app.services.cmmc_documents (SSP/POA&M, CMMC/NIST-specific)
to every framework, using the document type and terminology actually used in
that framework's ecosystem instead of a one-size-fits-all label:

- cmmc_l2, nist_800_171, nist_800_53  -> System Security Plan (SSP) / POA&M
- iso27001, iso27701                  -> Statement of Applicability (SoA) / Corrective Action Plan
- hipaa                               -> Security Risk Assessment (SRA) Report / Corrective Action Plan
- pci_dss                             -> Compliance Readiness Report (SAQ-style) / Remediation Action Plan
- gdpr                                -> Article 32 Security Measures Report / Corrective Action Plan
- nis2                                -> Article 21 Risk-Management Measures Report / Corrective Action Plan
- soc2, cis_controls, owasp_asvs,
  owasp_top10, nist_csf (and anything
  else not listed above)              -> Control Implementation Report / Remediation Action Plan

Where real data doesn't exist yet -- no organization profile, no linked
evidence, no remediation owner, no data-processing register for a GDPR RoPA
-- the document says so explicitly rather than inventing a plausible-looking
value. Same honesty rules as cmmc_documents.py, evidence_workflow.py, and the
exception workflow: no fabricated compliance claims, and no document ever
claims to be a certified/accepted/audited artifact.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from app.services.cmmc_documents import (
    _asset_environment_summary,
    _control_catalog_by_id,
    _controls_from_assessment,
    _evidence_by_control,
    _org_name,
    _remediations_by_control,
    compute_sprs_preview,
)
from app.gap_analysis import get_assessment

# Per-framework document identity. `report_kind`/`plan_kind` are the labels
# used in headings and API responses; `report_caveat`/`plan_caveat` state
# plainly what SecuraIQ's version of that document is NOT, so nobody mistakes
# it for the real regulated/audited artifact.
FRAMEWORK_DOCS: dict[str, dict[str, str]] = {
    "cmmc_l2": {
        "report_kind": "System Security Plan (SSP)",
        "plan_kind": "Plan of Action & Milestones (POA&M)",
        "report_caveat": "not a certified SSP accepted by a C3PAO or the DoD",
        "plan_caveat": "not a POA&M accepted by any authority",
    },
    "nist_800_171": {
        "report_kind": "System Security Plan (SSP)",
        "plan_kind": "Plan of Action & Milestones (POA&M)",
        "report_caveat": "not a certified SSP",
        "plan_caveat": "not a POA&M accepted by any authority",
    },
    "nist_800_53": {
        "report_kind": "System Security Plan (SSP)",
        "plan_kind": "Plan of Action & Milestones (POA&M)",
        "report_caveat": "not an Authority to Operate (ATO) package or an accepted SSP",
        "plan_caveat": "not a POA&M accepted by any authorizing official",
    },
    "iso27001": {
        "report_kind": "Statement of Applicability (SoA)",
        "plan_kind": "Corrective Action Plan",
        "report_caveat": "not a management-approved SoA per ISO/IEC 27001 clause 6.1.3(d), and not a certification audit artifact",
        "plan_caveat": "not a certification-body-accepted corrective action record",
    },
    "iso27701": {
        "report_kind": "Statement of Applicability (SoA)",
        "plan_kind": "Corrective Action Plan",
        "report_caveat": "not a management-approved PIMS SoA, and not a certification audit artifact",
        "plan_caveat": "not a certification-body-accepted corrective action record",
    },
    "hipaa": {
        "report_kind": "Security Risk Assessment (SRA) Report",
        "plan_kind": "Corrective Action Plan",
        "report_caveat": "not an OCR-accepted Security Risk Assessment under 45 CFR 164.308(a)(1)",
        "plan_caveat": "not a corrective action plan accepted by HHS OCR",
    },
    "pci_dss": {
        "report_kind": "PCI DSS Compliance Readiness Report",
        "plan_kind": "Remediation Action Plan",
        "report_caveat": "not a completed Self-Assessment Questionnaire (SAQ) and not an Attestation of Compliance (AOC) -- those require a formal SAQ eligibility determination and, for many merchant levels, a QSA",
        "plan_caveat": "not a QSA-reviewed remediation plan",
    },
    "gdpr": {
        "report_kind": "Article 32 Security Measures Report",
        "plan_kind": "Corrective Action Plan",
        "report_caveat": (
            "not a Record of Processing Activities (RoPA) under Article 30 -- a RoPA requires a "
            "processing-purpose and data-category register that SecuraIQ does not yet collect, so "
            "this report covers the Article 32 technical/organizational security measures SecuraIQ "
            "can evidence, not the full data-processing inventory"
        ),
        "plan_caveat": "not a supervisory-authority-accepted remediation record",
    },
    "nis2": {
        "report_kind": "Article 21 Risk-Management Measures Report",
        "plan_kind": "Corrective Action Plan",
        "report_caveat": "not a competent-authority-accepted compliance filing",
        "plan_caveat": "not a competent-authority-accepted remediation record",
    },
}

DEFAULT_DOC = {
    "report_kind": "Control Implementation Report",
    "plan_kind": "Remediation Action Plan",
    "report_caveat": "not an audited or certified compliance artifact",
    "plan_caveat": "not an auditor-accepted remediation record",
}


def document_profile(framework_id: str) -> dict[str, str]:
    return FRAMEWORK_DOCS.get(framework_id, DEFAULT_DOC)


def _disclaimer(caveat: str) -> str:
    return (
        "This document is generated from SecuraIQ assessment data as an aid to preparing your own "
        f"compliance documentation -- it is {caveat}. Review, correct, and formally approve it "
        "through your organization's own process before submission, audit, or attestation."
    )


def generate_report_markdown(user_id: str, assessment_id: str) -> str:
    """The framework-appropriate implementation report (SSP / SoA / SRA /
    readiness report / generic control implementation report -- see
    FRAMEWORK_DOCS) for one assessment."""
    data = get_assessment(user_id, assessment_id)
    if not data:
        raise ValueError("Assessment not found")

    framework_id = data.get("framework_id") or ""
    profile = document_profile(framework_id)
    catalog = _control_catalog_by_id(framework_id)
    evidence_by_control = _evidence_by_control(user_id, data.get("engagement_id"))
    remediations = _remediations_by_control(user_id, assessment_id)
    org_name = _org_name(user_id)
    env = _asset_environment_summary(user_id)
    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    lines: list[str] = [
        f"# {profile['report_kind']}",
        "",
        f"**Organization:** {org_name}",
        f"**Framework:** {data.get('framework_name')} (`{framework_id}`)",
        f"**Based on assessment:** {data.get('title')} (`{assessment_id}`)",
        f"**Generated:** {generated}",
        "",
        f"> {_disclaimer(profile['report_caveat'])}",
        "",
        "## 1. System / environment scope",
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
        "system or processing boundary. Confirm and document the true scope separately before "
        "formal submission or audit.",
        "",
    ]

    section_num = 2
    if framework_id == "cmmc_l2":
        sprs = compute_sprs_preview(user_id, assessment_id)
        if sprs:
            section_num = 3
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
            cc = sprs.get("conditional_certification")
            if cc:
                lines += [
                    f"**Conditional Level 2 certification:** {'ELIGIBLE' if cc['eligible'] else 'NOT ELIGIBLE'} "
                    f"(needs score >= {cc['threshold']}, currently {'met' if cc['meets_score_threshold'] else 'not met'}; "
                    f"{len(cc['blocking_failures'])} open control(s) that cannot be deferred to a POA&M).",
                    "",
                    f"> {cc['disclaimer']}",
                    "",
                ]
                if cc["blocking_failures"]:
                    lines += ["Controls that must be fully implemented (no POA&M allowed):", ""]
                    for b in cc["blocking_failures"]:
                        lines.append(f"- {b['control_id']} ({b['weight']} pts, {b['status']}): {b['title']} — {b['reason']}")
                    lines.append("")

    lines += [f"## {section_num}. Control implementation status", ""]

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
        f"_Generated by SecuraIQ. Review with your compliance owner before use as a submitted "
        f"{profile['report_kind']}._",
    ]
    return "\n".join(lines)


def generate_action_plan_markdown(user_id: str, assessment_id: str) -> str:
    """The framework-appropriate open-items action plan (POA&M / corrective
    action plan / remediation action plan -- see FRAMEWORK_DOCS) for one
    assessment."""
    data = get_assessment(user_id, assessment_id)
    if not data:
        raise ValueError("Assessment not found")

    framework_id = data.get("framework_id") or ""
    profile = document_profile(framework_id)
    remediations = _remediations_by_control(user_id, assessment_id)
    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    results = _controls_from_assessment(data)
    open_items = [r for r in results if (r.get("status") or "").lower() in {"missing", "partial"}]
    open_items.sort(key=lambda x: (0 if x.get("status") == "missing" else 1, x.get("control_id", "")))

    lines: list[str] = [
        f"# {profile['plan_kind']}",
        "",
        f"**Framework:** {data.get('framework_name')} (`{framework_id}`)",
        f"**Based on assessment:** {data.get('title')} (`{assessment_id}`)",
        f"**Generated:** {generated}",
        f"**Open items:** {len(open_items)} of {len(results)} controls",
        "",
        f"> {_disclaimer(profile['plan_caveat'])}",
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
            cc = sprs.get("conditional_certification")
            if cc and cc["blocking_failures"]:
                lines += [
                    "",
                    "**Important — not eligible for this POA&M:** the DoD's published rule bars "
                    "5-point controls and the System Security Plan control (CA.L2-3.12.4) from "
                    "POA&M deferral. These open items below must be fully implemented directly, "
                    "not tracked as milestones on this plan:",
                    "",
                ]
                for b in cc["blocking_failures"]:
                    lines.append(f"- {b['control_id']} ({b['weight']} pts, {b['status']}): {b['title']} — {b['reason']}")

    lines += [
        "",
        "---",
        f"_Generated by SecuraIQ. {profile['plan_caveat'].capitalize()} until reviewed and approved "
        "through your own process._",
    ]
    return "\n".join(lines)
