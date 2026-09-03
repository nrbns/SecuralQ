"""Cross-cutting compliance aggregates -- the Compliance Center overview and
the Audit Center. Both are read-only rollups over data that already exists
elsewhere (gap_assessments, evidence_links, securaiq_exceptions, live
control tests); nothing here invents a number. A framework that has never
been assessed is reported as not-assessed, not scored 0%, and is excluded
from the overall percentage rather than silently dragging it down.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any


def _latest_assessment_by_framework(user_id: str) -> dict[str, dict[str, Any]]:
    from app.gap_analysis import list_assessments

    latest: dict[str, dict[str, Any]] = {}
    for row in list_assessments(user_id):
        fid = row.get("framework_id")
        if fid and fid not in latest:
            latest[fid] = row
    return latest


def _evidence_expiring_soon(user_id: str, *, within_days: int = 30) -> list[dict[str, Any]]:
    """Evidence links with a parseable expiry date landing within the
    window. `evidence_links.expiry` is free text (see app.commercial_ext),
    so anything that doesn't parse as a real date is skipped rather than
    guessed at -- an unparseable expiry is not the same claim as "expiring
    soon" and must not be reported as one."""
    from app.commercial_ext import list_evidence_links

    out: list[dict[str, Any]] = []
    now_dt = datetime.now(timezone.utc)
    for link in list_evidence_links(user_id):
        raw = (link.get("expiry") or "").strip()
        if not raw:
            continue
        parsed = None
        for fmt in ("%Y-%m-%d", "%Y-%m-%dT%H:%M:%S", "%m/%d/%Y"):
            try:
                parsed = datetime.strptime(raw, fmt).replace(tzinfo=timezone.utc)
                break
            except ValueError:
                continue
        if not parsed:
            continue
        days = (parsed - now_dt).days
        if 0 <= days <= within_days:
            out.append(
                {
                    "link_id": link.get("id"),
                    "control_id": link.get("control_id"),
                    "filename": link.get("filename"),
                    "expiry": raw,
                    "days_until_expiry": days,
                }
            )
    out.sort(key=lambda x: x["days_until_expiry"])
    return out[:50]


def compliance_overview(user_id: str, *, org_id: str | None = None) -> dict[str, Any]:
    """Overall %, per-framework breakdown, evidence expiring soon, and
    exception coverage -- only for frameworks this tenant has actually
    assessed. Never blends in an un-assessed framework's control count as
    if it were scored."""
    from app.gap_analysis import get_assessment, list_frameworks
    from app.services.control_testing import controls_with_live_tests
    from app.services.exceptions import exceptions_summary

    catalog = list_frameworks()
    latest_by_fw = _latest_assessment_by_framework(user_id)

    fw_rows: list[dict[str, Any]] = []
    totals = {"implemented": 0, "partial": 0, "missing": 0, "not_applicable": 0}
    pct_sum = 0.0
    pct_n = 0
    for fw in catalog:
        fid = fw["id"]
        assessed = latest_by_fw.get(fid)
        entry: dict[str, Any] = {
            "framework_id": fid,
            "name": fw["name"],
            "control_count": fw["control_count"],
            "assessed": bool(assessed),
            "compliance_percent": None,
            "counts": {"implemented": 0, "partial": 0, "missing": 0, "not_applicable": 0},
            "assessment_id": None,
            "live_tested_controls": len(controls_with_live_tests(fid)),
        }
        if assessed:
            full = get_assessment(user_id, assessed["id"])
            if full:
                entry["assessment_id"] = assessed["id"]
                entry["compliance_percent"] = full.get("compliance_percent")
                counts = full.get("counts") or {}
                for k in entry["counts"]:
                    entry["counts"][k] = int(counts.get(k) or 0)
                    totals[k] += entry["counts"][k]
                pct_sum += float(entry["compliance_percent"] or 0)
                pct_n += 1
        fw_rows.append(entry)

    return {
        "overall_compliance_percent": round(pct_sum / pct_n, 1) if pct_n else None,
        "frameworks_assessed": pct_n,
        "frameworks_total": len(catalog),
        "counts": totals,
        "frameworks": fw_rows,
        "evidence_expiring_soon": _evidence_expiring_soon(user_id),
        "exceptions": exceptions_summary(user_id, org_id=org_id),
        "methodology": (
            "compliance_percent per framework is the pasted-evidence gap-analysis score "
            "(see app.gap_analysis.SCORING_METHODOLOGY, a keyword heuristic -- not an audit "
            "or certification). Only assessed frameworks count toward the overall percentage; "
            "frameworks never assessed are listed with assessed=false and excluded from it."
        ),
    }


def audit_center_overview(user_id: str, *, org_id: str | None = None) -> dict[str, Any]:
    """Evidence requested/supplied/missing and control pass/fail/pending
    counts, rolled up across every framework's latest assessment. Per-
    assessment export (build_audit_pack_zip) still needs an assessment_id --
    this view is for seeing where an audit package would and wouldn't be
    ready before generating one."""
    from app.evidence_workflow import evidence_coverage_for_assessment
    from app.gap_analysis import get_assessment
    from app.services.exceptions import exceptions_summary

    latest_by_fw = _latest_assessment_by_framework(user_id)

    frameworks_out: list[dict[str, Any]] = []
    totals = {
        "controls_total": 0,
        "passing": 0,
        "failing": 0,
        "pending": 0,
        "evidence_supplied": 0,
        "evidence_missing": 0,
    }
    for fid, row in latest_by_fw.items():
        aid = row["id"]
        try:
            coverage = evidence_coverage_for_assessment(user_id, aid)
        except ValueError:
            continue
        full = get_assessment(user_id, aid) or {}
        counts = full.get("counts") or {}
        passing = int(counts.get("implemented") or 0)
        failing = int(counts.get("missing") or 0)
        pending = int(counts.get("partial") or 0)
        total = int(coverage.get("controls_total") or 0)
        supplied = int(coverage.get("controls_with_evidence") or 0)
        missing_ev = max(total - supplied, 0)
        frameworks_out.append(
            {
                "framework_id": fid,
                "framework_name": full.get("framework_name") or fid,
                "assessment_id": aid,
                "controls_total": total,
                "passing": passing,
                "failing": failing,
                "pending": pending,
                "evidence_supplied": supplied,
                "evidence_missing": missing_ev,
                "evidence_coverage_percent": coverage.get("coverage_percent"),
            }
        )
        totals["controls_total"] += total
        totals["passing"] += passing
        totals["failing"] += failing
        totals["pending"] += pending
        totals["evidence_supplied"] += supplied
        totals["evidence_missing"] += missing_ev

    return {
        "frameworks": sorted(frameworks_out, key=lambda f: f["framework_id"]),
        "totals": totals,
        "exceptions": exceptions_summary(user_id, org_id=org_id),
        "assessments_included": len(frameworks_out),
    }
