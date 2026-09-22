"""Readiness Confidence — multi-signal, not a single PASS/FAIL score.

Honesty: confidence bands are SecuraIQ heuristics from local evidence,
objectives, freshness, and attestations. They are not C3PAO determinations.
"""

from __future__ import annotations

from typing import Any

from app.cmmc.objectives import get_control_assessment, seed_objectives_for_framework
from app.cmmc.schema import ensure_cmmc_assessment_schema
from app.controls.catalog import list_framework_controls
from app.db import get_conn, now


def _band(score: float) -> str:
    if score >= 0.75:
        return "HIGH"
    if score >= 0.4:
        return "MEDIUM"
    return "LOW"


def _avg(vals: list[float]) -> float:
    return sum(vals) / len(vals) if vals else 0.0


def control_readiness_confidence(
    user_id: str,
    framework_id: str,
    control_id: str,
) -> dict[str, Any]:
    """Per-control readiness confidence from objectives + methods + SSP + attestations."""
    ensure_cmmc_assessment_schema()
    detail = get_control_assessment(user_id, framework_id, control_id)

    objs = detail.get("objectives") or []
    met = int((detail.get("counts") or {}).get("met") or 0)
    partial = int((detail.get("counts") or {}).get("partial") or 0)
    total_obj = max(len(objs), 1)
    assessment_cov = (met + 0.5 * partial) / total_obj

    methods = detail.get("method_evidence") or []
    by_method = {m: 0 for m in ("examine", "interview", "test")}
    fresh_scores: list[float] = []
    for m in methods:
        meth = (m.get("method") or "").lower()
        if meth in by_method:
            by_method[meth] += 1
        res = (m.get("result") or "").lower()
        if res == "pass":
            fresh_scores.append(1.0)
        elif res == "partial":
            fresh_scores.append(0.5)
        elif res == "fail":
            fresh_scores.append(0.0)

    method_cov = sum(1 for v in by_method.values() if v > 0) / 3.0
    evidence_score = _avg(
        [
            1.0 if by_method["examine"] else 0.0,
            1.0 if by_method["interview"] else 0.0,
            1.0 if by_method["test"] else 0.0,
        ]
    )

    # Objective freshness
    fresh_n = stale_n = expired_n = unknown_n = 0
    for o in objs:
        ass = o.get("assessment") or {}
        fs = (ass.get("freshness_status") or "unknown").lower()
        if fs == "fresh":
            fresh_n += 1
        elif fs == "stale":
            stale_n += 1
        elif fs == "expired":
            expired_n += 1
        else:
            unknown_n += 1
    freshness = (fresh_n + 0.4 * stale_n) / total_obj

    # Implementation from live SSP
    ssp = detail.get("live_ssp") or {}
    ev_st = (ssp.get("evidence_status") or "not_assessed").lower()
    live_st = (ssp.get("live_test") or {}).get("status") if isinstance(ssp.get("live_test"), dict) else ssp.get("live_status")
    impl = 0.0
    if live_st == "pass" or ev_st in {"implemented", "pass", "met"}:
        impl = 1.0
    elif live_st == "partial" or ev_st in {"partial"}:
        impl = 0.55
    elif detail.get("rollup_status") == "met":
        impl = 0.7
    elif detail.get("rollup_status") == "partial":
        impl = 0.4

    # Interview readiness + independent verification via human attestations
    interview_ready = 1.0 if by_method["interview"] else 0.0
    independent = 0.0
    try:
        row = get_conn().execute(
            """
            SELECT COUNT(*) AS n FROM human_attestations
            WHERE user_id = ? AND framework_id = ? AND control_id = ?
              AND decision IN ('approved', 'attested')
            """,
            (user_id, framework_id, control_id),
        ).fetchone()
        if row and int(row["n"] or 0) > 0:
            independent = 1.0
        elif any(m.get("reviewer") for m in methods):
            independent = 0.45
    except Exception:
        if any(m.get("reviewer") for m in methods):
            independent = 0.45

    signals = {
        "implementation": {"score": round(impl, 3), "band": _band(impl)},
        "evidence": {"score": round(evidence_score, 3), "band": _band(evidence_score)},
        "freshness": {"score": round(freshness, 3), "band": _band(freshness)},
        "assessment_coverage": {"score": round(assessment_cov, 3), "band": _band(assessment_cov)},
        "interview_readiness": {"score": round(interview_ready, 3), "band": _band(interview_ready)},
        "independent_verification": {"score": round(independent, 3), "band": _band(independent)},
        "method_coverage": {"score": round(method_cov, 3), "band": _band(method_cov)},
    }
    overall = _avg([s["score"] for s in signals.values()])
    overall_band = _band(overall)
    if overall_band == "HIGH" and signals["interview_readiness"]["band"] == "LOW":
        recommendation = "Needs human interview / review before assessment claim"
    elif overall_band == "HIGH":
        recommendation = "Ready for internal review"
    elif overall_band == "MEDIUM":
        recommendation = "Needs human review — close evidence/objective gaps"
    else:
        recommendation = "Not ready — collect Examine/Interview/Test evidence"

    return {
        "ok": True,
        "framework_id": framework_id,
        "control_id": control_id,
        "rollup_status": detail.get("rollup_status"),
        "signals": signals,
        "overall": {"score": round(overall, 3), "band": overall_band},
        "recommendation": recommendation,
        "method_counts": by_method,
        "freshness_counts": {
            "fresh": fresh_n,
            "stale": stale_n,
            "expired": expired_n,
            "unknown": unknown_n,
        },
        "computed_at": now(),
        "disclaimer": (
            "Readiness confidence is a SecuraIQ multi-signal heuristic. "
            "It is not a C3PAO finding, SPRS score, or certification claim."
        ),
    }


def framework_readiness_summary(
    user_id: str,
    framework_id: str = "cmmc_l2",
    *,
    sample_limit: int = 0,
) -> dict[str, Any]:
    """Org-level readiness rollup. sample_limit=0 means all controls."""
    seed_objectives_for_framework(framework_id)
    controls = list_framework_controls(framework_id)
    if sample_limit and sample_limit > 0:
        controls = controls[:sample_limit]

    bands = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
    needs_review = 0
    per_control: list[dict[str, Any]] = []
    for c in controls:
        conf = control_readiness_confidence(user_id, framework_id, c.id)
        band = conf["overall"]["band"]
        bands[band] = bands.get(band, 0) + 1
        if band != "HIGH" or "human" in (conf.get("recommendation") or "").lower():
            needs_review += 1
        per_control.append(
            {
                "control_id": c.id,
                "title": c.title,
                "rollup_status": conf.get("rollup_status"),
                "overall_band": band,
                "overall_score": conf["overall"]["score"],
                "recommendation": conf.get("recommendation"),
            }
        )

    return {
        "ok": True,
        "framework_id": framework_id,
        "controls_scored": len(per_control),
        "bands": bands,
        "needs_review": needs_review,
        "controls": per_control,
        "computed_at": now(),
        "disclaimer": (
            "Framework readiness summary aggregates per-control heuristics. "
            "Not SPRS submission or certification."
        ),
    }
