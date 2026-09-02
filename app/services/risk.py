"""Risk register domain service + deterministic risk scoring."""

from __future__ import annotations

from typing import Any

from app.enterprise import (
    create_risk,
    delete_risk,
    get_risk,
    list_risks,
    update_risk,
)

__all__ = [
    "create_risk",
    "delete_risk",
    "get_risk",
    "list_risks",
    "update_risk",
    "compute_risk_score",
    "explain_risk_score",
]

_CRITICALITY = {"critical": 1.0, "high": 0.85, "medium": 0.65, "low": 0.4, "info": 0.2}


def compute_risk_score(
    *,
    cvss: float | None = None,
    exploitability: float | None = None,
    exposure: float | None = None,
    asset_criticality: str | None = None,
    threat_intel: float | None = None,
    confidence: float | None = None,
    compensating_controls: float | None = None,
    business_criticality: str | None = None,
) -> dict[str, Any]:
    """Deterministic 0–100 risk score. AI should explain this, not invent it.

    Inputs are normalized to 0–1 (CVSS /10). Missing factors use neutral defaults
    so scores stay reproducible across runs.

    compensating_controls is 0 (none known) to 1 (fully mitigated) — e.g. an
    actively monitored asset (an online EDR/agent) is a real, if partial,
    compensating control that lowers effective risk even though the raw
    vulnerability is unchanged. Unset defaults to 0 (assume no mitigation —
    the conservative default; never assume protection that isn't confirmed).

    business_criticality is the same {critical,high,medium,low,info} scale as
    asset_criticality, but answers a different question: asset_criticality is
    "how critical is this piece of infrastructure", business_criticality is
    "how critical is the business function/data it serves" — a forgotten
    low-spec box holding the customer database is the canonical case where
    these diverge. Left unset, it falls back to asset_criticality's value
    rather than fabricating a distinct number the caller never provided.
    """
    cvss_n = max(0.0, min(1.0, (float(cvss) if cvss is not None else 5.0) / 10.0))
    exploit_n = max(0.0, min(1.0, float(exploitability) if exploitability is not None else 0.5))
    exposure_n = max(0.0, min(1.0, float(exposure) if exposure is not None else 0.5))
    crit_n = _CRITICALITY.get((asset_criticality or "medium").lower(), 0.65)
    intel_n = max(0.0, min(1.0, float(threat_intel) if threat_intel is not None else 0.4))
    conf_n = max(0.0, min(1.0, float(confidence) if confidence is not None else 0.7))
    controls_n = max(0.0, min(1.0, float(compensating_controls) if compensating_controls is not None else 0.0))
    biz_crit_n = _CRITICALITY.get(business_criticality.lower(), crit_n) if business_criticality else crit_n

    # Weighted blend — documented weights for auditability. Sums to 1.0.
    # compensating_controls is inverted (1 - controls_n): more mitigation
    # in place contributes LESS to the score, rather than more.
    weights = {
        "cvss": 0.30,
        "exploitability": 0.18,
        "exposure": 0.13,
        "asset_criticality": 0.12,
        "threat_intel": 0.10,
        "confidence": 0.05,
        "compensating_controls": 0.07,
        "business_criticality": 0.05,
    }
    raw = (
        weights["cvss"] * cvss_n
        + weights["exploitability"] * exploit_n
        + weights["exposure"] * exposure_n
        + weights["asset_criticality"] * crit_n
        + weights["threat_intel"] * intel_n
        + weights["confidence"] * conf_n
        + weights["compensating_controls"] * (1.0 - controls_n)
        + weights["business_criticality"] * biz_crit_n
    )
    score = round(raw * 100, 1)
    factors = {
        "cvss": round(cvss_n, 3),
        "exploitability": round(exploit_n, 3),
        "exposure": round(exposure_n, 3),
        "asset_criticality": round(crit_n, 3),
        "threat_intel": round(intel_n, 3),
        "confidence": round(conf_n, 3),
        "compensating_controls": round(controls_n, 3),
        "business_criticality": round(biz_crit_n, 3),
    }
    return {
        "score": score,
        "band": _band(score),
        "weights": weights,
        "factors": factors,
        "formula": (
            "weighted_sum(cvss,exploitability,exposure,criticality,intel,"
            "confidence,(1-compensating_controls),business_criticality)*100"
        ),
    }


def explain_risk_score(result: dict[str, Any]) -> str:
    """Human-readable explanation of a compute_risk_score() result."""
    factors = result.get("factors") or {}
    weights = result.get("weights") or {}
    parts = [
        f"{name}={factors.get(name)}×{weights.get(name)}"
        for name in (
            "cvss",
            "exploitability",
            "exposure",
            "asset_criticality",
            "threat_intel",
            "confidence",
            "compensating_controls",
            "business_criticality",
        )
        if name in factors
    ]
    return (
        f"Risk score {result.get('score')} ({result.get('band')}): "
        + " + ".join(parts)
        + f". Formula: {result.get('formula')}."
    )


def _band(score: float) -> str:
    if score >= 85:
        return "critical"
    if score >= 70:
        return "high"
    if score >= 45:
        return "medium"
    if score >= 25:
        return "low"
    return "info"
