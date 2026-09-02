"""Risk prioritization engine — "what to fix first".

A scoped-down security graph: rather than standing up a separate graph
database, this ranks the user's existing open findings by joining data
that's already there — asset criticality (`assets.criticality`), exposure
inferred from asset type, exploitability boosted by CISA KEV membership,
and whether a patch is already available in the software inventory — into
the one deterministic scoring function the product already uses
(`app.services.risk.compute_risk_score`). Nothing here invents a score;
it reuses the same weighted formula the AI risk-score endpoint uses, so a
"top N to fix" list is explainable the same way a single risk score is.

"Quick win" flags a finding where a fix already exists (patch_status has a
target_version) — those are cheap wins worth doing first even if the raw
score of a same-severity un-patchable finding is close, since remediation
cost (not just risk) is part of "what to fix first" in practice.
"""

from __future__ import annotations

from typing import Any

from app.db import get_conn, now
from app.enterprise import list_assets, list_vulnerabilities
from app.services.risk import compute_risk_score

# asset_type values treated as internet-facing for exposure inference —
# matches the same heuristic already used by app.services.investigation's
# investigate_top_assets(), so a finding's exposure reads the same way
# whether it surfaces there or here.
_PUBLIC_ASSET_TYPES = {"domain", "url", "api", "public"}


def _exposure_for_asset(asset: dict[str, Any] | None) -> float:
    asset_type = ((asset or {}).get("asset_type") or "").lower()
    return 0.8 if asset_type in _PUBLIC_ASSET_TYPES else 0.5


def _kev_cves() -> set[str]:
    try:
        from app.software.advisories import load_kev_catalog

        cves, _items = load_kev_catalog()
        return cves
    except Exception:
        return set()


def _patchable_cves(user_id: str) -> set[str]:
    """CVEs for which the software-inventory pipeline already has a target
    fix version recorded somewhere in this user's installations — a cheap,
    honest "a fix exists" signal without requiring a new join table."""
    try:
        c = get_conn()
        rows = c.execute(
            """
            SELECT i.cve AS cve, ps.target_version AS target_version
            FROM patch_status ps
            JOIN software_installations i ON i.id = ps.software_installation_id AND i.user_id = ps.user_id
            WHERE ps.user_id = ? AND ps.target_version != ''
            """,
            (user_id,),
        ).fetchall()
    except Exception:
        return set()
    out: set[str] = set()
    for r in rows:
        d = dict(r)
        for token in str(d.get("cve") or "").replace(";", ",").split(","):
            token = token.strip().upper()
            if token.startswith("CVE-"):
                out.add(token)
    return out


_SEVERITY_EXPLOITABILITY = {"critical": 0.65, "high": 0.55, "medium": 0.35, "low": 0.2, "info": 0.1}


def compute_priority_list(
    user_id: str,
    *,
    org_id: str | None = None,
    engagement_id: str | None = None,
    limit: int = 25,
) -> dict[str, Any]:
    """Rank this user's open findings by deterministic risk score, richest
    signal first. Returns {generated_at, total_open, items: [...]}, each
    item carrying the same score/band/factors shape compute_risk_score()
    already produces elsewhere, plus why-flags (kev, quick_win, internet
    facing, critical asset) that explain the ranking without re-deriving
    it — consistent with the product's "AI should explain this, not invent
    it" rule for risk scores."""
    vulns = [v for v in list_vulnerabilities(user_id, status="open", org_id=org_id, engagement_id=engagement_id) if v]
    if not vulns:
        return {"generated_at": now(), "total_open": 0, "items": []}

    assets = list_assets(user_id, engagement_id, org_id=org_id)
    assets_by_id = {a.get("id"): a for a in assets if a.get("id")}
    kev_cves = _kev_cves()
    patchable = _patchable_cves(user_id)

    scored: list[dict[str, Any]] = []
    for v in vulns:
        asset = assets_by_id.get(v.get("asset_id") or "")
        severity = (v.get("severity") or "medium").lower()
        cve = (v.get("cve") or "").strip().upper()
        is_kev = bool(cve) and cve in kev_cves
        has_patch = bool(cve) and cve in patchable
        exploitability = 0.95 if is_kev else _SEVERITY_EXPLOITABILITY.get(severity, 0.35)
        exposure = _exposure_for_asset(asset)
        asset_criticality = (asset or {}).get("criticality") or "medium"
        threat_intel = 0.9 if is_kev else 0.3
        age_days = max(0.0, (now() - float(v.get("created_at") or now())) / 86400.0)
        # long-open findings nudge confidence up slightly — they've survived
        # re-scans, so they're not a transient/false-positive blip.
        confidence = 0.85 if age_days > 14 else 0.7

        result = compute_risk_score(
            cvss=v.get("cvss"),
            exploitability=exploitability,
            exposure=exposure,
            asset_criticality=asset_criticality,
            threat_intel=threat_intel,
            confidence=confidence,
        )
        reasons: list[str] = []
        if is_kev:
            reasons.append("Actively exploited (CISA KEV)")
        if exposure >= 0.8:
            reasons.append("Internet-facing asset")
        if asset_criticality in ("critical", "high"):
            reasons.append(f"{asset_criticality.title()}-criticality asset")
        if has_patch:
            reasons.append("Patch already available — quick win")
        if age_days > 30:
            reasons.append(f"Open {int(age_days)} days")
        if not reasons:
            reasons.append(f"{severity.title()} severity finding")

        scored.append(
            {
                "vuln_id": v.get("id"),
                "cve": v.get("cve") or "",
                "title": v.get("title") or "",
                "severity": severity,
                "asset_id": v.get("asset_id") or "",
                "asset_name": v.get("asset_name") or (asset or {}).get("name") or "",
                "asset_criticality": asset_criticality,
                "score": result["score"],
                "band": result["band"],
                "factors": result["factors"],
                "kev": is_kev,
                "quick_win": has_patch,
                "age_days": round(age_days, 1),
                "reasons": reasons,
            }
        )

    # Quick wins (patch ready) sort ahead of a same-band item without one —
    # remediation cost matters for "what to fix FIRST", not just raw risk.
    scored.sort(key=lambda item: (item["score"] + (5 if item["quick_win"] else 0)), reverse=True)
    top = scored[: max(1, min(limit, 200))]
    return {
        "generated_at": now(),
        "total_open": len(vulns),
        "kev_count": sum(1 for i in scored if i["kev"]),
        "quick_win_count": sum(1 for i in scored if i["quick_win"]),
        "items": top,
    }
