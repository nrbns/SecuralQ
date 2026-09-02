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


def _scored_open_items(
    user_id: str,
    *,
    org_id: str | None = None,
    engagement_id: str | None = None,
) -> list[dict[str, Any]]:
    """Score every open finding once — the shared computation behind the
    priority list, the organizational risk score, and the reduction
    simulator, so all three always agree with each other (same inputs,
    same weights, same numbers) instead of drifting apart via duplicated
    logic. Unsorted; callers rank/group/aggregate as needed."""
    vulns = [v for v in list_vulnerabilities(user_id, status="open", org_id=org_id, engagement_id=engagement_id) if v]
    if not vulns:
        return []

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
                "exposure": exposure,
                "score": result["score"],
                "band": result["band"],
                "factors": result["factors"],
                "kev": is_kev,
                "quick_win": has_patch,
                "age_days": round(age_days, 1),
                "reasons": reasons,
            }
        )
    return scored


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
    scored = _scored_open_items(user_id, org_id=org_id, engagement_id=engagement_id)
    if not scored:
        return {"generated_at": now(), "total_open": 0, "items": []}

    # Quick wins (patch ready) sort ahead of a same-band item without one —
    # remediation cost matters for "what to fix FIRST", not just raw risk.
    ranked = sorted(scored, key=lambda item: (item["score"] + (5 if item["quick_win"] else 0)), reverse=True)
    top = ranked[: max(1, min(limit, 200))]
    return {
        "generated_at": now(),
        "total_open": len(scored),
        "kev_count": sum(1 for i in scored if i["kev"]),
        "quick_win_count": sum(1 for i in scored if i["quick_win"]),
        "items": top,
    }


def _mean_score(items: list[dict[str, Any]]) -> float:
    if not items:
        return 0.0
    return round(sum(i["score"] for i in items) / len(items), 1)


def _band_for(score: float) -> str:
    from app.services.risk import _band

    return _band(score)


def compute_org_risk_score(
    user_id: str,
    *,
    org_id: str | None = None,
    engagement_id: str | None = None,
) -> dict[str, Any]:
    """A single organizational exposure number: the mean deterministic risk
    score across every open finding. Not a new metric — it's the same
    compute_risk_score() the product already shows per-finding, aggregated
    so there's one number a dashboard (or a before/after remediation delta)
    can show without inventing a second scoring model."""
    scored = _scored_open_items(user_id, org_id=org_id, engagement_id=engagement_id)
    score = _mean_score(scored)
    return {
        "score": score,
        "band": _band_for(score),
        "total_open": len(scored),
        "kev_count": sum(1 for i in scored if i["kev"]),
        "critical_high_count": sum(1 for i in scored if i["severity"] in ("critical", "high")),
    }


def _group_key(item: dict[str, Any]) -> str:
    """CVE is the precise grouping key when present (exact identifier); a
    normalized title is the honest fallback for scanner findings without
    one — no product/package field exists on the vulnerabilities table to
    group by instead (see app/services/risk_priority.py module docstring
    for what data is and isn't available)."""
    if item.get("cve"):
        return f"cve:{item['cve']}"
    title = (item.get("title") or "").strip().lower()
    return f"title:{title}" if title else f"vuln:{item.get('vuln_id')}"


def compute_risk_simulation(
    user_id: str,
    *,
    org_id: str | None = None,
    engagement_id: str | None = None,
    limit: int = 10,
) -> dict[str, Any]:
    """"If you fix these findings, here's the estimated impact" — groups
    open findings by CVE (or normalized title when no CVE is recorded),
    then estimates each group's risk-reduction contribution by recomputing
    the organizational score with that group's findings excluded and
    diffing against the real baseline. This is a real recomputation of the
    same deterministic formula, not a fabricated percentage — every number
    here is reproducible from compute_risk_score() on the current data.

    Deliberately does NOT report an "attack paths disrupted" metric: this
    product has no attack-path graph, and inventing one would violate the
    "AI should explain this, not invent it" rule that governs risk scoring
    here. Every field below is derived from real, already-computed data.
    """
    scored = _scored_open_items(user_id, org_id=org_id, engagement_id=engagement_id)
    baseline_score = _mean_score(scored)
    if not scored:
        return {
            "generated_at": now(),
            "baseline_score": 0.0,
            "baseline_band": _band_for(0.0),
            "total_open": 0,
            "groups": [],
            "top3_combined_reduction_pct": 0.0,
        }

    groups: dict[str, list[dict[str, Any]]] = {}
    for item in scored:
        groups.setdefault(_group_key(item), []).append(item)

    def _score_excluding(excluded_ids: set[str]) -> float:
        remaining = [i for i in scored if i["vuln_id"] not in excluded_ids]
        return _mean_score(remaining)

    group_results: list[dict[str, Any]] = []
    for key, items in groups.items():
        group_ids = {i["vuln_id"] for i in items}
        simulated_score = _score_excluding(group_ids)
        reduction_pct = round((baseline_score - simulated_score) / baseline_score * 100, 1) if baseline_score else 0.0
        assets_affected = sorted({i["asset_id"] for i in items if i["asset_id"]})
        internet_exposed = sorted({i["asset_id"] for i in items if i["asset_id"] and i.get("exposure", 0) >= 0.8})
        title = items[0].get("title") or items[0].get("cve") or "Untitled finding"
        group_results.append(
            {
                "group_key": key,
                "title": title,
                "cve": items[0].get("cve") or "",
                "vulns_removed": len(items),
                "assets_affected": len(assets_affected),
                "internet_exposed_assets": len(internet_exposed),
                "kev": any(i["kev"] for i in items),
                "critical_high_count": sum(1 for i in items if i["severity"] in ("critical", "high")),
                "quick_win": any(i["quick_win"] for i in items),
                "estimated_risk_reduction_pct": max(0.0, reduction_pct),
            }
        )

    group_results.sort(key=lambda g: g["estimated_risk_reduction_pct"], reverse=True)
    top = group_results[: max(1, min(limit, 50))]

    top3_ids: set[str] = set()
    for g in group_results[:3]:
        top3_ids |= {i["vuln_id"] for i in groups[g["group_key"]]}
    top3_score = _score_excluding(top3_ids) if top3_ids else baseline_score
    top3_combined_reduction = round((baseline_score - top3_score) / baseline_score * 100, 1) if baseline_score else 0.0

    return {
        "generated_at": now(),
        "baseline_score": baseline_score,
        "baseline_band": _band_for(baseline_score),
        "total_open": len(scored),
        "groups": top,
        "top3_combined_reduction_pct": max(0.0, top3_combined_reduction),
        "top3_group_titles": [g["title"] for g in group_results[:3]],
    }
