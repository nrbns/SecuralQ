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

from app.cmmc_scoping import FULL_ASSESSMENT_CATEGORIES, cmmc_scope_label, normalize_cmmc_scope
from app.db import get_conn, now
from app.enterprise import list_assets, list_vulnerabilities
from app.services.risk import compute_risk_score

# CMMC "full assessment" assets (cui_asset / spa -- see app.cmmc_scoping) sit
# inside the CUI boundary by the framework's own definition, so a finding on
# one of them is a finding against a critical business function even when
# nobody has separately tagged that asset's business_criticality field. This
# is a *floor*, not an override: it only raises business_criticality up to
# "high" when the user hasn't already recorded something at least that high,
# and it never touches asset_criticality or invents a new score weight --
# compute_risk_score's existing, documented business_criticality input
# already means exactly this ("how critical is the business function/data it
# serves"). cmmc_asset_category is always a user-entered, self-reported
# classification (see app.cmmc_scoping module docstring) -- this floor is
# honest about that: it never claims CUI presence was verified, only that
# *if* the user classified this asset as in-scope, the score should reflect
# it instead of silently defaulting to "medium".
_CMMC_BUSINESS_CRITICALITY_FLOOR = "high"
_CRITICALITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def _cmmc_scope_for_asset(asset: dict[str, Any] | None) -> str:
    return normalize_cmmc_scope((asset or {}).get("cmmc_asset_category"))


def _floor_business_criticality(business_criticality: str, cmmc_scope: str) -> tuple[str, bool]:
    """Returns (effective_business_criticality, floor_applied)."""
    if cmmc_scope not in FULL_ASSESSMENT_CATEGORIES:
        return business_criticality, False
    current_rank = _CRITICALITY_RANK.get(business_criticality, 2)
    floor_rank = _CRITICALITY_RANK[_CMMC_BUSINESS_CRITICALITY_FLOOR]
    if current_rank >= floor_rank:
        return business_criticality, False
    return _CMMC_BUSINESS_CRITICALITY_FLOOR, True


def _exposure_for_asset(asset: dict[str, Any] | None) -> float:
    from app.asset_categories import is_internet_exposed_category

    return 0.8 if is_internet_exposed_category((asset or {}).get("asset_type")) else 0.5


def _kev_cves() -> set[str]:
    try:
        from app.software.advisories import load_kev_catalog

        cves, _items = load_kev_catalog()
        return cves
    except Exception:
        return set()


def _agent_monitored_asset_ids(user_id: str) -> set[str]:
    """Asset IDs with an actively checked-in SecuraIQ agent right now — a
    real, existing signal (not fabricated) that stands in for "compensating
    controls": continuous telemetry/monitoring genuinely reduces effective
    risk (faster detection, shorter dwell time) even though it doesn't
    patch anything. An offline or never-enrolled agent contributes nothing —
    only currently-online coverage counts, so this can't go stale silently."""
    try:
        from app.agents import list_agents

        return {a["asset_id"] for a in list_agents(user_id) if a.get("status") == "online" and a.get("asset_id")}
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
    monitored_asset_ids = _agent_monitored_asset_ids(user_id)

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
        business_criticality = ((asset or {}).get("business_criticality") or "").strip().lower()
        cmmc_scope = _cmmc_scope_for_asset(asset)
        # Same effective label compute_risk_score would fall back to on its
        # own (business_criticality if set, else asset_criticality) -- the
        # floor only changes anything when that effective label is below
        # "high" and the asset is CMMC in-scope.
        effective_business_criticality, cmmc_floor_applied = _floor_business_criticality(
            (business_criticality or str(asset_criticality).lower()), cmmc_scope
        )
        threat_intel = 0.9 if is_kev else 0.3
        age_days = max(0.0, (now() - float(v.get("created_at") or now())) / 86400.0)
        # long-open findings nudge confidence up slightly — they've survived
        # re-scans, so they're not a transient/false-positive blip.
        confidence = 0.85 if age_days > 14 else 0.7
        # a currently-online SecuraIQ agent is a real, existing compensating
        # control signal (continuous monitoring/telemetry) — see
        # _agent_monitored_asset_ids(). 0.5, not 1.0: monitoring detects
        # faster, it doesn't remediate, so it's a partial mitigation only.
        is_monitored = bool(v.get("asset_id")) and v.get("asset_id") in monitored_asset_ids
        compensating_controls = 0.5 if is_monitored else 0.0

        result = compute_risk_score(
            cvss=v.get("cvss"),
            exploitability=exploitability,
            exposure=exposure,
            asset_criticality=asset_criticality,
            threat_intel=threat_intel,
            confidence=confidence,
            compensating_controls=compensating_controls,
            business_criticality=effective_business_criticality,
        )
        reasons: list[str] = []
        if is_kev:
            reasons.append("Actively exploited (CISA KEV)")
        if exposure >= 0.8:
            reasons.append("Internet-facing asset")
        if asset_criticality in ("critical", "high"):
            reasons.append(f"{asset_criticality.title()}-criticality asset")
        if business_criticality in ("critical", "high") and business_criticality != asset_criticality:
            reasons.append(f"{business_criticality.title()}-criticality business function")
        if cmmc_floor_applied:
            reasons.append(f"Asset self-classified as {cmmc_scope_label(cmmc_scope)} (CMMC scope)")
        if has_patch:
            reasons.append("Patch already available — quick win")
        if age_days > 30:
            reasons.append(f"Open {int(age_days)} days")
        if not reasons:
            reasons.append(f"{severity.title()} severity finding")
        if is_monitored:
            reasons.append("Partially offset by active agent monitoring")

        scored.append(
            {
                "vuln_id": v.get("id"),
                "cve": v.get("cve") or "",
                "title": v.get("title") or "",
                "severity": severity,
                "asset_id": v.get("asset_id") or "",
                "asset_name": v.get("asset_name") or (asset or {}).get("name") or "",
                "asset_criticality": asset_criticality,
                "business_criticality": effective_business_criticality,
                "cmmc_scope": cmmc_scope,
                "cmmc_scope_label": cmmc_scope_label(cmmc_scope) if cmmc_scope else "",
                "cmmc_floor_applied": cmmc_floor_applied,
                "exposure": exposure,
                "compensating_controls": compensating_controls,
                "monitored": is_monitored,
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

    Each group also carries attack_paths_disrupted / business_critical_
    paths_disrupted from app.services.attack_graph — how many currently
    computed Internet -> ... -> asset routes include a vulnerability from
    this group, and how many of those reach a business-critical target.
    This is a real recomputation over the attack graph (declared + inferred
    connects_to edges), not an invented count; if the graph build fails for
    any reason this degrades to 0 rather than breaking the simulator.
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
            "total_attack_paths": 0,
            "business_critical_attack_paths": 0,
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

    total_attack_paths = 0
    business_critical_attack_paths = 0
    for g in top:
        g["attack_paths_disrupted"] = 0
        g["business_critical_paths_disrupted"] = 0
    try:
        from app.services.attack_graph import compute_attack_paths

        ap_result = compute_attack_paths(user_id, org_id=org_id, engagement_id=engagement_id, max_depth=6, limit=1000)
        total_attack_paths = ap_result["total_paths"]
        keys_needing_counts = {g["group_key"] for g in top} | {g["group_key"] for g in group_results[:3]}
        group_vuln_ids = {key: {i["vuln_id"] for i in groups[key]} for key in keys_needing_counts}
        counts = {key: {"attack_paths_disrupted": 0, "business_critical_paths_disrupted": 0} for key in keys_needing_counts}
        for path in ap_result["paths"]:
            path_vuln_ids = {v.get("vuln_id") for v in path.get("vulnerabilities", []) if v.get("vuln_id")}
            if not path_vuln_ids:
                continue
            target = path.get("target_asset") or {}
            is_business_critical = str(target.get("business_criticality") or target.get("criticality") or "medium").lower() in ("critical", "high")
            if is_business_critical:
                business_critical_attack_paths += 1
            for key, ids in group_vuln_ids.items():
                if path_vuln_ids & ids:
                    counts[key]["attack_paths_disrupted"] += 1
                    if is_business_critical:
                        counts[key]["business_critical_paths_disrupted"] += 1
        for g in top:
            g.update(counts.get(g["group_key"], {"attack_paths_disrupted": 0, "business_critical_paths_disrupted": 0}))
    except Exception:
        pass  # the attack graph is a real enhancement, but must never break the simulator

    return {
        "generated_at": now(),
        "baseline_score": baseline_score,
        "baseline_band": _band_for(baseline_score),
        "total_open": len(scored),
        "groups": top,
        "top3_combined_reduction_pct": max(0.0, top3_combined_reduction),
        "top3_group_titles": [g["title"] for g in group_results[:3]],
        "total_attack_paths": total_attack_paths,
        "business_critical_attack_paths": business_critical_attack_paths,
    }
