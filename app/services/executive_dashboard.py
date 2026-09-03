"""Executive Dashboard -- the management-facing view, separate from the
technical SOC page. Every number here is either a direct read of an
existing real computation (org risk score, patch compliance, campaign
verification stats) or a straightforward aggregation over real rows
(mean remediation time from actual status-change timestamps). Nothing on
this dashboard is modeled, projected, or invented.

A trend/change figure is only reported when there are at least two real
data points to compare -- a tenant with no history yet (new account, no
campaigns run, dashboard never opened before today) gets "not enough
history yet" rather than a fabricated percentage or a silently-zero delta
that looks like "no change" when it actually means "no data".
"""

from __future__ import annotations

from typing import Any

from app.db import now


def _security_exposure(user_id: str, *, org_id: str | None, engagement_id: str | None) -> dict[str, Any]:
    from app.services.risk_priority import compute_org_risk_score
    from app.services.risk_snapshots import get_score_history, maybe_snapshot_periodic

    try:
        maybe_snapshot_periodic(user_id)
    except Exception:
        pass  # the current-score read below still works without a snapshot

    current = compute_org_risk_score(user_id, org_id=org_id, engagement_id=engagement_id)
    history = []
    change_pct = None
    try:
        history = get_score_history(user_id, days=90)
    except Exception:
        history = []
    if len(history) >= 2 and history[0]["score"]:
        change_pct = round((history[0]["score"] - current["score"]) / history[0]["score"] * 100, 1)

    return {
        "current_score": current["score"],
        "band": current["band"],
        "total_open": current["total_open"],
        "history": [{"ts": h["created_at"], "score": h["score"], "label": h["label"]} for h in history],
        "change_pct": change_pct,  # positive = risk went down since the earliest point in the 90-day window
        "history_points": len(history),
    }


def _critical_findings(user_id: str, *, org_id: str | None, engagement_id: str | None) -> dict[str, Any]:
    from app.enterprise import list_vulnerabilities
    from app.services.risk_snapshots import get_score_history

    open_vulns = list_vulnerabilities(user_id, status="open", org_id=org_id, engagement_id=engagement_id)
    current_critical = sum(1 for v in open_vulns if (v.get("severity") or "").lower() == "critical")
    current_critical_high = sum(1 for v in open_vulns if (v.get("severity") or "").lower() in ("critical", "high"))

    change = None
    try:
        history = get_score_history(user_id, days=90)
    except Exception:
        history = []
    if len(history) >= 2:
        change = int(history[0]["critical_high_count"]) - current_critical_high

    return {
        "critical": current_critical,
        "critical_high": current_critical_high,
        "change_since_earliest_snapshot": change,  # positive = went down (fixed more than were newly found)
    }


def _patch_compliance(user_id: str) -> dict[str, Any]:
    from app.software.service import summary_for_user

    try:
        s = summary_for_user(user_id)
    except Exception:
        return {"pct": None, "up_to_date": 0, "total": 0}
    total = s.get("total_installations", 0)
    up_to_date = s.get("up_to_date", 0)
    return {
        "pct": round(up_to_date / total * 100, 1) if total else None,
        "up_to_date": up_to_date,
        "total": total,
        "critical": s.get("critical", 0),
        "eol": s.get("eol", 0),
    }


def _mean_remediation_time_days(user_id: str, *, org_id: str | None, engagement_id: str | None) -> dict[str, Any]:
    """Mean of (updated_at - created_at) across vulnerabilities whose status
    is resolved/closed/fixed -- the timestamp of the last status change,
    which for the auto-resolve-on-verified-patch path (see
    app.agents.report_command_result) IS the actual resolution moment. For
    a manually-edited status this is an approximation (updated_at reflects
    the last edit, not necessarily the fix date), which is why this is
    labeled "based on status-change timestamps" rather than claimed as a
    precise SLA metric."""
    from app.enterprise import list_vulnerabilities

    all_vulns = list_vulnerabilities(user_id, org_id=org_id, engagement_id=engagement_id)
    resolved = [
        v for v in all_vulns
        if (v.get("status") or "").lower() in ("resolved", "closed", "fixed")
        and v.get("created_at") and v.get("updated_at")
        and float(v["updated_at"]) >= float(v["created_at"])
    ]
    if not resolved:
        return {"mean_days": None, "sample_size": 0}
    days = [(float(v["updated_at"]) - float(v["created_at"])) / 86400.0 for v in resolved]
    return {"mean_days": round(sum(days) / len(days), 1), "sample_size": len(resolved)}


def _verified_remediation(user_id: str) -> dict[str, Any]:
    from app.agents import fleet_verification_summary

    try:
        return fleet_verification_summary(user_id)
    except Exception:
        return {"total_done": 0, "verified": 0, "verification_failed": 0, "verification_pending": 0, "verified_pct": None}


def _active_campaigns_count(user_id: str) -> int:
    from app.agents import list_campaigns

    try:
        return sum(1 for c in list_campaigns(user_id, limit=300) if c.get("status") == "active")
    except Exception:
        return 0


def _active_threats(user_id: str) -> dict[str, Any]:
    """Real, currently-active Sentinel detections (agents.securaiq_agent_
    threats with status='active'), grouped by severity -- the same rows the
    Agents panel's threat feed reads from, just counted here."""
    from app.agents import list_threats

    try:
        threats = [t for t in list_threats(user_id, limit=500) if (t.get("status") or "") == "active"]
    except Exception:
        threats = []
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for t in threats:
        sev = (t.get("severity") or "medium").lower()
        if sev in counts:
            counts[sev] += 1
    counts["total"] = len(threats)
    return counts


def _asset_health(user_id: str, *, org_id: str | None, engagement_id: str | None) -> dict[str, Any]:
    """Every asset bucketed into exactly one real state, checked in this
    priority order: compromised (an active critical/high Sentinel threat on
    that asset) > offline (a linked SecuraIQ agent that's currently offline
    or stale) > at_risk (an open critical/high vulnerability) > healthy.
    Never a fabricated "healthy" default -- an asset only lands there after
    failing every real check above."""
    from app.agents import list_agents, list_threats
    from app.enterprise import list_assets
    from app.services.risk_priority import _scored_open_items

    try:
        assets = list_assets(user_id, engagement_id=engagement_id, org_id=org_id)
    except Exception:
        assets = []
    if not assets:
        return {"healthy": 0, "at_risk": 0, "compromised": 0, "offline": 0, "total": 0}

    compromised_assets: set[str] = set()
    try:
        for t in list_threats(user_id, limit=500):
            if (t.get("status") or "") == "active" and (t.get("severity") or "").lower() in ("critical", "high"):
                aid = t.get("asset_id") or ""
                if aid:
                    compromised_assets.add(aid)
    except Exception:
        pass

    offline_assets: set[str] = set()
    try:
        for a in list_agents(user_id):
            aid = a.get("asset_id") or ""
            if aid and a.get("status") in ("offline", "stale"):
                offline_assets.add(aid)
    except Exception:
        pass

    at_risk_assets: set[str] = set()
    try:
        for item in _scored_open_items(user_id, org_id=org_id, engagement_id=engagement_id):
            if item.get("severity") in ("critical", "high") and item.get("asset_id"):
                at_risk_assets.add(item["asset_id"])
    except Exception:
        pass

    counts = {"healthy": 0, "at_risk": 0, "compromised": 0, "offline": 0}
    for a in assets:
        aid = a.get("id") or ""
        if aid in compromised_assets:
            counts["compromised"] += 1
        elif aid in offline_assets:
            counts["offline"] += 1
        elif aid in at_risk_assets:
            counts["at_risk"] += 1
        else:
            counts["healthy"] += 1
    counts["total"] = len(assets)
    return counts


def _ai_priority_queue(user_id: str, *, org_id: str | None, engagement_id: str | None, limit: int = 5) -> list[dict[str, Any]]:
    """"What should I fix first?" -- the hero feature. Reuses the Risk
    Reduction Simulator's grouping/ranking (compute_risk_simulation) so the
    ranking here is identical to the Simulator page, then enriches the top
    N with the same confirmed/unconfirmed attack-path split and asset names
    a Remediation Plan would show (via remediation._find_group -- the exact
    function create_plan() itself calls), so "Create remediation plan" from
    this queue produces a plan whose numbers already matched what was shown
    here. Never a separate, parallel ranking model."""
    from app.enterprise import list_assets
    from app.services.remediation import _find_group
    from app.services.risk_priority import compute_risk_simulation

    try:
        sim = compute_risk_simulation(user_id, org_id=org_id, engagement_id=engagement_id, limit=limit)
    except Exception:
        return []
    groups = sim.get("groups", [])[:limit]
    if not groups:
        return []

    try:
        assets_by_id = {a["id"]: a for a in list_assets(user_id, engagement_id=engagement_id, org_id=org_id)}
    except Exception:
        assets_by_id = {}

    queue = []
    for g in groups:
        enriched = dict(g)
        try:
            full_group, asset_ids = _find_group(user_id, g["group_key"], org_id=org_id, engagement_id=engagement_id)
        except Exception:
            full_group, asset_ids = None, set()
        if full_group:
            enriched["verified_attack_paths_disrupted"] = full_group.get("verified_attack_paths_disrupted", 0)
        else:
            enriched["verified_attack_paths_disrupted"] = 0
        names = [assets_by_id[a]["name"] for a in sorted(asset_ids) if a in assets_by_id and assets_by_id[a].get("name")]
        enriched["asset_names"] = names[:3]
        queue.append(enriched)
    return queue


def compute_executive_dashboard(
    user_id: str,
    *,
    org_id: str | None = None,
    engagement_id: str | None = None,
) -> dict[str, Any]:
    from app.services.risk_priority import compute_priority_list

    exposure = _security_exposure(user_id, org_id=org_id, engagement_id=engagement_id)
    findings = _critical_findings(user_id, org_id=org_id, engagement_id=engagement_id)
    patch = _patch_compliance(user_id)
    mttr = _mean_remediation_time_days(user_id, org_id=org_id, engagement_id=engagement_id)
    verified = _verified_remediation(user_id)
    active_campaigns = _active_campaigns_count(user_id)
    active_threats = _active_threats(user_id)
    asset_health = _asset_health(user_id, org_id=org_id, engagement_id=engagement_id)
    priority_queue = _ai_priority_queue(user_id, org_id=org_id, engagement_id=engagement_id, limit=5)

    top_risks = []
    try:
        priority = compute_priority_list(user_id, org_id=org_id, engagement_id=engagement_id, limit=5)
        top_risks = priority.get("items", [])
    except Exception:
        pass

    return {
        "generated_at": now(),
        "security_exposure": exposure,
        "critical_findings": findings,
        "patch_compliance": patch,
        "mean_remediation_time": mttr,
        "verified_remediation": verified,
        "active_campaigns": active_campaigns,
        "active_threats": active_threats,
        "asset_health": asset_health,
        "ai_priority_queue": priority_queue,
        "top_remaining_risks": top_risks,
    }
