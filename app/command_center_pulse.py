"""Command Center pulse — what changed + top decisions (lab)."""

from __future__ import annotations

from typing import Any


def command_center_pulse(user_id: str) -> dict[str, Any]:
    from app.controls.live_compliance import explain_live_compliance
    from app.host_change import list_host_changes
    from app.services.risk_narrative import explain_risk_increase
    from app.services.risk_priority import compute_org_risk_score, compute_priority_list

    from app.control_truth import truth_indicators
    from app.nist_profile import organizational_profile

    changes = list_host_changes(user_id, limit=8)
    why = explain_risk_increase(user_id, limit_findings=5)
    live = explain_live_compliance(user_id)
    truth = truth_indicators(user_id, live=live)
    profile = organizational_profile(user_id)
    risk = compute_org_risk_score(user_id)
    priority = compute_priority_list(user_id, limit=5)
    items = priority.get("items") or priority.get("findings") or []
    if isinstance(priority, list):
        items = priority
    decisions = []
    for it in (items or [])[:5]:
        if not isinstance(it, dict):
            continue
        decisions.append(
            {
                "kind": "finding",
                "target_id": it.get("id") or it.get("finding_id") or it.get("vuln_id"),
                "title": it.get("title") or it.get("cve") or "Open finding",
                "score": it.get("score") or it.get("risk_score"),
                "asset": it.get("asset_name") or it.get("asset"),
            }
        )
    try:
        from app.metrics import stage_latency_snapshot

        stages = stage_latency_snapshot()
    except Exception:
        stages = {}
    if not decisions and why.get("drivers"):
        for d in (why.get("drivers") or [])[:5]:
            decisions.append(
                {
                    "kind": "finding",
                    "target_id": d.get("id"),
                    "title": d.get("title") or "Risk driver",
                    "score": d.get("score"),
                    "asset": d.get("asset"),
                }
            )
    return {
        "ok": True,
        "org_risk": risk,
        "live_compliance": {
            "percent": live.get("live_percent"),
            "passing": live.get("passing"),
            "failing": live.get("failing"),
            "unknown": live.get("unknown"),
            "why": live.get("why"),
        },
        "what_changed": {
            "count": changes.get("count") or 0,
            "changes": changes.get("changes") or [],
            "disclaimer": changes.get("disclaimer"),
        },
        "truth": truth,
        "profile": profile,
        "top_decisions": decisions,
        "risk_why": {
            "direction": why.get("direction"),
            "narrative": why.get("narrative"),
            "drivers": why.get("drivers") or [],
        },
        "stage_latency": stages,
        "modes": ["exec", "soc", "compliance", "it", "auditor"],
        "note": "Pulse is last-known agent/finding state. Deep scanners are not this feed.",
    }
