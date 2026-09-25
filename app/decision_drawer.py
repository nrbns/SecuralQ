"""Reusable Decision Drawer payload — WHAT/WHY/EVIDENCE/IMPACT/ACTION/VERIFY."""

from __future__ import annotations

from typing import Any


def build_decision_drawer(
    user_id: str,
    *,
    kind: str = "risk",
    target_id: str = "",
) -> dict[str, Any]:
    kind_l = (kind or "risk").strip().lower()
    if kind_l in {"asset", "identity"} and target_id:
        from app.asset_identity_card import asset_identity_card

        card = asset_identity_card(user_id, target_id) or {}
        exp = card.get("exposure") or {}
        return {
            "ok": True,
            "kind": "asset",
            "title": f"Why is {card.get('name') or target_id} a priority?",
            "what": f"{card.get('name')} · scope {exp.get('scope')} · {exp.get('open_findings') or 0} open findings",
            "why": (
                f"Critical CVEs {exp.get('critical_cves')}, failed controls "
                f"{exp.get('failed_controls')}, internet-facing={exp.get('internet_facing')}"
            ),
            "evidence": "Agent/scanner observations on this canonical asset (aliases listed on the identity card).",
            "impact": f"Business service: {card.get('business_service') or 'unmapped'}. Risk band {card.get('risk_band')}.",
            "action": "Fix highest risk, or request an allowlisted remediation.",
            "verify": "Independent next check-in / scan — execute is not verified.",
            "expected": "Risk and live compliance recalculate after verify.",
            "simulate": True,
            "request_approval": True,
            "card": card,
        }
    if kind_l in {"vuln", "finding", "cve"} and target_id:
        from app.services.risk_narrative import explain_finding

        return explain_finding(user_id, target_id)
    if kind_l in {"compliance", "control", "live"}:
        from app.controls.live_compliance import explain_live_compliance

        live = explain_live_compliance(user_id)
        return {
            "ok": True,
            "kind": "compliance",
            "title": "Why is live compliance at this level?",
            "what": f"Live controls {live.get('live_percent')}% of decisive PASS/FAIL",
            "why": live.get("why") or live.get("narrative"),
            "evidence": live.get("evidence") or "Last-result rows only — not a certification score.",
            "impact": f"Passing {live.get('passing')} · failing {live.get('failing')} · stale/unknown {live.get('unknown')}",
            "action": "Restore failed host controls, then wait for independent verify.",
            "verify": "Next agent check-in or scheduled control re-test.",
            "expected": "live_percent moves only after PASS/FAIL last-results change.",
            "simulate": False,
            "request_approval": True,
            "live_compliance": live,
        }
    from app.controls.live_compliance import compute_live_compliance
    from app.services.risk_narrative import explain_risk_increase
    from app.services.risk_priority import compute_org_risk_score

    risk = compute_org_risk_score(user_id)
    why = explain_risk_increase(user_id)
    live = compute_live_compliance(user_id)
    return {
        "ok": True,
        "kind": "risk",
        "title": "Why is risk at this level?",
        "what": f"Org risk {risk.get('score')} ({risk.get('band')})",
        "why": why.get("narrative") or why.get("direction") or "Factor contributions from open findings and host controls.",
        "evidence": why.get("note") or "Risk narrative uses stored findings — not invented scores.",
        "impact": f"Live controls {live.get('live_percent')}% of decisive PASS/FAIL (not certification).",
        "action": "Open the top decision on Command Center and request approval.",
        "verify": "Verified remediations only reduce the score.",
        "expected": why.get("direction") or "",
        "contributions": why.get("drivers") or [],
        "simulate": True,
        "request_approval": True,
        "org_risk": risk,
        "live_compliance": {
            "percent": live.get("live_percent"),
            "passing": live.get("passing"),
            "failing": live.get("failing"),
        },
    }
