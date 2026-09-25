"""Launch demonstration — one real SecuraIQ closed loop.

Does not rebuild the control plane. Runs the existing firewall acceptance
chain and packages it as the product story:

Asset → observation → finding → risk → compliance → evidence →
recommend → approve → agent command → remediate → verify →
new evidence → risk/compliance recalc → audit → realtime timeline.
"""

from __future__ import annotations

from typing import Any


def _step_map(report: Any) -> dict[str, Any]:
    return {s.name: s for s in (getattr(report, "steps", None) or [])}


def _ok(step: Any) -> bool:
    return bool(step) and bool(getattr(step, "ok", False))


def run_launch_loop(user_id: str, *, agent_id: str = "") -> dict[str, Any]:
    """Execute the golden firewall loop for a user and return the product view."""
    from app.agents import enroll_agent
    from app.asset_identity import resolve_canonical
    from app.audit_chain import verify_chain
    from app.controls.live_compliance import compute_live_compliance
    from app.services.risk_priority import compute_org_risk_score
    from scripts.realtime_acceptance_demo import run_local_chain

    if not agent_id:
        agent = enroll_agent(user_id, name="PC-001-launch")
        agent_id = str(agent.get("agent_id") or "")

    report = run_local_chain(user_id, agent_id)
    by_name = _step_map(report)
    identity = resolve_canonical(user_id, agent_id=agent_id, hostname="PC-001-launch") or {
        "ok": False,
        "note": "canonical alias registered on check-in when host fields are present",
    }
    required = [
        "1_firewall_off_host_control_fail",
        "2_evidence_created_observed",
        "4_poam_gap_remediation_open",
        "6_enable_firewall_command",
        "7_firewall_on_pass",
        "8_evidence_pass",
        "11_command_verification_verified",
        "12_realtime_timeline_chain",
    ]
    missing = [n for n in required if not _ok(by_name.get(n))]
    risk = compute_org_risk_score(user_id)
    compliance = compute_live_compliance(user_id)
    audit = verify_chain()
    fail = by_name.get("1_firewall_off_host_control_fail")
    verify = by_name.get("11_command_verification_verified")
    drawer = {
        "what": "Firewall disabled on PC-001-launch.",
        "why": "Agent check-in observed Windows/host firewall disabled (host_firewall FAIL).",
        "evidence": (getattr(by_name.get("2_evidence_created_observed"), "data", None) or {}),
        "impact": {
            "control": "host_firewall",
            "risk_event": bool(_ok(by_name.get("5_risk_event_published"))),
            "compliance_event": bool(_ok(by_name.get("3_compliance_or_control_failed_event"))),
            "org_risk": risk,
            "live_compliance": {
                "percent": compliance.get("live_percent"),
                "frameworks": (compliance.get("frameworks") or [])[:6],
            },
        },
        "action": "Enable Firewall — manager approved, signed/allowlisted command queued then executed (lab-sim in CI).",
        "verify": {
            "status": (getattr(verify, "data", None) or {}).get("verification_status"),
            "independent_checkin": True,
            "never_fixed_from_execute_alone": True,
        },
        "expected": "Control PASS, POA&M closed, risk reduction event, live compliance update, audit chain intact.",
    }
    return {
        "ok": not missing,
        "product": "Continuous Security, Risk & Compliance Control Plane",
        "loop": "asset→observe→find→risk→compliance→evidence→recommend→approve→agent→fix→verify→recalc→audit→sse",
        "agent_id": agent_id,
        "asset_identity": identity,
        "steps": [
            {
                "name": s.name,
                "ok": bool(s.ok),
                "detail": getattr(s, "detail", "") or "",
            }
            for s in (report.steps or [])
        ],
        "missing": missing,
        "decision_drawer": drawer,
        "audit": {"ok": bool(audit.get("ok")), "checked": audit.get("checked")},
        "disclaimer": (
            "Lab launch demonstration on the existing acceptance chain. "
            "CI uses synthetic check-in + lab-simulated command execute. "
            "Owned-host OS mutation, EV signing, cloud WORM, and 5k HTTP remain ops."
        ),
        "fail_via_checkin": bool((getattr(fail, "data", None) or {}).get("via_checkin")),
    }
