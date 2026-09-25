"""Effective control status — never PASS when the agent is offline or evidence expired.

Technical truth comes from observation + freshness + agent availability.
AI does not decide PASS.
"""

from __future__ import annotations

from typing import Any

from app.db import now
from app.evidence_spine.freshness import apply_freshness_to_result


def agent_availability(user_id: str) -> dict[str, Any]:
    """Online = recent check-in. Does not load payloads or latest commands."""
    online = 0
    total = 0
    try:
        from app.agents import OFFLINE_AFTER_SEC, ensure_schema
        from app.db import get_conn

        ensure_schema()
        try:
            from app.tenancy import tenant_visibility_sql

            where, args = tenant_visibility_sql(user_id)
            rows = get_conn().execute(
                f"SELECT last_checkin, revoked FROM securaiq_agents WHERE {where} LIMIT 200",
                args,
            ).fetchall()
        except Exception:
            rows = get_conn().execute(
                "SELECT last_checkin, revoked FROM securaiq_agents WHERE user_id = ? LIMIT 200",
                (user_id,),
            ).fetchall()
        now_ts = now()
        for row in rows:
            rec = dict(row)
            total += 1
            if rec.get("revoked"):
                continue
            last = float(rec.get("last_checkin") or 0)
            if last and (now_ts - last) <= float(OFFLINE_AFTER_SEC):
                online += 1
    except Exception:
        pass
    return {
        "agents": total,
        "online": online,
        "any_online": online > 0,
        "offline": max(0, total - online),
    }


def agents_permit_pass(user_id: str) -> bool:
    """PASS is allowed only if no agents are enrolled, or at least one is online."""
    avail = agent_availability(user_id)
    return bool(avail["any_online"] or avail["agents"] == 0)


def resolve_result_truth(
    row: dict[str, Any],
    *,
    agents_online: bool,
    now_ts: float | None = None,
) -> dict[str, Any]:
    """Map a stored last-result into PASS/FAIL/UNKNOWN/EXPIRED/NA/ERROR."""
    raw = str(row.get("status") or "unknown").strip().lower()
    test_name = str(row.get("test_name") or row.get("test") or "")
    tested_at = row.get("tested_at")
    try:
        last = float(tested_at) if tested_at is not None else None
    except (TypeError, ValueError):
        last = None
    fr = apply_freshness_to_result(
        result=raw,
        last_observed=last,
        control_or_test=test_name,
        now_ts=now_ts,
    )
    age = fr.get("age_sec")
    freshness = "valid"
    status = raw
    reason = "Within freshness window."
    if raw in {"na", "not_applicable"}:
        status = "not_applicable"
        freshness = "na"
        reason = "Not applicable."
    elif raw == "error":
        status = "error"
        freshness = "error"
        reason = str(row.get("summary") or "Collector error.")
    elif raw == "pass" and not agents_online:
        status = "unknown"
        freshness = "unknown"
        reason = "Agent unavailable — never PASS from offline telemetry."
    elif fr.get("stale") and raw == "pass":
        status = "expired"
        freshness = "expired"
        reason = str(fr.get("note") or "Evidence expired — recollect required.")
    elif fr.get("stale"):
        freshness = "expired"
        reason = str(fr.get("note") or "Last-known result is past freshness policy.")
        status = "fail" if raw in {"fail", "partial"} else raw
    elif raw == "unknown":
        freshness = "unknown"
        reason = str(row.get("summary") or "Not collected.")
    return {
        "raw_status": raw,
        "status": status,
        "freshness": freshness,
        "age_sec": age,
        "last_observed": last,
        "reason": reason,
        "agents_online": agents_online,
        "test_name": test_name,
        "summary": row.get("summary") or "",
        "detail": row.get("detail") if isinstance(row.get("detail"), dict) else {},
        "policy": fr.get("policy"),
    }


def control_detail(user_id: str, framework_id: str, control_id: str) -> dict[str, Any] | None:
    from app.controls.catalog import get_control
    from app.controls.results import get_results_for_control
    from app.controls.test_engine import _why_failing

    ctrl = get_control(framework_id, control_id)
    if not ctrl:
        return None
    avail = agent_availability(user_id)
    permit_pass = bool(avail["any_online"] or avail["agents"] == 0)
    stored = get_results_for_control(user_id, framework_id, control_id)
    truths = [resolve_result_truth(r, agents_online=permit_pass) for r in stored]
    live_results = []
    why: list[str] = []
    for row in stored:
        shaped = {
            "test": row.get("test_name"),
            "test_name": row.get("test_name"),
            "status": row.get("status"),
            "summary": row.get("summary") or "",
            "detail": row.get("detail") if isinstance(row.get("detail"), dict) else {},
        }
        w = _why_failing(shaped)
        why.extend(w)
        live_results.append(
            {
                "test": row.get("test_name"),
                "status": row.get("status"),
                "summary": row.get("summary") or "",
                "detail": shaped["detail"],
                "tested_at": row.get("tested_at"),
                "why": w,
            }
        )
    statuses = [t["status"] for t in truths]
    if any(s == "fail" for s in statuses):
        rollup = "fail"
    elif any(s == "expired" for s in statuses):
        rollup = "expired"
    elif any(s == "unknown" for s in statuses) or not statuses:
        rollup = "unknown" if statuses else "unknown"
    elif any(s == "error" for s in statuses):
        rollup = "error"
    elif all(s == "pass" for s in statuses):
        rollup = "pass"
    else:
        rollup = statuses[0] if statuses else "unknown"
    last_obs = max((t.get("last_observed") or 0) for t in truths) if truths else None
    freshness = "valid"
    if any(t["freshness"] == "expired" for t in truths):
        freshness = "expired"
    elif any(t["freshness"] == "unknown" for t in truths) or (
        avail["agents"] and not avail["any_online"]
    ):
        freshness = "unknown"
    if rollup == "unknown" and avail["agents"] and not avail["any_online"]:
        why = ["Agent unavailable — last PASS is not shown as PASS."] + why
    return {
        "ok": True,
        "framework_id": framework_id,
        "control_id": control_id,
        "title": ctrl.title,
        "domain": ctrl.domain,
        "description": ctrl.description,
        "requirement": ctrl.description or ctrl.title,
        "status": rollup,
        "freshness": freshness,
        "last_evidence_at": last_obs or None,
        "age_sec": (now() - last_obs) if last_obs else None,
        "agents": avail,
        "why": why,
        "evidence": truths,
        "live_results": live_results,
        "action": {
            "label": "Create remediation" if rollup in {"fail", "expired"} else "Investigate",
            "workspace": "remediations" if rollup == "fail" else "evidence",
        },
        "verify": "Independent re-read of the same control after execution — execute alone is not PASS.",
        "document": {
            "class": "document",
            "status": None,
            "text": ctrl.description or ctrl.title,
            "disclaimer": "Catalog / policy text is not operating-effectiveness PASS.",
        },
        "observation": {
            "class": "observation",
            "status": rollup,
            "freshness": freshness,
            "count": len(truths),
            "disclaimer": "Last agent/control test. Offline or expired PASS is not PASS.",
        },
        "disclaimer": (
            "Observation + freshness + agent availability decide status. "
            "Document text never certifies PASS. Not a certification. AI does not decide PASS."
        ),
    }


def truth_indicators(user_id: str, live: dict[str, Any] | None = None) -> dict[str, Any]:
    avail = agent_availability(user_id)
    if live is None:
        try:
            from app.controls.live_compliance import compute_live_compliance

            live = compute_live_compliance(user_id)
        except Exception:
            live = {}
    live = live or {}
    last = live.get("last_test")
    age = (now() - float(last)) if last else None
    if avail["agents"] and not avail["any_online"]:
        state = "unknown"
        label = "UNKNOWN"
        note = "Agent offline — last PASS is not current."
    elif not avail["agents"]:
        state = "unknown"
        label = "UNKNOWN"
        note = (
            "No agent enrolled — last-results only, not live telemetry."
            if last
            else "No live control results yet."
        )
    elif age is not None and age > 15 * 60:
        state = "stale"
        label = "STALE"
        note = f"Last control result {int(age)}s ago."
    elif last:
        state = "live"
        label = "LIVE"
        note = f"Last control result {int(age or 0)}s ago."
    else:
        state = "unknown"
        label = "UNKNOWN"
        note = "No live control results yet."
    return {
        "ok": True,
        "state": state,
        "label": label,
        "note": note,
        "age_sec": age,
        "agents": avail,
        "live_percent": live.get("live_percent"),
        "passing": live.get("passing"),
        "failing": live.get("failing"),
        "unknown": live.get("unknown"),
        "disclaimer": "LIVE means a recent agent observation exists — not a marketed SLA.",
    }
