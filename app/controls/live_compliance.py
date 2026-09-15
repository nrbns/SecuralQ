"""Live operating-effectiveness from control test last-results (Phase A).

Distinct from pasted-evidence gap ``compliance_percent`` — this score only
reflects decisive PASS/FAIL rows in ``securaiq_control_test_results``.
No manual editing; recomputed whenever controls change.
"""

from __future__ import annotations

from typing import Any

_last_live_percent: dict[str, float] = {}


def compute_live_compliance(user_id: str) -> dict[str, Any]:
    """Roll up last-result statuses across frameworks that have live rows."""
    from app.controls.results import aggregate_control_statuses, ensure_schema
    from app.db import get_conn

    ensure_schema()
    c = get_conn()
    fids = [
        str(r[0] if not hasattr(r, "keys") else r["framework_id"])
        for r in c.execute(
            """
            SELECT DISTINCT framework_id FROM securaiq_control_test_results
            WHERE user_id = ? AND framework_id != ''
            ORDER BY framework_id
            """,
            (user_id,),
        ).fetchall()
    ]

    frameworks: list[dict[str, Any]] = []
    total_pass = total_fail = total_unknown = 0
    decisive = 0
    last_test: float | None = None

    for fid in fids:
        agg = aggregate_control_statuses(user_id, fid)
        passing = int(agg.get("passing") or 0)
        failing = int(agg.get("failing") or 0)
        unknown = int(agg.get("unknown") or 0)
        na = int(agg.get("na") or 0)
        scored = passing + failing
        pct = round(100.0 * passing / scored, 1) if scored else None
        frameworks.append(
            {
                "framework_id": fid,
                "passing": passing,
                "failing": failing,
                "unknown": unknown,
                "na": na,
                "controls_with_results": int(agg.get("controls_with_results") or 0),
                "live_percent": pct,
                "last_test": agg.get("last_test"),
            }
        )
        total_pass += passing
        total_fail += failing
        total_unknown += unknown
        decisive += scored
        lt = agg.get("last_test")
        if lt is not None:
            try:
                ltf = float(lt)
            except (TypeError, ValueError):
                ltf = None
            if ltf is not None and (last_test is None or ltf > last_test):
                last_test = ltf

    overall = round(100.0 * total_pass / decisive, 1) if decisive else None
    return {
        "ok": True,
        "live_percent": overall,
        "passing": total_pass,
        "failing": total_fail,
        "unknown": total_unknown,
        "decisive_controls": decisive,
        "frameworks": frameworks,
        "last_test": last_test,
        "disclaimer": (
            "Live operating-effectiveness from agent/control last-results only — "
            "not a certification score and not blended into gap-analysis %."
        ),
    }


def publish_live_compliance_update(
    user_id: str,
    *,
    reason: str = "",
    agent_id: str = "",
    asset_id: str = "",
    test: str = "",
    status: str = "",
) -> dict[str, Any] | None:
    """Recompute and publish ``compliance.updated`` with previous_percent / delta."""
    if not user_id:
        return None
    snap = compute_live_compliance(user_id)
    pct = snap.get("live_percent")
    previous = _last_live_percent.get(user_id)
    if pct is not None:
        try:
            _last_live_percent[user_id] = float(pct)
        except (TypeError, ValueError):
            pass
    payload: dict[str, Any] = {
        "type": "compliance.updated",
        "event_type": "compliance.updated",
        "user_id": user_id,
        "live_percent": pct,
        "passing": snap.get("passing"),
        "failing": snap.get("failing"),
        "decisive_controls": snap.get("decisive_controls"),
        "reason": reason or "control_result",
        "agent_id": agent_id or None,
        "asset_id": asset_id or None,
        "test": test or None,
        "status": status or None,
        "source": "live_compliance",
    }
    if previous is not None and pct is not None:
        try:
            payload["previous_percent"] = previous
            payload["percent_delta"] = round(float(pct) - float(previous), 2)
        except (TypeError, ValueError):
            pass
    try:
        from app.realtime_bus import publish

        publish(**payload, _from_processor=True)
    except Exception:
        pass
    out = dict(snap)
    if "previous_percent" in payload:
        out["previous_percent"] = payload["previous_percent"]
    if "percent_delta" in payload:
        out["percent_delta"] = payload["percent_delta"]
    return out


def clear_live_compliance_cache() -> None:
    _last_live_percent.clear()
