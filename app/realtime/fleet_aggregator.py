"""Fleet-level aggregation — publish summaries, not every heartbeat, to SSE.

At large fleet sizes the UI must subscribe to ``fleet.*.changed`` aggregates.
Per-agent detail is fetched on demand when an operator opens an agent.
"""

from __future__ import annotations

import threading
import time
from typing import Any

_lock = threading.RLock()
# user_id -> {agent_id -> {status, ts, warning}}
_AGENT_STATE: dict[str, dict[str, dict[str, Any]]] = {}
# user_id -> last published summary signature
_LAST_SIG: dict[str, str] = {}
_LAST_PUBLISH_TS: dict[str, float] = {}

# Debounce: do not spam fleet.health.changed faster than this (seconds)
_MIN_PUBLISH_INTERVAL = 2.0


def reset_fleet_state_for_tests() -> None:
    with _lock:
        _AGENT_STATE.clear()
        _LAST_SIG.clear()
        _LAST_PUBLISH_TS.clear()


def record_agent_observation(
    user_id: str,
    agent_id: str,
    *,
    status: str = "online",
    warning: bool = False,
    org_id: str = "",
    publish: bool = True,
) -> dict[str, Any]:
    """Update in-memory fleet state; optionally publish aggregate if changed."""
    uid = (user_id or "").strip() or "local"
    aid = (agent_id or "").strip()
    if not aid:
        return {"ok": False, "error": "agent_id required"}
    st = (status or "online").strip().lower() or "online"
    now = time.time()
    with _lock:
        bucket = _AGENT_STATE.setdefault(uid, {})
        bucket[aid] = {
            "status": st,
            "warning": bool(warning),
            "ts": now,
            "org_id": org_id or "",
        }
        summary = _summarize_unlocked(uid)
    if publish:
        maybe_publish_fleet_health(uid, summary)
    return {"ok": True, "summary": summary}


def fleet_summary(user_id: str) -> dict[str, Any]:
    uid = (user_id or "").strip() or "local"
    with _lock:
        return _summarize_unlocked(uid)


def _summarize_unlocked(user_id: str) -> dict[str, Any]:
    agents = _AGENT_STATE.get(user_id) or {}
    online = offline = warning = 0
    for row in agents.values():
        st = str(row.get("status") or "")
        if row.get("warning"):
            warning += 1
        if st in {"online", "ok", "healthy"}:
            online += 1
        elif st in {"offline", "disconnected", "stale"}:
            offline += 1
        else:
            # unknown / degraded counts toward warning bucket for UI
            warning += 1
    total = len(agents)
    return {
        "user_id": user_id,
        "total": total,
        "online": online,
        "offline": offline,
        "warning": warning,
        "updated_at": time.time(),
    }


def _signature(summary: dict[str, Any]) -> str:
    return (
        f"{summary.get('total')}:{summary.get('online')}:"
        f"{summary.get('offline')}:{summary.get('warning')}"
    )


def maybe_publish_fleet_health(user_id: str, summary: dict[str, Any] | None = None) -> bool:
    """Publish ``fleet.health.changed`` when counts change (debounced)."""
    uid = (user_id or "").strip() or "local"
    summary = summary or fleet_summary(uid)
    sig = _signature(summary)
    now = time.time()
    with _lock:
        if _LAST_SIG.get(uid) == sig:
            return False
        last_ts = float(_LAST_PUBLISH_TS.get(uid) or 0)
        if now - last_ts < _MIN_PUBLISH_INTERVAL and _LAST_SIG.get(uid):
            return False
        _LAST_SIG[uid] = sig
        _LAST_PUBLISH_TS[uid] = now
    try:
        from app.realtime_bus import publish

        publish(
            type="fleet.health.changed",
            event_type="fleet.health.changed",
            user_id=uid,
            online=summary.get("online"),
            offline=summary.get("offline"),
            warning=summary.get("warning"),
            total=summary.get("total"),
            message=(
                f"Online: {summary.get('online')} · Offline: {summary.get('offline')} · "
                f"Warning: {summary.get('warning')}"
            ),
        )
        return True
    except Exception:
        return False


def publish_fleet_metric(
    user_id: str,
    metric: str,
    *,
    value: Any = None,
    **extra: Any,
) -> None:
    """Publish a named fleet aggregate (risk/compliance/vuln/incident counts)."""
    name = (metric or "").strip().lower().replace(" ", "_")
    if not name:
        return
    et = name if name.startswith("fleet.") else f"fleet.{name}.changed"
    try:
        from app.realtime_bus import publish

        publish(
            type=et,
            event_type=et,
            user_id=(user_id or "").strip() or "local",
            value=value,
            **extra,
        )
    except Exception:
        pass
