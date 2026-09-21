"""Platform Mission Control — aggregated ops health for SecuraIQ.

Honesty: process-local when Redis/Postgres unset. Not a commercial HA console.
Answers: API / Redis / workers / agent GW / evidence / notifications / SSE.
"""

from __future__ import annotations

from typing import Any


def _comp(status: str, **extra: Any) -> dict[str, Any]:
    return {"status": status, **extra}


def mission_control_snapshot(*, user_id: str | None = None) -> dict[str, Any]:
    """Aggregate component health for internal ops / Mission Control UI."""
    components: dict[str, Any] = {}
    queue_lag: float | None = None
    dlq = 0
    agents_online = 0
    agents_stale = 0
    sse_clients = 0
    outbox_pending = 0
    evidence_ok = True

    # API — if we are answering, we are up
    components["api"] = _comp("healthy")

    # Redis / Streams
    try:
        from app.realtime_ops import pipeline_metrics

        m = pipeline_metrics()
        redis_on = bool(m.get("redis_configured"))
        stream = m.get("stream") or {}
        lag = stream.get("lag")
        if lag is not None:
            try:
                queue_lag = float(lag)
            except (TypeError, ValueError):
                queue_lag = None
        try:
            dlq = int(stream.get("dlq_length") or 0)
        except (TypeError, ValueError):
            dlq = 0
        sse = m.get("sse") or {}
        try:
            sse_clients = int(sse.get("local_subscribers") or 0)
        except (TypeError, ValueError):
            sse_clients = 0
        components["redis"] = _comp(
            "healthy" if redis_on else "degraded",
            mode=m.get("mode"),
            configured=redis_on,
            note=None if redis_on else "REDIS_URL unset — in-process bus only",
        )
        components["sse"] = _comp(
            "healthy",
            subscribers=sse_clients,
            streams_fanout=bool(sse.get("streams_fanout")),
        )
        proc = m.get("processor") or {}
        components["workers"] = _comp(
            "healthy" if not proc.get("error") else "degraded",
            processor=proc.get("mode") or proc.get("status") or "local",
            error=proc.get("error"),
        )
    except Exception as exc:
        components["redis"] = _comp("unknown", error=str(exc)[:160])
        components["sse"] = _comp("unknown")
        components["workers"] = _comp("unknown")

    # Postgres — optional; SQLite lab is normal
    try:
        from app.config import settings

        db_url = (getattr(settings, "database_url", None) or "").strip()
        if db_url.startswith("postgres"):
            components["postgres"] = _comp("healthy", configured=True)
        else:
            components["postgres"] = _comp(
                "not_configured",
                configured=False,
                note="SQLite lab default — Postgres optional for SaaS",
            )
    except Exception as exc:
        components["postgres"] = _comp("unknown", error=str(exc)[:120])

    # Agent gateway
    try:
        from app.config import settings as _sgw

        enabled = bool(getattr(_sgw, "agent_gateway_enabled", True))
        waiters_n = 0
        ws_n = 0
        try:
            from app import agent_gateway as _gw

            lock = getattr(_gw, "_wait_lock", None)
            waiters = getattr(_gw, "_waiters", {}) or {}
            if lock is not None:
                with lock:
                    waiters_n = sum(len(v) for v in waiters.values()) if isinstance(waiters, dict) else 0
            elif isinstance(waiters, dict):
                waiters_n = sum(len(v) for v in waiters.values())
            conns = getattr(_gw, "_connections", {}) or {}
            ws_n = len(conns) if isinstance(conns, dict) else 0
        except Exception:
            pass
        components["agent_gateway"] = _comp(
            "healthy" if enabled else "disabled",
            waiters=waiters_n,
            websockets=ws_n,
        )
    except Exception as exc:
        components["agent_gateway"] = _comp("unknown", error=str(exc)[:120])

    # Agents online / stale (scoped when user_id given)
    try:
        from app.agents import list_agents

        uid = (user_id or "local").strip() or "local"
        rows = list_agents(uid, limit=500)
        for a in rows:
            st = str(a.get("status") or "").lower()
            if st == "online":
                agents_online += 1
            elif st in {"stale", "offline"}:
                agents_stale += 1
    except Exception:
        pass

    # Evidence store reachable
    try:
        from app.services.evidence import ensure_schema

        ensure_schema()
        components["evidence"] = _comp("healthy")
    except Exception as exc:
        evidence_ok = False
        components["evidence"] = _comp("degraded", error=str(exc)[:120])

    # Notification outbox
    try:
        from app.notification_worker import outbox_stats

        stats = outbox_stats(user_id or "")
        counts = stats.get("counts") or {}
        outbox_pending = int(counts.get("pending") or 0) + int(counts.get("retrying") or 0)
        dead = int(counts.get("dead") or 0)
        components["notifications"] = _comp(
            "healthy" if dead == 0 else "degraded",
            pending=outbox_pending,
            dead=dead,
            counts=counts,
        )
    except Exception as exc:
        components["notifications"] = _comp("unknown", error=str(exc)[:120])

    overall = "healthy"
    for c in components.values():
        if c.get("status") in {"degraded", "unknown"}:
            overall = "degraded"
            break
        if c.get("status") == "disabled":
            continue

    return {
        "ok": True,
        "overall": overall,
        "components": components,
        "queue_lag_sec": queue_lag,
        "dlq": dlq,
        "agents_online": agents_online,
        "agents_stale": agents_stale,
        "sse_clients": sse_clients,
        "outbox_pending": outbox_pending,
        "evidence_ok": evidence_ok,
        "disclaimer": (
            "Lab Mission Control — process-local metrics when Redis unset. "
            "Not a multi-node HA dashboard. Do not claim production SLO from this panel."
        ),
    }
