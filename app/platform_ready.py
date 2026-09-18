"""Platform readiness probe — DB + Redis/realtime (Phase A observability)."""

from __future__ import annotations

from typing import Any


def platform_ready() -> dict[str, Any]:
    """Return readiness for load balancers (not a substitute for /api/health)."""
    checks: dict[str, Any] = {}
    ready = True

    try:
        from app.db import get_conn

        get_conn().execute("SELECT 1").fetchone()
        checks["database"] = {"ok": True}
    except Exception as exc:
        ready = False
        checks["database"] = {"ok": False, "error": str(exc)[:160]}

    try:
        from app.config import settings
        from app.redis_client import get_redis

        redis_url = (getattr(settings, "redis_url", None) or "").strip()
        sentinel = (getattr(settings, "redis_sentinel_hosts", None) or "").strip()
        if redis_url or sentinel:
            client = get_redis()
            if client is None:
                checks["redis"] = {
                    "ok": False,
                    "configured": True,
                    "error": "client unavailable",
                }
                ready = False
            else:
                try:
                    pong = client.ping()
                    checks["redis"] = {"ok": bool(pong), "configured": True}
                    if not pong:
                        ready = False
                except Exception as exc:
                    ready = False
                    checks["redis"] = {
                        "ok": False,
                        "configured": True,
                        "error": str(exc)[:160],
                    }
        else:
            checks["redis"] = {
                "ok": True,
                "configured": False,
                "mode": "in_process",
                "note": "REDIS_URL unset — lab in-process bus",
            }
    except Exception as exc:
        checks["redis"] = {"ok": False, "error": str(exc)[:160]}
        ready = False

    try:
        from app.realtime_bus import publish_throughput

        m = publish_throughput()
        checks["realtime"] = {"ok": True, "metrics": m if isinstance(m, dict) else {}}
    except Exception:
        checks["realtime"] = {"ok": True, "metrics": {}}

    try:
        from app.production_profile import production_profile_status

        checks["production_profile"] = production_profile_status()
    except Exception:
        checks["production_profile"] = {"ok": False}

    return {
        "ready": ready,
        "status": "ready" if ready else "not_ready",
        "checks": checks,
        "disclaimer": (
            "Lab may be ready without Redis HA. Commercial installs should enable "
            "Sentinel/Postgres and production profile flags."
        ),
    }
