"""Aggregated System Health for the commercial Admin screen (#23)."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends
from typing import Annotated

from app.auth import AuthUser
from app.commercial_api import require_user
from app.rbac import require_perm

router = APIRouter(prefix="/api/admin", tags=["system-health"])


@router.get("/system-health")
async def api_system_health(user: Annotated[AuthUser, Depends(require_user)]):
    require_perm(user, "settings.write", org_id=None)
    return build_system_health()


def build_system_health() -> dict[str, Any]:
    from app.config import settings

    checks: dict[str, Any] = {}
    # API
    checks["api"] = {"status": "healthy", "detail": "ok"}

    # Database
    try:
        from app.db import current_backend, get_conn

        get_conn().execute("SELECT 1").fetchone()
        checks["database"] = {"status": "healthy", "detail": current_backend()}
    except Exception as exc:
        checks["database"] = {"status": "down", "detail": str(exc)[:160]}

    # Redis / Streams
    try:
        from app.redis_client import redis_enabled
        from app.realtime_bus import backend_status

        rt = backend_status() if callable(backend_status) else {}
        if redis_enabled():
            checks["redis_streams"] = {
                "status": "healthy" if (rt.get("ok") or rt.get("backend")) else "degraded",
                "detail": rt,
            }
        else:
            checks["redis_streams"] = {
                "status": "lab",
                "detail": "REDIS_URL not set — in-process bus",
            }
    except Exception as exc:
        checks["redis_streams"] = {"status": "unknown", "detail": str(exc)[:120]}

    # Event processor / DLQ
    try:
        from app.event_processor import dlq_stats  # type: ignore

        stats = dlq_stats() if callable(dlq_stats) else {}
        checks["event_processor"] = {"status": "healthy", "detail": stats}
    except Exception:
        try:
            from app.realtime_bus import backend_status

            checks["event_processor"] = {"status": "healthy", "detail": backend_status()}
        except Exception as exc:
            checks["event_processor"] = {"status": "unknown", "detail": str(exc)[:120]}

    # Agent gateway
    checks["agent_gateway"] = {
        "status": "healthy" if getattr(settings, "agent_gateway_enabled", True) else "off",
        "detail": {"enabled": bool(getattr(settings, "agent_gateway_enabled", True))},
    }

    # SSE
    try:
        from app.realtime_bus import subscriber_count

        n = subscriber_count() if callable(subscriber_count) else None
        checks["sse"] = {"status": "healthy", "detail": {"subscribers": n}}
    except Exception:
        checks["sse"] = {"status": "healthy", "detail": "SSE endpoint /api/realtime"}

    # Evidence / object storage
    try:
        from app.object_storage import status as os_status

        st = os_status()
        checks["evidence_store"] = {
            "status": "healthy" if st.get("configured") or st.get("backend") == "local" else "degraded",
            "detail": st,
        }
    except Exception as exc:
        checks["evidence_store"] = {"status": "unknown", "detail": str(exc)[:120]}

    # mTLS fleet
    try:
        from app.agent_certs import fleet_mtls_status

        checks["agent_mtls"] = {"status": "ready" if fleet_mtls_status().get("ca_ready") or not fleet_mtls_status().get("enabled") else "pending", "detail": fleet_mtls_status()}
    except Exception as exc:
        checks["agent_mtls"] = {"status": "unknown", "detail": str(exc)[:80]}

    overall = "healthy"
    for v in checks.values():
        s = (v.get("status") or "").lower()
        if s in {"down", "failed"}:
            overall = "down"
            break
        if s in {"degraded", "pending"} and overall == "healthy":
            overall = "degraded"

    return {
        "ok": overall != "down",
        "status": overall,
        "product": "SecuraIQ",
        "deployment_mode": getattr(settings, "deployment_mode", "lab"),
        "checks": checks,
        "loop": [
            "DISCOVER",
            "OBSERVE",
            "DETECT",
            "UNDERSTAND",
            "PRIORITIZE",
            "SIMULATE",
            "REMEDIATE",
            "VERIFY",
            "PROVE",
            "COMPLIANCE/RISK UPDATED",
        ],
    }
