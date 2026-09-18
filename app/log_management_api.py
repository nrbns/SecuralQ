"""API: log management + SIEM search.

Two ingestion paths exist for real logs:
  * POST /api/logs/ingest here -- user-session authenticated, for a manual
    push or a syslog/HTTP bridge script run with the operator's own API key.
  * POST /api/agents/logs (app/agents_api.py) -- agent-HMAC authenticated,
    for SecuraIQ's own native agents to ship OS-level log events the same
    way they already ship check-ins and threat detections.

Both land in the same `ingested_logs` table via app.services.log_management,
and both trigger the same correlation check.
"""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field

from app.auth import AuthUser
from app.commercial_api import require_user
from app.services.log_management import (
    ingest_log,
    log_stats,
    run_auth_failure_correlation,
    search_logs,
)

router = APIRouter(prefix="/api/logs", tags=["log-management"])


class LogIngest(BaseModel):
    host: str = ""
    actor: str = ""
    severity: str = "info"
    event_type: str = ""
    message: str = Field(min_length=1, max_length=4000)
    raw: dict[str, Any] = Field(default_factory=dict)


@router.post("/ingest")
async def post_ingest(req: LogIngest, user: Annotated[AuthUser, Depends(require_user)]):
    result = ingest_log(
        user.id,
        source="api",
        source_id="manual-api",
        host=req.host,
        actor=req.actor,
        severity=req.severity,
        event_type=req.event_type,
        message=req.message,
        raw=req.raw,
    )
    incidents = run_auth_failure_correlation(user.id)
    result["incidents_created"] = incidents
    return result


@router.get("")
async def get_logs(
    user: Annotated[AuthUser, Depends(require_user)],
    q: str = "",
    source: str = "",
    severity: str = "",
    limit: int = 200,
):
    return {"logs": search_logs(user.id, q=q, source=source, severity=severity, limit=limit)}


@router.get("/stats")
async def get_stats(user: Annotated[AuthUser, Depends(require_user)]):
    return log_stats(user.id)


@router.get("/siem/status")
async def get_siem_status(user: Annotated[AuthUser, Depends(require_user)]):
    """Outbound SIEM forwarding status — reflects exactly what's configured,
    real reachability only reported after /siem/test actually calls out."""
    from app.config import settings

    return {
        "generic": {
            "enabled": bool(settings.siem_forward_enabled),
            "configured": bool((settings.siem_forward_url or "").strip() or (settings.siem_syslog_host or "").strip()),
        },
        "azure_sentinel": {
            "enabled": bool(settings.siem_azure_sentinel_enabled),
            "configured": _azure_sentinel_configured(),
        },
    }


def _azure_sentinel_configured() -> bool:
    from app.connectors import azure_sentinel

    return azure_sentinel.is_configured()


@router.post("/siem/azure/test")
async def test_azure_sentinel(user: Annotated[AuthUser, Depends(require_user)]):
    """Real connectivity check: acquires a live OAuth2 token from Entra ID
    and sends one heartbeat event through the actual Logs Ingestion API
    pipeline — not a canned 'ok'. Any misconfigured DCE/DCR/permission
    surfaces here as a real error."""
    from app.connectors import azure_sentinel

    result = await azure_sentinel.ping()
    return result
