"""API routes for XDR/EDR integrations — status, manual sync trigger,
normalized detections feed, patch-compliance summary, and inbound ingest.

See app/xdr.py for the orchestration logic and app/connectors/{sophos,
crowdstrike,sentinelone,defender}.py for the per-vendor clients.
"""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Depends, Header, HTTPException, Request

from app.auth import AuthUser
from app.commercial_api import require_user
from app.config import settings
from app.db import audit
from app.xdr import ingest_detections, list_events, patch_compliance_summary
from app.xdr import status as xdr_status

router = APIRouter(prefix="/api/xdr", tags=["xdr"])


def _require_ingest_secret(header_val: str | None) -> None:
    secret = (settings.ingest_webhook_secret or "").strip()
    if secret:
        if (header_val or "").strip() != secret:
            raise HTTPException(status_code=401, detail="Invalid ingest secret")
        return
    if settings.auth_enabled:
        raise HTTPException(
            status_code=503,
            detail="Set INGEST_WEBHOOK_SECRET for push ingest when auth is enabled",
        )


@router.get("/status")
async def get_status(user: Annotated[AuthUser, Depends(require_user)]):
    from app.connectors import defender as defender_conn

    try:
        from app import xdr_stream

        streaming = xdr_stream.status()
    except Exception:
        streaming = {
            "crowdstrike": {"mode": "stream", "connected": False},
            "sophos": {"mode": "near_realtime_poll", "connected": False},
            "sentinelone": {"mode": "near_realtime_poll", "connected": False},
            "defender": {"mode": "near_realtime_poll", "connected": False},
        }

    return {
        "vendors": xdr_status(),
        "ingest_path": "/api/xdr/ingest",
        "ingest_secret_set": bool((settings.ingest_webhook_secret or "").strip()),
        "near_realtime_interval_sec": int(getattr(settings, "xdr_near_realtime_interval_sec", 60) or 60),
        "streaming": streaming,
        "hunting": {
            "path": "/api/xdr/hunting/run",
            "configured": defender_conn.is_configured(),
            "api": getattr(settings, "defender_hunting_api", "auto") or "auto",
            "default_query": defender_conn.DEFAULT_LIVE_QUERY,
            "docs": {
                "graph": "https://learn.microsoft.com/en-us/graph/api/security-security-runhuntingquery",
                "legacy": "https://learn.microsoft.com/en-us/defender-xdr/api-advanced-hunting",
            },
        },
    }


@router.post("/sync")
async def trigger_sync(user: Annotated[AuthUser, Depends(require_user)]):
    from app.jobs import enqueue_job

    job = enqueue_job("xdr_sync", {"user_id": user.id})
    return {"job": job}


@router.get("/detections")
async def get_detections(
    user: Annotated[AuthUser, Depends(require_user)],
    limit: int = 100,
    vendor: str | None = None,
    kind: str | None = None,
    x_securaiq_org: str | None = Header(default=None, alias="X-SecuraIQ-Org"),
):
    from app.tenancy import resolve_request_org

    oid = resolve_request_org(user, org_id=None, header_org=x_securaiq_org)
    return {
        "events": list_events(user.id, limit=limit, vendor=vendor, kind=kind, org_id=oid),
        "org_id": oid,
    }


@router.get("/patches")
async def get_patch_compliance(
    user: Annotated[AuthUser, Depends(require_user)],
    x_securaiq_org: str | None = Header(default=None, alias="X-SecuraIQ-Org"),
):
    from app.tenancy import resolve_request_org

    oid = resolve_request_org(user, org_id=None, header_org=x_securaiq_org)
    return patch_compliance_summary(user.id, org_id=oid)


@router.post("/hunting/run")
async def hunting_run(request: Request, user: Annotated[AuthUser, Depends(require_user)]):
    """Run Defender XDR advanced hunting KQL against the live tenant only.

    Body: ``{"query": "...", "timespan": "P7D", "backend": "auto|graph|legacy",
    "limit": 50, "ingest": false}``
    """
    from app.connectors import defender as defender_conn

    try:
        body = await request.json()
    except Exception as exc:
        raise HTTPException(status_code=400, detail="Invalid JSON") from exc
    if not isinstance(body, dict):
        raise HTTPException(status_code=400, detail="Expected JSON object")

    query = (body.get("query") or "").strip() or defender_conn.DEFAULT_LIVE_QUERY

    backend = (body.get("backend") or "").strip().lower() or None
    if backend and backend not in ("auto", "graph", "legacy"):
        raise HTTPException(status_code=400, detail="backend must be auto|graph|legacy")

    timespan = (body.get("timespan") or "").strip() or None
    limit = int(body.get("limit") or 100)
    do_ingest = bool(body.get("ingest"))

    result = await defender_conn.run_advanced_hunting(
        query,
        timespan=timespan,
        backend=backend,  # type: ignore[arg-type]
        limit=limit,
    )
    audit(
        "defender_hunting",
        user.id,
        {
            "ok": result.get("ok"),
            "backend": result.get("backend"),
            "live": bool(result.get("ok")),
            "result_count": result.get("result_count"),
        },
    )

    try:
        from app.realtime_bus import publish

        publish(
            type="hunt",
            backend=result.get("backend"),
            ok=bool(result.get("ok")),
            result_count=result.get("result_count"),
            live=bool(result.get("ok")),
        )
    except Exception:
        pass

    ingested = None
    if do_ingest and result.get("ok") and result.get("results"):
        items = []
        for i, row in enumerate(result["results"][:50]):
            if not isinstance(row, dict):
                continue
            title = (
                row.get("Title")
                or row.get("title")
                or row.get("FileName")
                or row.get("AlertId")
                or f"Hunt row {i + 1}"
            )
            host = row.get("DeviceName") or row.get("host") or row.get("AccountUpn") or ""
            sev = row.get("Severity") or row.get("severity") or "medium"
            ext = str(row.get("AlertId") or row.get("Timestamp") or f"hunt-{i}")
            items.append(
                {
                    "vendor": "defender",
                    "external_id": f"hunt:{ext}"[:200],
                    "kind": "hunt_finding",
                    "severity": str(sev).lower() if isinstance(sev, str) else "medium",
                    "host": str(host)[:200],
                    "title": str(title)[:300],
                    "description": "Advanced hunting result",
                    "raw": row,
                }
            )
        if items:
            ingested = ingest_detections(items, user_id=user.id, auto_incidents=False)

    out: dict[str, Any] = {**result}
    if ingested is not None:
        out["ingested"] = ingested
    return out


@router.post("/hunting/ping")
async def hunting_ping(user: Annotated[AuthUser, Depends(require_user)]):
    from app.connectors import defender as defender_conn

    return await defender_conn.ping_hunting()


@router.post("/ingest")
async def ingest_webhook(
    request: Request,
    x_securaiq_ingest: Annotated[str | None, Header(alias="X-SecuraIQ-Ingest")] = None,
):
    """Push normalized detections from a lab script or SIEM automation.

    Body: ``{"detections":[{vendor,external_id,title,severity,host,kind}]}``
    or a bare list of detection objects. Auth via ``X-SecuraIQ-Ingest`` when
    ``INGEST_WEBHOOK_SECRET`` is set (required if AUTH_ENABLED).
    """
    _require_ingest_secret(x_securaiq_ingest)
    try:
        body = await request.json()
    except Exception as exc:
        raise HTTPException(status_code=400, detail="Invalid JSON") from exc

    if isinstance(body, list):
        items = body
        user_id = "local"
    elif isinstance(body, dict):
        items = body.get("detections") or body.get("events") or body.get("alerts") or []
        user_id = str(body.get("user_id") or "local")
        if not isinstance(items, list):
            raise HTTPException(status_code=400, detail="detections must be a list")
    else:
        raise HTTPException(status_code=400, detail="Expected object or list")

    result = ingest_detections([x for x in items if isinstance(x, dict)], user_id=user_id)
    audit("xdr_ingest", user_id, {"new": result.get("new"), "total": result.get("total")})
    return {"ok": True, **result}
