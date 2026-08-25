"""API routes for Open-AudIT inventory integration."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends

from app.auth import AuthUser
from app.commercial_api import require_user
from app.connectors import openaudit as oa_conn
from app.openaudit import list_devices
from app.openaudit import status as oa_status

router = APIRouter(prefix="/api/openaudit", tags=["openaudit"])


@router.get("/status")
async def get_status(user: Annotated[AuthUser, Depends(require_user)]):
    st = oa_status()
    if st.get("configured"):
        st["ping"] = await oa_conn.ping()
    else:
        st["ping"] = {"ok": False, "error": "not_configured"}
    return st


@router.post("/sync")
async def trigger_sync(user: Annotated[AuthUser, Depends(require_user)]):
    from app.jobs import enqueue_job

    job = enqueue_job("openaudit_sync", {"user_id": user.id}, engine="auto")
    return {"job": job}


@router.get("/devices")
async def get_devices(user: Annotated[AuthUser, Depends(require_user)], limit: int = 100):
    devices = list_devices(limit=limit)
    for row in devices:
        row.pop("raw", None)
        row.pop("raw_json", None)
    return {"devices": devices}


@router.get("/networks")
async def get_networks(user: Annotated[AuthUser, Depends(require_user)], limit: int = 50):
    if not oa_conn.is_configured():
        return {"networks": []}
    try:
        nets = await oa_conn.fetch_networks(limit=limit)
    except Exception:
        nets = []
    return {"networks": nets}
