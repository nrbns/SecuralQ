"""API routes for TheHive case management."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from app.auth import AuthUser
from app.commercial_api import require_user
from app.connectors import thehive as th_conn
from app.thehive import list_cases
from app.thehive import status as th_status

router = APIRouter(prefix="/api/thehive", tags=["thehive"])


class CaseCreate(BaseModel):
    title: str = Field(min_length=1, max_length=200)
    description: str = ""
    severity: int = Field(default=2, ge=1, le=4)


@router.get("/status")
async def get_status(user: Annotated[AuthUser, Depends(require_user)]):
    st = th_status()
    if st.get("configured"):
        st["ping"] = await th_conn.ping()
    else:
        st["ping"] = {"ok": False, "error": "not_configured"}
    return st


@router.post("/sync")
async def trigger_sync(user: Annotated[AuthUser, Depends(require_user)]):
    from app.jobs import enqueue_job

    job = enqueue_job("thehive_sync", {"user_id": user.id}, engine="auto")
    return {"job": job}


@router.get("/cases")
async def get_cases(user: Annotated[AuthUser, Depends(require_user)], limit: int = 50):
    return {"cases": list_cases(limit=limit)}


@router.post("/cases")
async def post_case(req: CaseCreate, user: Annotated[AuthUser, Depends(require_user)]):
    try:
        return await th_conn.create_case(
            title=req.title, description=req.description, severity=req.severity
        )
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
