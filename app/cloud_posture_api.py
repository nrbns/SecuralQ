"""API routes for multi-cloud posture (AWS / Azure / GCP)."""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from app.auth import AuthUser
from app.cloud_posture import import_findings, list_findings, ping_all
from app.cloud_posture import status as cloud_status
from app.commercial_api import require_user

router = APIRouter(prefix="/api/cloud", tags=["cloud-posture"])


class CloudImportBody(BaseModel):
    vendor: str = "cloud_import"
    findings: list[dict[str, Any]] = Field(default_factory=list)


@router.get("/status")
async def get_status(user: Annotated[AuthUser, Depends(require_user)]):
    st = cloud_status()
    st["ping"] = await ping_all()
    return st


@router.post("/sync")
async def trigger_sync(user: Annotated[AuthUser, Depends(require_user)]):
    from app.jobs import enqueue_job

    job = enqueue_job("cloud_posture_sync", {"user_id": user.id}, engine="auto")
    return {"job": job}


@router.get("/findings")
async def get_findings(
    user: Annotated[AuthUser, Depends(require_user)],
    limit: int = 50,
    vendor: str | None = None,
):
    return {"findings": list_findings(limit=limit, vendor=vendor)}


@router.post("/import")
async def post_import(req: CloudImportBody, user: Annotated[AuthUser, Depends(require_user)]):
    if not req.findings:
        raise HTTPException(400, "findings array required")
    return import_findings(user.id, req.findings, vendor=req.vendor or "cloud_import")
