"""API routes for multi-cloud posture (AWS / Azure / GCP)."""

from __future__ import annotations

import json
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
    st = cloud_status()
    if int(st.get("configured_count") or 0) <= 0:
        raise HTTPException(
            400,
            "No AWS / Azure / GCP connectors configured — use Import JSON for lab findings "
            "(or configure vendors in Settings → Cloud posture).",
        )
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


@router.get("/lab-sample")
async def get_lab_sample(user: Annotated[AuthUser, Depends(require_user)]):
    """Return bundled lab findings JSON for one-click Import (no live cloud creds)."""
    from pathlib import Path

    path = Path(__file__).resolve().parents[1] / "data" / "samples" / "cloud_findings_lab.json"
    if not path.is_file():
        raise HTTPException(404, "lab sample not found")
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(500, f"lab sample unreadable: {exc}") from exc


@router.post("/import")
async def post_import(req: CloudImportBody, user: Annotated[AuthUser, Depends(require_user)]):
    if not req.findings:
        raise HTTPException(400, "findings array required")
    return import_findings(user.id, req.findings, vendor=req.vendor or "cloud_import")
