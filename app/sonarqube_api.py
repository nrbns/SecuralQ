"""SecuraIQ Code API — branded SAST console backed by a Sonar-compatible engine.

Primary routes: /api/code/*
Compat alias:   /api/sonarqube/* (older clients / settings)
"""

from __future__ import annotations

import json
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field

from app.auth import AuthUser
from app.commercial_api import require_user
from app.connectors import sonarqube as sonar_conn
from app.sonarqube import status as sonar_status

# Shared route table (no prefix) — mounted under /api/code and /api/sonarqube
router = APIRouter(tags=["securaiq-code"])


class CodeScanBody(BaseModel):
    path: str = Field(..., min_length=1, description="Local project folder you own / are authorized to scan")
    authorized: bool = True
    sync_engine: bool = False


@router.get("/status")
async def get_status(user: Annotated[AuthUser, Depends(require_user)]):
    st = sonar_status()
    st["brand"] = "SecuraIQ Code"
    st["engine"] = "sonar_compatible"
    st["local_scan"] = True
    st["ping"] = await sonar_conn.ping() if st.get("configured") else {"ok": False, "error": "not_configured"}
    return st


@router.post("/sync")
async def trigger_sync(user: Annotated[AuthUser, Depends(require_user)]):
    st = sonar_status()
    if not st.get("configured"):
        raise HTTPException(
            400,
            "No code engine configured — use Scan folder for local SAST "
            "(or set SecuraIQ Code / Sonar settings).",
        )
    from app.jobs import enqueue_job

    job = enqueue_job("sonarqube_sync", {"user_id": user.id}, engine="auto")
    return {"job": job, "ok": True, "brand": "SecuraIQ Code"}


@router.post("/test")
async def test_connection(user: Annotated[AuthUser, Depends(require_user)]):
    result = await sonar_conn.ping()
    result["brand"] = "SecuraIQ Code"
    return result


@router.post("/scan/stream")
async def scan_folder_stream(
    body: CodeScanBody,
    user: Annotated[AuthUser, Depends(require_user)],
):
    """Realtime NDJSON stream for local folder SAST (Auth required to persist)."""
    from app.tools.runner import iter_security_tools

    path = body.path.strip()
    tools = ["securaiq_code"] if body.sync_engine else ["code_scan"]

    async def gen():
        async for ev in iter_security_tools(
            f"authorized code analysis of {path}",
            target=path,
            tools=tools,
            authorized=bool(body.authorized),
            include_heavy=True,
            user_id=user.id,
        ):
            yield json.dumps(ev, default=str) + "\n"

    return StreamingResponse(gen(), media_type="application/x-ndjson")
