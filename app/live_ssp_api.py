"""Live SSP — Sprint 6 of the Control & Configuration Engine roadmap.

Prefix: ``/api/compliance/ssp``. See app.services.live_ssp for the honesty
rules this endpoint follows (recomputed from real data every call, never a
cached document, three separate signals per control never blended).
"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException

from app.auth import AuthUser
from app.commercial_api import require_user
from app.gap_analysis import load_framework
from app.services.live_ssp import live_ssp_control_detail, live_ssp_snapshot

router = APIRouter(prefix="/api/compliance/ssp", tags=["compliance"])


def _ensure_framework(framework_id: str) -> None:
    try:
        load_framework(framework_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.get("/{framework_id}/live")
async def api_live_ssp(framework_id: str, user: Annotated[AuthUser, Depends(require_user)]):
    """Full live SSP snapshot for one framework, recomputed now."""
    _ensure_framework(framework_id)
    return live_ssp_snapshot(user.id, framework_id)


@router.get("/{framework_id}/live/{control_id}")
async def api_live_ssp_control(
    framework_id: str, control_id: str, user: Annotated[AuthUser, Depends(require_user)]
):
    """One control's live SSP entry."""
    _ensure_framework(framework_id)
    result = live_ssp_control_detail(user.id, framework_id, control_id)
    if not result:
        raise HTTPException(status_code=404, detail="Control not found")
    return result
