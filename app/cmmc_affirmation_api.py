"""API routes for CMMC / SPRS self-assessment affirmation tracking -- see
app/services/cmmc_affirmation.py for the rules (score/date/official are all
user-attested; SecuraIQ computes only the two due dates). Thin router, same
pattern as exceptions_api.py: authenticate, call through, return.
"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from app.auth import AuthUser
from app.commercial_api import require_user
from app.services.cmmc_affirmation import (
    create_affirmation,
    delete_affirmation,
    get_affirmation,
    latest_affirmation,
    list_affirmations,
)

router = APIRouter(prefix="/api/cmmc/affirmations", tags=["cmmc-affirmation"])


class AffirmationCreate(BaseModel):
    level: str = Field(min_length=1, max_length=20)
    assessment_date: float
    affirming_official: str = Field(min_length=1, max_length=200)
    score: int | None = None
    framework_id: str = "cmmc_l2"
    assessment_id: str | None = None
    notes: str = ""
    org_id: str | None = None


@router.get("")
async def api_list_affirmations(
    user: Annotated[AuthUser, Depends(require_user)],
    framework_id: str | None = None,
):
    return {"affirmations": list_affirmations(user.id, framework_id=framework_id)}


@router.get("/latest")
async def api_latest_affirmation(
    user: Annotated[AuthUser, Depends(require_user)],
    framework_id: str = "cmmc_l2",
):
    return {"affirmation": latest_affirmation(user.id, framework_id=framework_id)}


@router.post("")
async def api_create_affirmation(body: AffirmationCreate, user: Annotated[AuthUser, Depends(require_user)]):
    try:
        return create_affirmation(user.id, **body.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/{affirmation_id}")
async def api_get_affirmation(affirmation_id: str, user: Annotated[AuthUser, Depends(require_user)]):
    result = get_affirmation(user.id, affirmation_id)
    if not result:
        raise HTTPException(status_code=404, detail="Affirmation not found")
    return result


@router.delete("/{affirmation_id}")
async def api_delete_affirmation(affirmation_id: str, user: Annotated[AuthUser, Depends(require_user)]):
    if not delete_affirmation(user.id, affirmation_id):
        raise HTTPException(status_code=404, detail="Affirmation not found")
    return {"ok": True}
