"""API routes for generalized per-framework compliance attestation tracking
-- see app/services/compliance_attestation.py for the rules (attesting
official/date/notes are all user-attested; SecuraIQ computes only the two due
dates from the framework's cadence profile). cmmc_l2 keeps its own dedicated
router at /api/cmmc/affirmations (app/cmmc_affirmation_api.py) since it models
an official numeric SPRS score this generic module does not. Thin router,
same pattern as cmmc_affirmation_api.py: authenticate, call through, return.
"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from app.auth import AuthUser
from app.commercial_api import require_user
from app.services.compliance_attestation import (
    attestation_profile,
    create_attestation,
    delete_attestation,
    get_attestation,
    latest_attestation,
    list_attestations,
)

router = APIRouter(prefix="/api/compliance/attestations", tags=["compliance-attestation"])


class AttestationCreate(BaseModel):
    framework_id: str = Field(min_length=1, max_length=64)
    assessment_date: float
    attesting_official: str = Field(min_length=1, max_length=200)
    assessment_id: str | None = None
    notes: str = ""
    org_id: str | None = None


@router.get("/profile/{framework_id}")
async def api_attestation_profile(framework_id: str, _user: Annotated[AuthUser, Depends(require_user)]):
    """The attestation label, cadence, and cadence-source note for a
    framework -- lets the UI show the right terminology (e.g. 'Management
    review sign-off' for iso27001 vs 'SAQ / Attestation of Compliance' for
    pci_dss) before the user creates a record."""
    return attestation_profile(framework_id)


@router.get("")
async def api_list_attestations(
    user: Annotated[AuthUser, Depends(require_user)],
    framework_id: str | None = None,
):
    return {"attestations": list_attestations(user.id, framework_id=framework_id)}


@router.get("/latest")
async def api_latest_attestation(
    user: Annotated[AuthUser, Depends(require_user)],
    framework_id: str,
):
    return {"attestation": latest_attestation(user.id, framework_id=framework_id)}


@router.post("")
async def api_create_attestation(body: AttestationCreate, user: Annotated[AuthUser, Depends(require_user)]):
    try:
        return create_attestation(user.id, **body.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/{attestation_id}")
async def api_get_attestation(attestation_id: str, user: Annotated[AuthUser, Depends(require_user)]):
    result = get_attestation(user.id, attestation_id)
    if not result:
        raise HTTPException(status_code=404, detail="Attestation not found")
    return result


@router.delete("/{attestation_id}")
async def api_delete_attestation(attestation_id: str, user: Annotated[AuthUser, Depends(require_user)]):
    if not delete_attestation(user.id, attestation_id):
        raise HTTPException(status_code=404, detail="Attestation not found")
    return {"ok": True}
