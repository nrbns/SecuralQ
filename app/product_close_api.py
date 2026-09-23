"""APIs that close remaining lab-unblocked product rows."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from app.auth import AuthUser
from app.commercial_api import require_user
from app.product_close import list_evidence_lineage, onboarding_progress, roi_metrics, tamper_status
from app.service_accounts import (
    create_service_account,
    list_service_accounts,
    revoke_service_account,
    rotate_service_account,
)
from app.trust_center import trust_center_payload

router = APIRouter(tags=["product-close"])


class ServiceAccountIn(BaseModel):
    name: str = Field(min_length=1, max_length=80)
    scopes: list[str] = Field(default_factory=list)


@router.get("/api/trust")
async def api_trust_center():
    return trust_center_payload()


@router.get("/api/tamper")
async def api_tamper(user: Annotated[AuthUser, Depends(require_user)]):
    return tamper_status(user.id)


@router.get("/api/onboarding/progress")
async def api_onboarding(user: Annotated[AuthUser, Depends(require_user)]):
    return onboarding_progress(user.id)


@router.get("/api/roi")
async def api_roi(user: Annotated[AuthUser, Depends(require_user)]):
    return roi_metrics(user.id)


@router.get("/api/evidence-spine/lineage")
async def api_evidence_lineage(
    user: Annotated[AuthUser, Depends(require_user)],
    limit: int = 50,
):
    return {"ok": True, "events": list_evidence_lineage(user.id, limit=limit)}


@router.post("/api/service-accounts")
async def api_sa_create(body: ServiceAccountIn, user: Annotated[AuthUser, Depends(require_user)]):
    raw, meta = create_service_account(user.id, body.name, body.scopes)
    return {"token": raw, **meta, "note": "Store this token now — it will not be shown again."}


@router.get("/api/service-accounts")
async def api_sa_list(user: Annotated[AuthUser, Depends(require_user)]):
    return {"ok": True, "accounts": list_service_accounts(user.id)}


@router.post("/api/service-accounts/{key_id}/revoke")
async def api_sa_revoke(key_id: str, user: Annotated[AuthUser, Depends(require_user)]):
    if not revoke_service_account(user.id, key_id):
        raise HTTPException(status_code=404, detail="service account not found")
    return {"ok": True, "id": key_id, "revoked": True}


@router.post("/api/service-accounts/{key_id}/rotate")
async def api_sa_rotate(key_id: str, user: Annotated[AuthUser, Depends(require_user)]):
    out = rotate_service_account(user.id, key_id)
    if not out:
        raise HTTPException(status_code=404, detail="service account not found")
    raw, meta = out
    return {"token": raw, **meta, "note": "Store this token now — it will not be shown again."}
