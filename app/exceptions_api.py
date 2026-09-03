"""API routes for Compliance Exceptions -- see app/services/exceptions.py for
the rules (every exception is bounded, owned, and expires; approval is an
explicit human action). Thin router, same pattern as the other *_api.py
modules: authenticate, call through, return.
"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from app.auth import AuthUser
from app.commercial_api import require_user
from app.services.exceptions import (
    approve_exception,
    create_exception,
    delete_exception,
    exceptions_summary,
    get_exception,
    list_exceptions,
    reject_exception,
    revoke_exception,
    update_exception,
)

router = APIRouter(prefix="/api/exceptions", tags=["compliance-exceptions"])


class ExceptionCreate(BaseModel):
    title: str = Field(min_length=1, max_length=300)
    reason: str = Field(min_length=1, max_length=4000)
    risk_accepted: str = Field(min_length=1, max_length=4000)
    owner: str = Field(min_length=1, max_length=200)
    expiry: float
    risk_level: str = "medium"
    framework_id: str = ""
    control_id: str = ""
    compensating_controls: str = ""
    review_date: float | None = None
    org_id: str | None = None


class ExceptionUpdate(BaseModel):
    title: str | None = None
    reason: str | None = None
    risk_accepted: str | None = None
    risk_level: str | None = None
    owner: str | None = None
    compensating_controls: str | None = None
    framework_id: str | None = None
    control_id: str | None = None
    expiry: float | None = None
    review_date: float | None = None


class RejectBody(BaseModel):
    reason: str = ""


@router.get("")
async def api_list_exceptions(
    user: Annotated[AuthUser, Depends(require_user)],
    status: str | None = None,
    org_id: str | None = None,
):
    try:
        return {"exceptions": list_exceptions(user.id, org_id=org_id, status=status)}
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/summary")
async def api_exceptions_summary(
    user: Annotated[AuthUser, Depends(require_user)], org_id: str | None = None
):
    return exceptions_summary(user.id, org_id=org_id)


@router.post("")
async def api_create_exception(body: ExceptionCreate, user: Annotated[AuthUser, Depends(require_user)]):
    try:
        return create_exception(user.id, created_by=user.id, **body.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/{exception_id}")
async def api_get_exception(exception_id: str, user: Annotated[AuthUser, Depends(require_user)]):
    result = get_exception(user.id, exception_id)
    if not result:
        raise HTTPException(status_code=404, detail="Exception not found")
    return result


@router.patch("/{exception_id}")
async def api_update_exception(
    exception_id: str, body: ExceptionUpdate, user: Annotated[AuthUser, Depends(require_user)]
):
    try:
        result = update_exception(user.id, exception_id, body.model_dump(exclude_unset=True))
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    if not result:
        raise HTTPException(status_code=404, detail="Exception not found")
    return result


@router.post("/{exception_id}/approve")
async def api_approve_exception(exception_id: str, user: Annotated[AuthUser, Depends(require_user)]):
    try:
        result = approve_exception(user.id, exception_id, approved_by=user.id)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    if not result:
        raise HTTPException(status_code=404, detail="Exception not found")
    return result


@router.post("/{exception_id}/reject")
async def api_reject_exception(
    exception_id: str, body: RejectBody, user: Annotated[AuthUser, Depends(require_user)]
):
    result = reject_exception(user.id, exception_id, rejected_by=user.id, reason=body.reason)
    if not result:
        raise HTTPException(status_code=404, detail="Exception not found")
    return result


@router.post("/{exception_id}/revoke")
async def api_revoke_exception(exception_id: str, user: Annotated[AuthUser, Depends(require_user)]):
    result = revoke_exception(user.id, exception_id, revoked_by=user.id)
    if not result:
        raise HTTPException(status_code=404, detail="Exception not found")
    return result


@router.delete("/{exception_id}")
async def api_delete_exception(exception_id: str, user: Annotated[AuthUser, Depends(require_user)]):
    if not delete_exception(user.id, exception_id):
        raise HTTPException(status_code=404, detail="Exception not found")
    return {"ok": True}
