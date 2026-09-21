"""HTTP API for human attestations (Who/What/When/Evidence/Decision)."""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Depends, Header, HTTPException
from pydantic import BaseModel, Field

from app.auth import AuthUser
from app.commercial_api import require_user
from app.rbac import require_perm
from app.services.human_attestation import get_attestation, list_attestations, record_attestation
from app.services.tenancy import resolve_request_org

router = APIRouter(prefix="/api/attestations", tags=["human-attestations"])


class AttestationIn(BaseModel):
    subject_type: str = Field(min_length=1, max_length=40)
    decision: str = Field(min_length=1, max_length=40)
    title: str = ""
    subject_id: str = ""
    submitted_by: str = ""
    comment: str = ""
    evidence_ids: list[str] = Field(default_factory=list)
    framework_id: str = ""
    control_id: str = ""
    meta: dict[str, Any] = Field(default_factory=dict)


@router.get("")
async def api_list_attestations(
    user: Annotated[AuthUser, Depends(require_user)],
    subject_type: str = "",
    subject_id: str = "",
    decision: str = "",
    limit: int = 100,
    org_id: str | None = None,
    x_securaiq_org: str | None = Header(default=None, alias="X-SecuraIQ-Org"),
):
    oid = resolve_request_org(user, org_id=org_id, header_org=x_securaiq_org)
    require_perm(user, "risk.read", org_id=oid)
    return {
        "ok": True,
        "attestations": list_attestations(
            user.id,
            subject_type=subject_type,
            subject_id=subject_id,
            decision=decision,
            limit=limit,
            org_id=oid,
        ),
        "org_id": oid,
    }


@router.post("")
async def api_create_attestation(
    body: AttestationIn,
    user: Annotated[AuthUser, Depends(require_user)],
    x_securaiq_org: str | None = Header(default=None, alias="X-SecuraIQ-Org"),
):
    oid = resolve_request_org(user, header_org=x_securaiq_org)
    require_perm(user, "risk.write", org_id=oid)
    try:
        return record_attestation(
            user.id,
            subject_type=body.subject_type,
            decision=body.decision,
            title=body.title,
            subject_id=body.subject_id,
            submitted_by=body.submitted_by or user.id,
            reviewed_by=user.id,
            comment=body.comment,
            evidence_ids=body.evidence_ids,
            framework_id=body.framework_id,
            control_id=body.control_id,
            meta=body.meta,
            org_id=oid,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/{attestation_id}")
async def api_get_attestation(
    attestation_id: str,
    user: Annotated[AuthUser, Depends(require_user)],
    x_securaiq_org: str | None = Header(default=None, alias="X-SecuraIQ-Org"),
):
    oid = resolve_request_org(user, header_org=x_securaiq_org)
    require_perm(user, "risk.read", org_id=oid)
    row = get_attestation(user.id, attestation_id)
    if not row:
        raise HTTPException(status_code=404, detail="attestation not found")
    return row
