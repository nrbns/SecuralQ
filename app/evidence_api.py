"""API routes for the Evidence Store — see app/services/evidence.py for what
this is and why it exists. Thin router, same pattern as the other *_api.py
modules: authenticate, call through, return.
"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, Header, HTTPException

from app.auth import AuthUser
from app.commercial_api import require_user
from app.services.evidence import confirm_evidence, get_evidence_for, list_evidence
from app.tenancy import resolve_request_org

router = APIRouter(prefix="/api/evidence", tags=["evidence"])


@router.get("")
async def api_list_evidence(
    user: Annotated[AuthUser, Depends(require_user)],
    entity_type: str = "",
    source: str = "",
    verified: bool | None = None,
    limit: int = 200,
    x_securaiq_org: str | None = Header(default=None, alias="X-SecuraIQ-Org"),
):
    oid = resolve_request_org(user, org_id=None, header_org=x_securaiq_org)
    return {
        "evidence": list_evidence(
            user.id, entity_type=entity_type, source=source, verified=verified, limit=limit, org_id=oid
        ),
        "org_id": oid,
    }


@router.get("/{entity_type}/{entity_id}")
async def api_get_evidence_for(
    entity_type: str,
    entity_id: str,
    user: Annotated[AuthUser, Depends(require_user)],
    limit: int = 100,
    x_securaiq_org: str | None = Header(default=None, alias="X-SecuraIQ-Org"),
):
    """The full evidence trail for one entity -- what answers 'why did
    SecuraIQ say that?' for a given threat/remediation plan/asset
    dependency/etc."""
    oid = resolve_request_org(user, org_id=None, header_org=x_securaiq_org)
    return {
        "evidence": get_evidence_for(
            user.id, entity_type=entity_type, entity_id=entity_id, limit=limit, org_id=oid
        ),
        "org_id": oid,
    }


@router.post("/{evidence_id}/confirm")
async def api_confirm_evidence(evidence_id: str, user: Annotated[AuthUser, Depends(require_user)]):
    """A human vouches for a non-declared piece of evidence. The only way a
    record's verified flag flips outside of source='declared'."""
    result = confirm_evidence(user.id, evidence_id, confirmed_by=user.id)
    if not result:
        raise HTTPException(status_code=404, detail="Evidence not found")
    return result
