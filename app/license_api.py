"""License / entitlement API — plans, current entitlements, issue signed licenses."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from app.auth import AuthUser
from app.commercial_api import require_user
from app.db import audit
from app.license_service import (
    check_agent_enrollment_allowed,
    effective_entitlements,
    issue_license,
    plan_catalog,
)
from app.rbac import require_perm
from app.tenancy import optional_org_header, resolve_request_org

router = APIRouter(prefix="/api/licenses", tags=["licenses"])


def _org_for(user: AuthUser, org_id: str | None) -> str | None:
    try:
        return resolve_request_org(user, org_id)
    except Exception:
        return (org_id or "").strip() or None


def _require_license_admin(user: AuthUser, org_id: str | None) -> None:
    """Prefer org.manage; global admin always allowed."""
    try:
        require_perm(user, "org.manage", org_id=org_id)
        return
    except HTTPException:
        pass
    if getattr(user, "role", None) in ("admin", "owner") or getattr(user, "id", None) == "local":
        return
    raise HTTPException(status_code=403, detail="org.manage required to issue licenses")


@router.get("/plans")
async def licenses_plans():
    """Public plan catalog (max_agents + feature entitlements)."""
    return {"plans": plan_catalog()}


@router.get("/entitlements")
async def licenses_entitlements(
    user: Annotated[AuthUser, Depends(require_user)],
    header_org: Annotated[str | None, Depends(optional_org_header)] = None,
    org_id: str | None = None,
):
    oid = _org_for(user, org_id or header_org)
    ent = effective_entitlements(user.id, org_id=oid)
    allowed, reason, quota = check_agent_enrollment_allowed(user.id, org_id=oid)
    return {
        **ent,
        "org_id": oid,
        "enrollment_allowed": allowed,
        "enrollment_reason": reason,
        "agents_current": quota.get("agents_current", 0),
    }


@router.get("/current")
async def licenses_current(
    user: Annotated[AuthUser, Depends(require_user)],
    header_org: Annotated[str | None, Depends(optional_org_header)] = None,
    org_id: str | None = None,
):
    """Alias for entitlements + enroll gate (dashboard-friendly)."""
    return await licenses_entitlements(user, header_org=header_org, org_id=org_id)


class IssueLicenseRequest(BaseModel):
    plan: str = "free"
    org_id: str | None = None
    max_agents: int | None = None
    features: list[str] | None = None
    expires_at: float | None = None
    grace_days: int = Field(default=14, ge=0, le=365)


@router.post("/issue")
async def licenses_issue(
    req: IssueLicenseRequest,
    user: Annotated[AuthUser, Depends(require_user)],
    header_org: Annotated[str | None, Depends(optional_org_header)] = None,
):
    """Issue a signed org/user license (operator/admin). Soft catalog — not Stripe checkout."""
    oid = _org_for(user, req.org_id or header_org)
    _require_license_admin(user, oid)

    plan = (req.plan or "free").strip().lower()
    if plan not in plan_catalog():
        raise HTTPException(status_code=400, detail=f"unknown plan: {plan}")

    lic = issue_license(
        user.id,
        org_id=oid,
        plan=plan,
        max_agents=req.max_agents,
        features=req.features,
        expires_at=req.expires_at,
        grace_days=req.grace_days,
    )
    audit(
        "license_issue",
        user.id,
        {"license_id": lic.get("id"), "plan": plan, "org_id": oid, "max_agents": lic.get("max_agents")},
    )
    return {"license": lic, "entitlements": effective_entitlements(user.id, org_id=oid)}
