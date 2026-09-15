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
    check_feature,
    effective_entitlements,
    issue_license,
    issue_trial_license,
    plan_catalog,
    revoke_license,
    validate_license,
)
from app.rbac import require_perm
from app.tenancy import optional_org_header, resolve_request_org

router = APIRouter(prefix="/api/licenses", tags=["licenses"])
entitlements_router = APIRouter(prefix="/api/entitlements", tags=["entitlements"])
admin_licenses_router = APIRouter(prefix="/api/admin/licenses", tags=["admin-licenses"])


def _org_for(user: AuthUser, org_id: str | None) -> str | None:
    try:
        return resolve_request_org(user, org_id=org_id)
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


@router.get("/commercial-status")
async def licenses_commercial_status(
    user: Annotated[AuthUser, Depends(require_user)],
    header_org: Annotated[str | None, Depends(optional_org_header)] = None,
    org_id: str | None = None,
):
    """Phase B UI: activation + usage + validation (server is license truth)."""
    from app import licensing

    oid = _org_for(user, org_id or header_org)
    return licensing.commercial_licensing_status(user.id, org_id=oid)


class RenewLicenseRequest(BaseModel):
    plan: str | None = None
    org_id: str | None = None
    days: int = Field(default=365, ge=1, le=1095)


@router.post("/renew")
async def licenses_renew(
    req: RenewLicenseRequest,
    user: Annotated[AuthUser, Depends(require_user)],
    header_org: Annotated[str | None, Depends(optional_org_header)] = None,
):
    """Renew by issuing a new signed entitlement (supersedes prior active)."""
    from app import licensing

    oid = _org_for(user, req.org_id or header_org)
    _require_license_admin(user, oid)
    out = licensing.renew_subscription(user.id, org_id=oid, plan=req.plan, days=req.days)
    audit("license_renew", user.id, {"org_id": oid, "plan": req.plan, "days": req.days})
    return out


@router.post("/validate")
@router.get("/validate")
async def licenses_validate(
    user: Annotated[AuthUser, Depends(require_user)],
    header_org: Annotated[str | None, Depends(optional_org_header)] = None,
    org_id: str | None = None,
):
    """Online license validation — cache locally, never trust local cache as SoT.

    Agents and dashboards should call this periodically (e.g. every 24h). Offline
    grace is returned in the payload; do not brick agents on transient outages.
    """
    oid = _org_for(user, org_id or header_org)
    result = validate_license(user.id, org_id=oid)
    audit("license_validate", user.id, {"org_id": oid, "mode": result.get("mode"), "valid": result.get("valid")})
    return result


class TrialLicenseRequest(BaseModel):
    plan: str = "pro"
    org_id: str | None = None
    days: int = Field(default=30, ge=1, le=365)


@router.post("/trial")
async def licenses_trial(
    req: TrialLicenseRequest,
    user: Annotated[AuthUser, Depends(require_user)],
    header_org: Annotated[str | None, Depends(optional_org_header)] = None,
):
    """Issue a signed N-day trial (default 30 days)."""
    oid = _org_for(user, req.org_id or header_org)
    _require_license_admin(user, oid)
    plan = (req.plan or "pro").strip().lower()
    if plan not in plan_catalog() or plan == "free":
        raise HTTPException(status_code=400, detail="trial plan must be a paid catalog plan")
    lic = issue_trial_license(user.id, org_id=oid, plan=plan, days=req.days)
    audit("license_trial", user.id, {"license_id": lic.get("id"), "plan": plan, "days": req.days, "org_id": oid})
    return {
        "license": lic,
        "validation": validate_license(user.id, org_id=oid),
    }


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


@entitlements_router.get("/check")
async def entitlements_check(
    feature: str,
    user: Annotated[AuthUser, Depends(require_user)],
    header_org: Annotated[str | None, Depends(optional_org_header)] = None,
    org_id: str | None = None,
):
    """Fast feature-gate check for UI/API (upgrade messaging)."""
    if not (feature or "").strip():
        raise HTTPException(status_code=400, detail="feature query param required")
    oid = _org_for(user, org_id or header_org)
    return check_feature(user.id, feature.strip(), org_id=oid)


@admin_licenses_router.post("/{license_id}/revoke")
async def admin_license_revoke(
    license_id: str,
    user: Annotated[AuthUser, Depends(require_user)],
):
    _require_license_admin(user, None)
    lic = revoke_license(user.id, license_id)
    if not lic:
        raise HTTPException(status_code=404, detail="License not found")
    audit("license_revoke", user.id, {"license_id": license_id})
    return {"ok": True, "license": lic}
