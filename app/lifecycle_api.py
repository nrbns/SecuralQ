"""Commercial lifecycle API — GDPR, retention, quotas, MSSP, status, audit chain, KMS, WebAuthn."""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from app.auth import AuthUser
from app.commercial_api import require_user
from app.rbac import require_perm

router = APIRouter(prefix="/api", tags=["commercial-lifecycle"])


# ----- GDPR -----


@router.get("/gdpr/export")
async def api_gdpr_export(user: Annotated[AuthUser, Depends(require_user)]):
    """Art.15/20 portable export for the calling user."""
    from app.gdpr import export_subject

    return export_subject(user.id)


class GdprEraseRequest(BaseModel):
    confirm: str = Field(..., description="Must equal DELETE")
    target_user_id: str | None = None


@router.post("/gdpr/erase")
async def api_gdpr_erase(
    req: GdprEraseRequest,
    user: Annotated[AuthUser, Depends(require_user)],
):
    """Art.17 erasure. Users may erase themselves; admins may erase others."""
    if req.confirm != "DELETE":
        raise HTTPException(status_code=400, detail="confirm must be DELETE")
    target = (req.target_user_id or user.id).strip()
    if target != user.id:
        require_perm(user, "org.manage", org_id=None)
    from app.gdpr import erase_subject

    return erase_subject(target)


# ----- Retention -----


@router.post("/admin/retention/purge")
async def api_retention_purge(
    user: Annotated[AuthUser, Depends(require_user)],
    dry_run: bool = True,
):
    require_perm(user, "settings.write", org_id=None)
    from app.retention import purge_expired

    return purge_expired(dry_run=dry_run)


# ----- Quotas -----


@router.get("/orgs/{org_id}/quotas")
async def api_org_quotas(org_id: str, user: Annotated[AuthUser, Depends(require_user)]):
    require_perm(user, "workspace.read", org_id=org_id)
    from app.tenant_quotas import usage

    return usage(org_id, user.id)


class QuotaUpdate(BaseModel):
    max_agents: int | None = None
    max_upload_mb: int | None = None
    max_scans_per_day: int | None = None
    api_per_minute: int | None = None


@router.put("/orgs/{org_id}/quotas")
async def api_set_org_quotas(
    org_id: str,
    req: QuotaUpdate,
    user: Annotated[AuthUser, Depends(require_user)],
):
    require_perm(user, "org.manage", org_id=org_id)
    from app.tenant_quotas import set_quotas

    return set_quotas(org_id, **req.model_dump(exclude_none=True))


# ----- Audit chain -----


@router.get("/admin/audit/verify-chain")
async def api_verify_audit_chain(user: Annotated[AuthUser, Depends(require_user)], limit: int = 5000):
    require_perm(user, "audit.read", org_id=None)
    from app.audit_chain import verify_chain

    return verify_chain(limit=limit)


@router.post("/admin/audit/backfill-chain")
async def api_backfill_audit_chain(user: Annotated[AuthUser, Depends(require_user)], limit: int = 50000):
    require_perm(user, "settings.write", org_id=None)
    from app.audit_chain import backfill_chain, verify_chain

    filled = backfill_chain(limit=limit)
    filled["verify"] = verify_chain(limit=min(limit, 10000))
    return filled


# ----- Object storage / KMS status -----


@router.get("/admin/object-storage/status")
async def api_object_storage_status(user: Annotated[AuthUser, Depends(require_user)]):
    require_perm(user, "settings.write", org_id=None)
    from app.object_storage import status

    return status()


@router.get("/admin/kms/status")
async def api_kms_status(user: Annotated[AuthUser, Depends(require_user)]):
    require_perm(user, "settings.write", org_id=None)
    from app.kms import status

    return status()


@router.get("/admin/mtls/fleet-status")
async def api_mtls_fleet_status(user: Annotated[AuthUser, Depends(require_user)]):
    require_perm(user, "settings.write", org_id=None)
    from app.agent_certs import fleet_mtls_status

    return fleet_mtls_status()


@router.get("/auth/saml/status")
async def api_saml_status(user: Annotated[AuthUser, Depends(require_user)]):
    from app.saml_scaffold import status

    return status()


@router.get("/auth/saml/metadata")
async def api_saml_metadata():
    from fastapi.responses import Response

    from app.saml_scaffold import sp_metadata

    return Response(content=sp_metadata(), media_type="application/samlmetadata+xml")


class SamlAcsBody(BaseModel):
    SAMLResponse: str = ""
    saml_response: str = ""
    RelayState: str = ""


@router.post("/auth/saml/acs")
async def api_saml_acs(req: SamlAcsBody, user: Annotated[AuthUser, Depends(require_user)]):
    from app.saml_scaffold import receive_acs

    try:
        return receive_acs(req.model_dump(), actor=user.id)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/export/pptx")
async def api_export_pptx(user: Annotated[AuthUser, Depends(require_user)]):
    """#221 — download a one-slide executive PPTX."""
    from pathlib import Path

    from fastapi.responses import FileResponse

    from app.config import settings
    from app.pptx_export import build_executive_pptx

    out = Path(settings.data_dir) / "exports" / f"exec-{user.id[:8]}.pptx"
    bullets = ["SecuraIQ posture export", f"Generated for user {user.username}"]
    try:
        from app.db import get_conn

        n = get_conn().execute("SELECT COUNT(*) AS n FROM securaiq_agents").fetchone()
        bullets.append(f"Agents enrolled: {int(n['n'] if n else 0)}")
    except Exception:
        pass
    build_executive_pptx(out, title="SecuraIQ Executive Summary", bullets=bullets)
    return FileResponse(
        path=str(out),
        filename="securaiq-executive.pptx",
        media_type="application/vnd.openxmlformats-officedocument.presentationml.presentation",
    )


class CanaryUpgradeRequest(BaseModel):
    agent_ids: list[str]
    ring_sizes: list[int] | None = None


@router.post("/agents/canary-upgrade")
async def api_canary_upgrade(
    req: CanaryUpgradeRequest,
    user: Annotated[AuthUser, Depends(require_user)],
):
    require_perm(user, "agent.command", org_id=None)
    from app.agents import create_upgrade_canary_campaign

    try:
        return create_upgrade_canary_campaign(
            user.id,
            agent_ids=req.agent_ids,
            ring_sizes=req.ring_sizes,
            requested_by=user.id,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


# ----- MSSP -----


class MsspLinkRequest(BaseModel):
    child_org_id: str


@router.post("/mssp/{parent_org_id}/link")
async def api_mssp_link(
    parent_org_id: str,
    req: MsspLinkRequest,
    user: Annotated[AuthUser, Depends(require_user)],
):
    require_perm(user, "org.manage", org_id=parent_org_id)
    from app.mssp import link_child

    try:
        return link_child(parent_org_id, req.child_org_id, actor_user_id=user.id)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/mssp/{org_id}/children")
async def api_mssp_children(org_id: str, user: Annotated[AuthUser, Depends(require_user)]):
    require_perm(user, "workspace.read", org_id=org_id)
    from app.mssp import mssp_status

    return mssp_status(org_id)


# ----- WebAuthn -----


@router.get("/auth/webauthn/status")
async def api_webauthn_status(user: Annotated[AuthUser, Depends(require_user)]):
    from app.webauthn_scaffold import status

    return status(user.id)


@router.post("/auth/webauthn/register/begin")
async def api_webauthn_reg_begin(user: Annotated[AuthUser, Depends(require_user)]):
    from app.webauthn_scaffold import begin_registration

    try:
        return begin_registration(user.id, user.username)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


class WebAuthnFinish(BaseModel):
    credential_id: str
    public_key_cose: str = ""
    nickname: str = "passkey"


@router.post("/auth/webauthn/register/finish")
async def api_webauthn_reg_finish(
    req: WebAuthnFinish,
    user: Annotated[AuthUser, Depends(require_user)],
):
    from app.webauthn_scaffold import finish_registration

    try:
        return finish_registration(
            user.id,
            credential_id=req.credential_id,
            public_key_cose=req.public_key_cose,
            nickname=req.nickname,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


# ----- Public status (no auth) -----


@router.get("/status/public")
async def api_public_status():
    """Public status page payload (#244) — no secrets."""
    from app.config import settings

    checks: dict[str, Any] = {"api": "ok"}
    try:
        from app.db import get_conn

        get_conn().execute("SELECT 1").fetchone()
        checks["database"] = "ok"
    except Exception:
        checks["database"] = "degraded"
    try:
        from app.redis_client import redis_enabled

        checks["redis"] = "ok" if redis_enabled() else "not_configured"
    except Exception:
        checks["redis"] = "unknown"
    overall = "operational" if checks.get("database") == "ok" else "degraded"
    return {
        "product": "SecuraIQ",
        "status": overall,
        "checks": checks,
        "deployment_mode": getattr(settings, "deployment_mode", "lab"),
        "psirt": "security@securaiq.example",
        "docs": "/status.html",
    }
