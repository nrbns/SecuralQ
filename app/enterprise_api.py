"""Enterprise workflow APIs: risks, assets, vulnerabilities, remediations."""

from __future__ import annotations

import re
from typing import Annotated

from fastapi import APIRouter, Depends, File, Header, HTTPException, UploadFile
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel, Field

from app.auth import AuthUser
from app.commercial_api import require_user
from app.rbac import require_perm
from app.services.tenancy import resolve_request_org
from app.services.assets import (
    create_asset,
    delete_asset,
    list_assets,
    update_asset,
)
from app.services.findings import (
    get_vulnerability,
    import_vulnerabilities,
    list_vulnerabilities,
    triage_vulnerability,
    update_vulnerability,
)
from app.services.risk import (
    compute_risk_score,
    create_risk,
    delete_risk,
    explain_risk_score,
    list_risks,
    update_risk,
)
from app.services.investigation import investigate_scan, investigate_top_assets
from app.enterprise import (
    create_campaign,
    create_playbook,
    create_remediation,
    delete_campaign,
    delete_playbook,
    enterprise_dashboard,
    evidence_from_files,
    export_risk_markdown,
    export_vuln_markdown,
    list_campaigns,
    list_playbooks,
    list_remediations,
    update_campaign,
    update_playbook,
    update_remediation,
)
from app.gap_analysis import ensure_gap_schema, run_gap_analysis

router = APIRouter(prefix="/api", tags=["enterprise"])


class AssetCreate(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    asset_type: str = "server"
    criticality: str = "medium"
    owner: str = ""
    notes: str = ""
    engagement_id: str | None = None


class AssetUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=200)
    asset_type: str | None = None
    criticality: str | None = None
    owner: str | None = None
    notes: str | None = None
    engagement_id: str | None = None


class RiskCreate(BaseModel):
    threat: str = Field(min_length=1, max_length=500)
    vulnerability: str = ""
    asset_name: str = ""
    asset_id: str | None = None
    impact: int = Field(default=3, ge=1, le=5)
    likelihood: int = Field(default=3, ge=1, le=5)
    owner: str = ""
    mitigation: str = ""
    status: str = "open"
    engagement_id: str | None = None


class RiskUpdate(BaseModel):
    threat: str | None = None
    vulnerability: str | None = None
    asset_name: str | None = None
    impact: int | None = Field(default=None, ge=1, le=5)
    likelihood: int | None = Field(default=None, ge=1, le=5)
    owner: str | None = None
    mitigation: str | None = None
    status: str | None = None


class VulnUpdate(BaseModel):
    status: str | None = None
    owner: str | None = None
    sla_due: str | None = None
    severity: str | None = None
    title: str | None = None
    asset_name: str | None = None
    cve: str | None = None


class RemediationUpdate(BaseModel):
    status: str | None = None
    owner: str | None = None
    due_date: str | None = None
    notes: str | None = None


class RemediationCreate(BaseModel):
    title: str = Field(min_length=1, max_length=300)
    control_id: str = "MC"
    owner: str = ""
    due_date: str = ""
    recommendation: str = ""
    engagement_id: str | None = None
    assessment_id: str | None = None


class SoftwareRemediationCreate(BaseModel):
    asset_id: str = ""
    asset_name: str = Field(default="", max_length=200)
    installation_id: str = ""


class PatchVerifyRequest(BaseModel):
    installation_id: str = ""


class GapRunStructured(BaseModel):
    framework_id: str
    evidence: str = ""
    title: str = "Gap assessment"
    engagement_id: str | None = None
    file_ids: list[str] = Field(default_factory=list)
    overrides: dict[str, str] | None = None


class PlaybookCreate(BaseModel):
    title: str = Field(min_length=1, max_length=300)
    category: str = "ir"
    severity: str = "high"
    steps: str = ""
    status: str = "ready"
    owner: str = ""
    engagement_id: str | None = None


class PlaybookUpdate(BaseModel):
    title: str | None = None
    category: str | None = None
    severity: str | None = None
    steps: str | None = None
    status: str | None = None
    owner: str | None = None
    engagement_id: str | None = None


class CampaignCreate(BaseModel):
    name: str = Field(min_length=1, max_length=300)
    campaign_type: str = "phishing_sim"
    audience: str = ""
    status: str = "planned"
    sent_count: int = Field(default=0, ge=0)
    click_count: int = Field(default=0, ge=0)
    report_count: int = Field(default=0, ge=0)
    notes: str = ""
    engagement_id: str | None = None


class CampaignUpdate(BaseModel):
    name: str | None = None
    campaign_type: str | None = None
    audience: str | None = None
    status: str | None = None
    sent_count: int | None = Field(default=None, ge=0)
    click_count: int | None = Field(default=None, ge=0)
    report_count: int | None = Field(default=None, ge=0)
    notes: str | None = None
    engagement_id: str | None = None


@router.get("/software/posture")
async def software_posture(user: Annotated[AuthUser, Depends(require_user)]):
    require_perm(user, "asset.read")
    from app.software_inventory import empty_posture, inventory_api_payload, posture_summary

    try:
        posture = posture_summary(user.id, rebuild_if_empty=False)
        return inventory_api_payload(user.id, inventory=[], posture=posture)
    except Exception:
        return inventory_api_payload(user.id, inventory=[], posture=empty_posture())


@router.get("/software/summary")
async def software_summary(user: Annotated[AuthUser, Depends(require_user)]):
    """Lightweight KPIs for Software page header — never 500 on empty inventory."""
    require_perm(user, "asset.read")
    from app.software_inventory import empty_posture, inventory_api_payload, posture_summary

    try:
        posture = posture_summary(user.id, rebuild_if_empty=False)
        payload = inventory_api_payload(user.id, inventory=[], posture=posture)
        try:
            from app.software.service import inventory_status, summary_for_user

            engine = summary_for_user(user.id)
            inv = inventory_status(user.id)
            payload["engine"] = engine
            payload["inventory_status"] = inv
            if engine.get("total_installations"):
                payload["total"] = int(engine.get("total_installations") or payload["total"])
        except Exception:
            pass
        return payload
    except Exception:
        return inventory_api_payload(user.id, inventory=[], posture=empty_posture())


@router.get("/inventory/status")
async def inventory_status_api(user: Annotated[AuthUser, Depends(require_user)]):
    require_perm(user, "asset.read")
    from app.software.service import inventory_status

    try:
        return inventory_status(user.id)
    except Exception:
        return {
            "status": "ok",
            "products": 0,
            "installations": 0,
            "last_sync": None,
            "sources_total": 0,
            "sources_healthy": 0,
            "sources": [],
            "message": "No software inventory has been collected yet.",
        }


@router.get("/inventory/sources")
async def inventory_sources_api(user: Annotated[AuthUser, Depends(require_user)]):
    require_perm(user, "asset.read")
    from app.software.service import list_sources

    try:
        return {"status": "ok", "sources": list_sources(user.id)}
    except Exception:
        return {"status": "ok", "sources": []}


@router.post("/inventory/sync")
async def inventory_sync_api(user: Annotated[AuthUser, Depends(require_user)]):
    """Sync normalized inventory from Wazuh, Open-AudIT, scans, and legacy rows."""
    require_perm(user, "asset.write")
    from app.software.service import inventory_status, refresh_wazuh_syscollector, sync_inventory

    syscol = 0
    try:
        syscol = await refresh_wazuh_syscollector(limit_agents=50)
    except Exception:
        pass
    try:
        totals = sync_inventory(user.id, publish=True)
    except Exception as exc:
        return {
            "status": "error",
            "message": str(exc)[:300],
            "syscollector_agents": syscol,
            "inventory": inventory_status(user.id),
        }
    return {
        "status": "ok",
        "syscollector_agents": syscol,
        "sync": totals,
        "inventory": inventory_status(user.id),
    }


@router.get("/software/versions/status")
async def software_versions_status(user: Annotated[AuthUser, Depends(require_user)]):
    require_perm(user, "asset.read")
    from app.software.versions import version_intelligence_status

    try:
        return version_intelligence_status(user.id)
    except Exception:
        return {
            "status": "ok",
            "products_total": 0,
            "products_with_latest": 0,
            "products_stale": 0,
            "last_checked": None,
        }


@router.post("/software/versions/refresh")
async def software_versions_refresh(user: Annotated[AuthUser, Depends(require_user)]):
    """Resolve latest versions from vendor/registry sources (batched, cached)."""
    require_perm(user, "asset.write")
    from app.software.service import sync_inventory
    from app.software.versions import refresh_versions_for_user

    try:
        result = refresh_versions_for_user(user.id)
        sync_inventory(user.id, publish=True)
        return {"status": "ok", "refresh": result}
    except Exception as exc:
        return {"status": "error", "message": str(exc)[:300]}


@router.get("/software/rows")
async def software_rows(
    user: Annotated[AuthUser, Depends(require_user)],
    limit: int = 50,
    asset_id: str | None = None,
    installation_id: str | None = None,
    product: str | None = None,
    canonical_id: str | None = None,
):
    """Fetch specific installation rows for partial SSE UI refresh."""
    require_perm(user, "asset.read")
    from app.software.service import list_legacy_from_engine

    try:
        rows = list_legacy_from_engine(
            user.id,
            limit=limit,
            asset_id=asset_id,
            installation_id=installation_id,
            product=product,
            canonical_id=canonical_id,
        )
        return {"status": "ok", "data": rows, "total": len(rows)}
    except Exception:
        return {"status": "ok", "data": [], "total": 0}


@router.get("/software/advisories")
async def software_advisories_list(
    user: Annotated[AuthUser, Depends(require_user)],
    limit: int = 200,
    critical: bool = False,
):
    require_perm(user, "asset.read")
    from app.software.advisories import advisory_summary, list_advisories

    try:
        return {
            "status": "ok",
            "data": list_advisories(user.id, limit=limit, critical_only=critical),
            "summary": advisory_summary(user.id),
        }
    except Exception:
        return {"status": "ok", "data": [], "summary": {"total_advisories": 0, "kev": 0, "critical": 0}}


@router.get("/software/critical")
async def software_critical_list(
    user: Annotated[AuthUser, Depends(require_user)],
    limit: int = 200,
):
    require_perm(user, "asset.read")
    from app.software.advisories import list_advisories
    from app.software.service import list_legacy_from_engine

    try:
        advisories = list_advisories(user.id, limit=limit, critical_only=True)
        rows = [
            r
            for r in list_legacy_from_engine(user.id, limit=limit)
            if (r.get("patch_status") or "") in {"exploited_kev", "critical_security_update"}
            or (r.get("severity") or "").lower() == "critical"
        ]
        return {"status": "ok", "advisories": advisories, "installations": rows, "total": len(rows)}
    except Exception:
        return {"status": "ok", "advisories": [], "installations": [], "total": 0}


@router.get("/patches/critical")
async def patches_critical(user: Annotated[AuthUser, Depends(require_user)], limit: int = 200):
    """Alias for critical patch posture — installations needing immediate attention."""
    require_perm(user, "asset.read")
    from app.software.advisories import list_advisories
    from app.software.service import list_legacy_from_engine, summary_for_user

    try:
        rows = [
            r
            for r in list_legacy_from_engine(user.id, limit=limit)
            if (r.get("patch_status") or "") in {"exploited_kev", "critical_security_update", "security_update"}
        ]
        return {
            "status": "ok",
            "data": rows,
            "total": len(rows),
            "summary": summary_for_user(user.id),
            "advisories": list_advisories(user.id, limit=50, critical_only=True),
        }
    except Exception:
        return {"status": "ok", "data": [], "total": 0}


@router.get("/software/inventory")
async def software_inventory_list(
    user: Annotated[AuthUser, Depends(require_user)],
    limit: int = 200,
    asset_id: str | None = None,
    status: str | None = None,
    source: str | None = None,
):
    require_perm(user, "asset.read")
    from app.software_inventory import empty_posture, inventory_api_payload, list_software, posture_summary

    try:
        inventory = list_software(
            user.id, limit=limit, asset_id=asset_id, status=status, source=source
        )
        posture = posture_summary(user.id, rebuild_if_empty=False)
        return inventory_api_payload(user.id, inventory=inventory, posture=posture)
    except Exception:
        return inventory_api_payload(user.id, inventory=[], posture=empty_posture())


@router.post("/software/local-refresh")
async def software_local_refresh(user: Annotated[AuthUser, Depends(require_user)]):
    """Refresh this machine's Control Panel registry apps + Windows Updates into inventory."""
    require_perm(user, "asset.write")
    from app.software_inventory import posture_summary
    from app.windows_inventory import refresh_local_windows_host

    refreshed = refresh_local_windows_host(user.id, force=True)
    posture = posture_summary(user.id, rebuild_if_empty=False)
    return {"status": "ok", **refreshed, "posture": posture}


@router.post("/software/rebuild")
async def software_inventory_rebuild(user: Annotated[AuthUser, Depends(require_user)]):
    require_perm(user, "asset.write")
    from app.software_inventory import posture_summary, rebuild_for_user

    counts = rebuild_for_user(user.id)
    return {"rebuilt": counts, "posture": posture_summary(user.id, rebuild_if_empty=False)}


@router.post("/software/sync-all")
async def software_sync_all(user: Annotated[AuthUser, Depends(require_user)]):
    """Queue SIEM/XDR/inventory sync jobs, probe local OS patches, rebuild software inventory."""
    require_perm(user, "asset.write")
    from app.software_inventory import sync_all_and_rebuild

    return sync_all_and_rebuild(user.id, rebuild=True)


@router.get("/software/export")
async def software_export(
    user: Annotated[AuthUser, Depends(require_user)],
    format: str = "md",
):
    require_perm(user, "report.export")
    from app.software_inventory import export_software_csv, export_software_markdown

    fmt = (format or "md").lower()
    if fmt == "csv":
        return PlainTextResponse(
            export_software_csv(user.id),
            media_type="text/csv; charset=utf-8",
            headers={"Content-Disposition": 'attachment; filename="securaiq-software.csv"'},
        )
    return PlainTextResponse(
        export_software_markdown(user.id),
        media_type="text/markdown; charset=utf-8",
    )


@router.get("/patches")
async def patches_list(
    user: Annotated[AuthUser, Depends(require_user)],
    limit: int = 200,
    critical: bool = False,
):
    require_perm(user, "asset.read")
    from app.software.patches import list_patches

    try:
        data = list_patches(user.id, limit=limit, critical_only=critical)
        return {"status": "ok", "data": data, "total": len(data)}
    except Exception:
        return {"status": "ok", "data": [], "total": 0}


@router.get("/patches/{patch_id}")
async def patch_detail_api(
    patch_id: str,
    user: Annotated[AuthUser, Depends(require_user)],
):
    require_perm(user, "asset.read")
    from app.software.patches import get_patch_detail

    try:
        detail = get_patch_detail(user.id, patch_id)
        if not detail:
            return {"status": "ok", "patch": None, "message": "Patch record not found."}
        return detail
    except Exception:
        return {"status": "ok", "patch": None, "message": "Patch record not found."}


@router.post("/patches/{patch_id}/remediation")
async def patch_remediation_create(
    patch_id: str,
    user: Annotated[AuthUser, Depends(require_user)],
):
    require_perm(user, "asset.write")
    from app.software.patches import build_remediation_for_installation

    draft = build_remediation_for_installation(user.id, patch_id)
    return create_remediation(user.id, **draft)


@router.post("/patches/{patch_id}/verify")
async def patch_verify_api(
    patch_id: str,
    user: Annotated[AuthUser, Depends(require_user)],
):
    """Re-inventory and check whether installed version meets target."""
    require_perm(user, "asset.write")
    from app.software.patches import verify_patch

    try:
        return verify_patch(user.id, patch_id)
    except Exception as exc:
        return {"status": "error", "message": str(exc)[:300]}


@router.get("/assets/{asset_id}/software")
async def asset_software_api(
    asset_id: str,
    user: Annotated[AuthUser, Depends(require_user)],
    limit: int = 200,
):
    require_perm(user, "asset.read")
    from app.software.patches import asset_software_detail

    try:
        return asset_software_detail(user.id, asset_id, limit=limit)
    except Exception:
        return {"status": "ok", "asset_id": asset_id, "software": [], "total": 0}


@router.get("/software/product/{key}")
async def software_product_detail(
    key: str,
    user: Annotated[AuthUser, Depends(require_user)],
):
    require_perm(user, "asset.read")
    from app.software.patches import product_detail

    try:
        return product_detail(user.id, key=key)
    except Exception:
        return {"status": "ok", "product": None, "installations": [], "advisories": []}


@router.post("/software/remediations")
async def software_remediation_create(
    req: SoftwareRemediationCreate,
    user: Annotated[AuthUser, Depends(require_user)],
):
    """Create a gap remediation task from server or installation patch posture."""
    require_perm(user, "asset.write")
    if (req.installation_id or "").strip():
        from app.software.patches import build_remediation_for_installation

        draft = build_remediation_for_installation(user.id, req.installation_id.strip())
    else:
        from app.software_inventory import build_remediation_for_server

        draft = build_remediation_for_server(
            user.id, asset_id=req.asset_id, asset_name=req.asset_name
        )
    return create_remediation(user.id, **draft)


@router.get("/dashboard")
async def dashboard(user: Annotated[AuthUser, Depends(require_user)]):
    ensure_gap_schema()
    return enterprise_dashboard(user.id)


@router.get("/dashboard/brief")
async def dashboard_brief(user: Annotated[AuthUser, Depends(require_user)]):
    """Morning Mission Control brief (fast rules engine; model optional later)."""
    ensure_gap_schema()
    dash = enterprise_dashboard(user.id)
    brief = dash.get("morning_brief") or {}
    return {
        "user": user.username,
        "organization": (dash.get("mission_control") or {}).get("organization"),
        "brief": brief,
        "scores": {
            "security": dash.get("security_index"),
            "compliance": dash.get("compliance_score"),
            "critical": dash.get("vulnerabilities_critical_high"),
            "risks": dash.get("risks_open"),
            "incidents": dash.get("incidents_open"),
        },
        "tasks": (dash.get("work_queue") or [])[:5],
    }


class WorkspaceResetRequest(BaseModel):
    clear_rag: bool = False
    confirm: bool = False
    confirm_code: str | None = None


@router.post("/workspace/reset/request-code")
async def workspace_reset_request_code(user: Annotated[AuthUser, Depends(require_user)]):
    """Step 1 of destructive-action approval when AUTH is enabled.

    In open local mode (AUTH_ENABLED=false) the code is also returned in the
    response so the UI can complete a one-click reset on localhost without
    digging through notifications.
    """
    from app.approvals import request_approval
    from app.config import settings as _settings

    result = request_approval(user.id, "workspace_reset", {})
    if not _settings.auth_enabled:
        # Local open mode only — code is still required by /workspace/reset
        from app.db import get_conn

        row = get_conn().execute(
            "SELECT code FROM action_approvals WHERE user_id = ? AND action = ? "
            "AND consumed_at IS NULL ORDER BY created_at DESC LIMIT 1",
            (user.id, "workspace_reset"),
        ).fetchone()
        if row:
            result = {**result, "confirm_code": row["code"] if hasattr(row, "keys") else row[0]}
    return result


@router.post("/workspace/reset")
async def workspace_reset(req: WorkspaceResetRequest, user: Annotated[AuthUser, Depends(require_user)]):
    """Wipe operational data for the current user. Starts Mission Control from zero."""
    from app.approvals import verify_and_consume
    from app.config import settings as _settings
    from app.enterprise import reset_workspace

    code = (req.confirm_code or "").strip()
    if not code or not verify_and_consume(user.id, "workspace_reset", code):
        raise HTTPException(
            status_code=400,
            detail=(
                "Missing or invalid confirmation code. Call POST /api/workspace/reset/request-code first, "
                + (
                    "check your notifications for the code, then resubmit with confirm_code set."
                    if _settings.auth_enabled
                    else "then resubmit with confirm_code (returned in local open mode)."
                )
            ),
        )
    return reset_workspace(user.id, clear_rag=req.clear_rag)


class InvestigateRequest(BaseModel):
    limit: int = Field(default=5, ge=1, le=25)
    engagement_id: str | None = None
    org_id: str | None = None


class InvestigateScanRequest(BaseModel):
    scan_id: str = Field(min_length=8, max_length=80)
    org_id: str | None = None


class RiskScoreRequest(BaseModel):
    cvss: float | None = None
    exploitability: float | None = None
    exposure: float | None = None
    asset_criticality: str | None = "medium"
    threat_intel: float | None = None
    confidence: float | None = None


@router.get("/assets/categories")
async def assets_categories(user: Annotated[AuthUser, Depends(require_user)]):
    require_perm(user, "asset.read")
    from app.asset_categories import list_categories

    return {"categories": list_categories()}


@router.get("/assets")
async def assets_list(
    user: Annotated[AuthUser, Depends(require_user)],
    engagement_id: str | None = None,
    org_id: str | None = None,
    x_securaiq_org: str | None = Header(default=None, alias="X-SecuraIQ-Org"),
):
    oid = resolve_request_org(user, org_id=org_id, header_org=x_securaiq_org)
    require_perm(user, "asset.read", org_id=oid)
    from app.enterprise import enrich_assets_with_scans

    raw = list_assets(user.id, engagement_id, org_id=oid)
    assets, live_scans = enrich_assets_with_scans(user.id, raw)
    return {"assets": assets, "live_scans": live_scans, "org_id": oid}


@router.post("/assets/lan-refresh")
async def assets_lan_refresh(
    user: Annotated[AuthUser, Depends(require_user)],
    x_securaiq_org: str | None = Header(default=None, alias="X-SecuraIQ-Org"),
    scans: bool = True,
):
    """Sweep local /24, upsert neighbors, stream Open-AudIT-style inventory.

    scans=true (default) also queues vulnerability scans for discovered hosts.
    scans=false is inventory-only — same path Tools hub Sync inventory uses.
    """
    oid = resolve_request_org(user, header_org=x_securaiq_org)
    require_perm(user, "asset.write", org_id=oid)
    from app.lan_sync import refresh_lan_assets

    result = refresh_lan_assets(user.id, queue_scan=scans)
    return result


@router.post("/ai/investigate")
async def ai_investigate(
    req: InvestigateRequest,
    user: Annotated[AuthUser, Depends(require_user)],
    x_securaiq_org: str | None = Header(default=None, alias="X-SecuraIQ-Org"),
):
    """Flagship workflow: investigate top-risk assets inside the caller's tenant."""
    oid = resolve_request_org(user, org_id=req.org_id, header_org=x_securaiq_org)
    require_perm(user, "asset.read", org_id=oid)
    require_perm(user, "vuln.read", org_id=oid)
    return investigate_top_assets(
        user.id,
        org_id=oid,
        engagement_id=req.engagement_id,
        limit=req.limit,
    )


@router.post("/ai/investigate-scan")
async def ai_investigate_scan(
    req: InvestigateScanRequest,
    user: Annotated[AuthUser, Depends(require_user)],
    x_securaiq_org: str | None = Header(default=None, alias="X-SecuraIQ-Org"),
):
    """Load scan evidence + report.md into an investigation pack for Ask AI."""
    oid = resolve_request_org(user, org_id=req.org_id, header_org=x_securaiq_org)
    require_perm(user, "asset.read", org_id=oid)
    require_perm(user, "vuln.read", org_id=oid)
    try:
        return investigate_scan(user.id, req.scan_id, org_id=oid)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.post("/risk/score")
async def risk_score_compute(req: RiskScoreRequest, user: Annotated[AuthUser, Depends(require_user)]):
    """Deterministic risk score — AI should explain, not invent."""
    _ = user
    result = compute_risk_score(
        cvss=req.cvss,
        exploitability=req.exploitability,
        exposure=req.exposure,
        asset_criticality=req.asset_criticality,
        threat_intel=req.threat_intel,
        confidence=req.confidence,
    )
    result["explanation"] = explain_risk_score(result)
    return result


@router.post("/assets")
async def assets_create(
    req: AssetCreate,
    user: Annotated[AuthUser, Depends(require_user)],
    x_securaiq_org: str | None = Header(default=None, alias="X-SecuraIQ-Org"),
):
    oid = resolve_request_org(user, header_org=x_securaiq_org)
    require_perm(user, "asset.write", org_id=oid)
    from app.asset_categories import normalize_asset_category

    return create_asset(
        user.id,
        req.name,
        asset_type=normalize_asset_category(req.asset_type),
        criticality=req.criticality,
        owner=req.owner,
        notes=req.notes,
        engagement_id=req.engagement_id,
        org_id=oid,
    )


@router.patch("/assets/{asset_id}")
async def assets_update(asset_id: str, req: AssetUpdate, user: Annotated[AuthUser, Depends(require_user)]):
    require_perm(user, "asset.write")
    payload = req.model_dump(exclude_none=True)
    if payload.get("asset_type") is not None:
        from app.asset_categories import normalize_asset_category

        payload["asset_type"] = normalize_asset_category(payload["asset_type"])
    out = update_asset(user.id, asset_id, payload)
    if not out:
        raise HTTPException(status_code=404, detail="Not found")
    return out


@router.delete("/assets/{asset_id}")
async def assets_delete(asset_id: str, user: Annotated[AuthUser, Depends(require_user)]):
    require_perm(user, "asset.write")
    if not delete_asset(user.id, asset_id):
        raise HTTPException(status_code=404, detail="Not found")
    return {"ok": True}


@router.get("/risks")
async def risks_list(
    user: Annotated[AuthUser, Depends(require_user)],
    engagement_id: str | None = None,
    status: str | None = None,
    org_id: str | None = None,
    x_securaiq_org: str | None = Header(default=None, alias="X-SecuraIQ-Org"),
):
    oid = resolve_request_org(user, org_id=org_id, header_org=x_securaiq_org)
    return {"risks": list_risks(user.id, engagement_id=engagement_id, status=status, org_id=oid), "org_id": oid}


@router.get("/risks/export")
async def risks_export(user: Annotated[AuthUser, Depends(require_user)], engagement_id: str | None = None):
    return PlainTextResponse(
        export_risk_markdown(user.id, engagement_id),
        media_type="text/markdown; charset=utf-8",
    )


@router.post("/risks")
async def risks_create(req: RiskCreate, user: Annotated[AuthUser, Depends(require_user)]):
    return create_risk(user.id, **req.model_dump())


@router.patch("/risks/{risk_id}")
async def risks_update(risk_id: str, req: RiskUpdate, user: Annotated[AuthUser, Depends(require_user)]):
    out = update_risk(user.id, risk_id, req.model_dump(exclude_none=True))
    if not out:
        raise HTTPException(status_code=404, detail="Not found")
    return out


@router.delete("/risks/{risk_id}")
async def risks_delete(risk_id: str, user: Annotated[AuthUser, Depends(require_user)]):
    if not delete_risk(user.id, risk_id):
        raise HTTPException(status_code=404, detail="Not found")
    return {"ok": True}


@router.get("/vulnerabilities")
async def vulns_list(
    user: Annotated[AuthUser, Depends(require_user)],
    engagement_id: str | None = None,
    status: str | None = None,
    org_id: str | None = None,
    x_securaiq_org: str | None = Header(default=None, alias="X-SecuraIQ-Org"),
):
    oid = resolve_request_org(user, org_id=org_id, header_org=x_securaiq_org)
    require_perm(user, "vuln.read", org_id=oid)
    from app.enterprise import collapse_duplicate_findings, enrich_vulnerabilities_display, list_vulnerabilities

    collapse_duplicate_findings(user.id)
    vulns = list_vulnerabilities(
        user.id, engagement_id=engagement_id, status=status, org_id=oid
    )
    return {
        "vulnerabilities": enrich_vulnerabilities_display(user.id, vulns),
        "org_id": oid,
    }


@router.get("/vulnerabilities/export")
async def vulns_export(user: Annotated[AuthUser, Depends(require_user)], engagement_id: str | None = None):
    require_perm(user, "report.export")
    return PlainTextResponse(
        export_vuln_markdown(user.id, engagement_id),
        media_type="text/markdown; charset=utf-8",
    )


@router.post("/vulnerabilities/import")
async def vulns_import(
    user: Annotated[AuthUser, Depends(require_user)],
    file: UploadFile = File(...),
    engagement_id: str | None = None,
    x_securaiq_org: str | None = Header(default=None, alias="X-SecuraIQ-Org"),
):
    oid = resolve_request_org(user, header_org=x_securaiq_org)
    require_perm(user, "vuln.write", org_id=oid)
    data = await file.read()
    try:
        return import_vulnerabilities(
            user.id,
            content=data,
            filename=file.filename or "import.csv",
            engagement_id=engagement_id,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Import failed: {exc}") from exc


@router.get("/vulnerabilities/samples")
async def vulns_samples(user: Annotated[AuthUser, Depends(require_user)]):
    """Demo fixtures disabled — import real scanner exports via /api/vulnerabilities/import."""
    return {
        "samples": [],
        "ok": True,
        "disabled": True,
        "hint": "Lab fixtures removed. Prefer Live scan (Tools + Auth) or import Trivy/Semgrep/Gitleaks/Nessus JSON.",
    }


@router.post("/vulnerabilities/samples/{sample_id}/import")
async def vulns_sample_import(
    sample_id: str,
    user: Annotated[AuthUser, Depends(require_user)],
    engagement_id: str | None = None,
):
    raise HTTPException(
        status_code=410,
        detail="Lab sample import disabled. Use Live scan or Import with your scanner export.",
    )


@router.patch("/vulnerabilities/{vuln_id}")
async def vulns_update(vuln_id: str, req: VulnUpdate, user: Annotated[AuthUser, Depends(require_user)]):
    require_perm(user, "vuln.write")
    try:
        out = update_vulnerability(user.id, vuln_id, req.model_dump(exclude_none=True))
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    if not out:
        raise HTTPException(status_code=404, detail="Not found")
    return out


class VulnTriage(BaseModel):
    owner: str = "SecOps"
    create_jira: bool = False


@router.post("/vulnerabilities/{vuln_id}/triage")
async def vulns_triage(vuln_id: str, req: VulnTriage, user: Annotated[AuthUser, Depends(require_user)]):
    """Golden path: finding → risk + remediation (+ optional Jira)."""
    require_perm(user, "vuln.triage")
    try:
        out = triage_vulnerability(user.id, vuln_id, owner=req.owner, create_ticket_hint=req.create_jira)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc

    jira = None
    if req.create_jira:
        try:
            from app.commercial_ext import jira_create_issue

            rem = out.get("remediation") or {}
            v = out.get("vulnerability") or {}
            summary = f"[SecuraIQ] {v.get('cve') or ''} {v.get('title') or rem.get('title')}".strip()[:255]
            jira = await jira_create_issue(
                summary=summary,
                description=(
                    f"Auto-triaged from vulnerability `{vuln_id}`.\n\n"
                    f"Severity: {v.get('severity')}\n"
                    f"Asset: {v.get('asset_name') or '—'}\n"
                    f"Risk id: {(out.get('risk') or {}).get('id')}\n"
                    f"Remediation id: {rem.get('id')}\n"
                ),
            )
            out["jira"] = jira
        except Exception as exc:
            out["jira_error"] = str(exc)
    return out


@router.post("/vulnerabilities/{vuln_id}/jira")
async def vulns_jira(vuln_id: str, user: Annotated[AuthUser, Depends(require_user)]):
    v = get_vulnerability(user.id, vuln_id)
    if not v:
        raise HTTPException(status_code=404, detail="Not found")
    try:
        from app.commercial_ext import jira_create_issue

        summary = f"[SecuraIQ] {v.get('cve') or ''} — {v.get('title')}".strip()[:255]
        return await jira_create_issue(
            summary=summary,
            description=(
                f"Vulnerability `{vuln_id}`\n"
                f"Severity: {v.get('severity')}\n"
                f"Asset: {v.get('asset_name') or '—'}\n"
                f"Source: {v.get('source') or '—'}\n"
            ),
        )
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/gap/remediations")
async def rem_list(
    user: Annotated[AuthUser, Depends(require_user)],
    assessment_id: str | None = None,
    engagement_id: str | None = None,
    status: str | None = None,
    org_id: str | None = None,
    x_securaiq_org: str | None = Header(default=None, alias="X-SecuraIQ-Org"),
):
    oid = resolve_request_org(user, org_id=org_id, header_org=x_securaiq_org)
    return {
        "remediations": list_remediations(
            user.id,
            assessment_id=assessment_id,
            engagement_id=engagement_id,
            status=status,
            org_id=oid,
        ),
        "org_id": oid,
    }


@router.post("/gap/remediations")
async def rem_create(req: RemediationCreate, user: Annotated[AuthUser, Depends(require_user)]):
    return create_remediation(user.id, **req.model_dump())


@router.patch("/gap/remediations/{rem_id}")
async def rem_update(rem_id: str, req: RemediationUpdate, user: Annotated[AuthUser, Depends(require_user)]):
    out = update_remediation(user.id, rem_id, req.model_dump(exclude_none=True))
    if not out:
        raise HTTPException(status_code=404, detail="Not found")
    return out


@router.get("/playbooks")
async def playbooks_list(
    user: Annotated[AuthUser, Depends(require_user)],
    engagement_id: str | None = None,
    org_id: str | None = None,
    x_securaiq_org: str | None = Header(default=None, alias="X-SecuraIQ-Org"),
):
    oid = resolve_request_org(user, org_id=org_id, header_org=x_securaiq_org)
    return {"playbooks": list_playbooks(user.id, engagement_id, org_id=oid), "org_id": oid}


@router.post("/playbooks")
async def playbooks_create(req: PlaybookCreate, user: Annotated[AuthUser, Depends(require_user)]):
    return create_playbook(user.id, **req.model_dump())


@router.patch("/playbooks/{playbook_id}")
async def playbooks_update(
    playbook_id: str, req: PlaybookUpdate, user: Annotated[AuthUser, Depends(require_user)]
):
    out = update_playbook(user.id, playbook_id, req.model_dump(exclude_none=True))
    if not out:
        raise HTTPException(status_code=404, detail="Not found")
    return out


@router.delete("/playbooks/{playbook_id}")
async def playbooks_delete(playbook_id: str, user: Annotated[AuthUser, Depends(require_user)]):
    if not delete_playbook(user.id, playbook_id):
        raise HTTPException(status_code=404, detail="Not found")
    return {"ok": True}


@router.get("/campaigns")
async def campaigns_list(
    user: Annotated[AuthUser, Depends(require_user)],
    engagement_id: str | None = None,
    org_id: str | None = None,
    x_securaiq_org: str | None = Header(default=None, alias="X-SecuraIQ-Org"),
):
    oid = resolve_request_org(user, org_id=org_id, header_org=x_securaiq_org)
    return {"campaigns": list_campaigns(user.id, engagement_id, org_id=oid), "org_id": oid}


@router.post("/campaigns")
async def campaigns_create(req: CampaignCreate, user: Annotated[AuthUser, Depends(require_user)]):
    return create_campaign(user.id, **req.model_dump())


@router.patch("/campaigns/{campaign_id}")
async def campaigns_update(
    campaign_id: str, req: CampaignUpdate, user: Annotated[AuthUser, Depends(require_user)]
):
    out = update_campaign(user.id, campaign_id, req.model_dump(exclude_none=True))
    if not out:
        raise HTTPException(status_code=404, detail="Not found")
    return out


@router.delete("/campaigns/{campaign_id}")
async def campaigns_delete(campaign_id: str, user: Annotated[AuthUser, Depends(require_user)]):
    if not delete_campaign(user.id, campaign_id):
        raise HTTPException(status_code=404, detail="Not found")
    return {"ok": True}


@router.post("/gap/run")
async def gap_run_structured(req: GapRunStructured, user: Annotated[AuthUser, Depends(require_user)]):
    """Structured gap workflow: evidence text + optional uploaded file IDs."""
    ensure_gap_schema()
    evidence = (req.evidence or "").strip()
    if req.file_ids:
        file_ev = evidence_from_files(user.id, req.file_ids)
        evidence = (evidence + "\n\n" + file_ev).strip() if evidence else file_ev
    if not evidence:
        raise HTTPException(status_code=400, detail="Provide evidence text and/or file_ids")
    try:
        return run_gap_analysis(
            framework_id=req.framework_id,
            evidence=evidence,
            title=req.title,
            engagement_id=req.engagement_id,
            user_id=user.id,
            overrides=req.overrides,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
