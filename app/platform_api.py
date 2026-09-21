"""Platform APIs: knowledge graph, intel feeds, office reports, webhooks, Qdrant status."""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import Response
from pydantic import BaseModel, Field

from app.auth import AuthUser
from app.automation import create_webhook, delete_webhook, dispatch_webhooks, list_webhooks
from app.commercial_api import require_user
from app.config import settings
from app.enterprise import (
    enterprise_dashboard,
    export_risk_markdown,
    export_vuln_markdown,
    list_risks,
    list_vulnerabilities,
)
from app.free_security_apis import (
    catalog_summary,
    check_password_pwned,
    generate_password,
    lookup_filterlists,
    lookup_greynoise,
    lookup_msrc,
    lookup_uk_police_forces,
    unified_lookup,
)
from app.intel_feeds import fetch_cisa_kev, lookup_nvd_cve, sync_kev_to_watchlist
from app.knowledge_graph import (
    add_entity_link,
    build_knowledge_graph,
    correlate_focus,
    correlation_hotspots,
    list_entity_links,
    rebuild_auto_links,
)
from app.office_export import build_xlsx, markdown_to_docx

router = APIRouter(prefix="/api", tags=["platform"])


class EntityLinkCreate(BaseModel):
    src_type: str = Field(min_length=1, max_length=40)
    src_id: str = Field(min_length=1, max_length=80)
    dst_type: str = Field(min_length=1, max_length=40)
    dst_id: str = Field(min_length=1, max_length=80)
    relation: str = "related"
    notes: str = ""


class WebhookCreate(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    url: str = Field(min_length=8, max_length=500)
    events: list[str] = Field(default_factory=lambda: ["*"])


class WebhookDispatch(BaseModel):
    event: str = "test"
    payload: dict[str, Any] = Field(default_factory=dict)


@router.get("/graph")
async def graph_get(user: Annotated[AuthUser, Depends(require_user)]):
    return build_knowledge_graph(user.id)


@router.get("/graph/hotspots")
async def graph_hotspots(
    user: Annotated[AuthUser, Depends(require_user)],
    limit: int = Query(12, ge=1, le=40),
):
    return {"hotspots": correlation_hotspots(user.id, limit=limit)}


@router.get("/graph/correlate")
async def graph_correlate(
    user: Annotated[AuthUser, Depends(require_user)],
    q: str = Query("", max_length=120),
):
    return correlate_focus(user.id, q)


@router.post("/graph/rebuild")
async def graph_rebuild(user: Annotated[AuthUser, Depends(require_user)]):
    return rebuild_auto_links(user.id)


@router.get("/graph/links")
async def graph_links(user: Annotated[AuthUser, Depends(require_user)]):
    return {"links": list_entity_links(user.id)}


@router.post("/graph/links")
async def graph_link_create(req: EntityLinkCreate, user: Annotated[AuthUser, Depends(require_user)]):
    return add_entity_link(user.id, **req.model_dump())


@router.get("/intel/kev")
async def intel_kev(user: Annotated[AuthUser, Depends(require_user)], limit: int = 40):
    try:
        return await fetch_cisa_kev(limit=min(100, max(5, limit)))
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=502, detail=f"KEV feed unavailable: {exc}") from exc


@router.post("/intel/kev/sync")
async def intel_kev_sync(user: Annotated[AuthUser, Depends(require_user)], limit: int = 25):
    try:
        return await sync_kev_to_watchlist(user.id, limit=min(50, max(1, limit)))
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=502, detail=f"KEV sync failed: {exc}") from exc


@router.get("/intel/nvd/{cve_id}")
async def intel_nvd(cve_id: str, user: Annotated[AuthUser, Depends(require_user)]):
    try:
        return await lookup_nvd_cve(cve_id)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=502, detail=f"NVD lookup failed: {exc}") from exc


@router.get("/intel/free/catalog")
async def intel_free_catalog(user: Annotated[AuthUser, Depends(require_user)]):
    """Built-in Security + Anti-Malware provider catalog with live/keyed/skipped status."""
    return catalog_summary()


@router.get("/intel/threat-detection")
async def intel_threat_detection(
    user: Annotated[AuthUser, Depends(require_user)],
    q: str = "",
    category: str = "",
    limit: int = 80,
    refresh: bool = False,
):
    """Searchable catalog from 0x4D31/awesome-threat-detection (tools, rules, labs)."""
    from app.threat_detection_catalog import load_catalog, search_catalog

    try:
        catalog = await load_catalog(force=refresh)
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(
            status_code=502, detail=f"Threat detection catalog unavailable: {exc}"
        ) from exc
    return search_catalog(catalog, q=q, category=category, limit=limit)


@router.post("/intel/threat-detection/refresh")
async def intel_threat_detection_refresh(user: Annotated[AuthUser, Depends(require_user)]):
    from app.threat_detection_catalog import load_catalog

    try:
        catalog = await load_catalog(force=True)
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(
            status_code=502, detail=f"Threat detection catalog refresh failed: {exc}"
        ) from exc
    return {
        "ok": True,
        "total": catalog.get("total"),
        "categories": catalog.get("categories"),
        "fetched_from": catalog.get("fetched_from"),
        "source": catalog.get("source"),
    }


@router.get("/intel/lookup")
async def intel_lookup(
    user: Annotated[AuthUser, Depends(require_user)],
    q: Annotated[str, Query(min_length=2, max_length=500, description="IP, domain, URL, email, hash, or CVE")],
):
    """Unified IOC/CVE lookup across free + configured keyed providers."""
    return await unified_lookup(q.strip())


@router.get("/intel/greynoise/{ip}")
async def intel_greynoise(ip: str, user: Annotated[AuthUser, Depends(require_user)]):
    try:
        return await lookup_greynoise(ip)
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=502, detail=f"GreyNoise lookup failed: {exc}") from exc


@router.get("/intel/msrc")
async def intel_msrc(user: Annotated[AuthUser, Depends(require_user)], limit: int = 15):
    try:
        return await lookup_msrc(limit=min(50, max(1, limit)))
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=502, detail=f"MSRC feed unavailable: {exc}") from exc


@router.get("/intel/filterlists")
async def intel_filterlists(user: Annotated[AuthUser, Depends(require_user)], limit: int = 20):
    try:
        return await lookup_filterlists(limit=min(100, max(1, limit)))
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=502, detail=f"FilterLists unavailable: {exc}") from exc


@router.get("/intel/uk-police/forces")
async def intel_uk_police(user: Annotated[AuthUser, Depends(require_user)]):
    try:
        return await lookup_uk_police_forces()
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=502, detail=f"UK Police API unavailable: {exc}") from exc


class PasswordCheckBody(BaseModel):
    password: str = Field(..., min_length=1, max_length=256)


@router.get("/intel/password")
async def intel_password(user: Annotated[AuthUser, Depends(require_user)], length: int = 16):
    """Generate a random password locally (does not check exposure)."""
    return await generate_password(length=length)


@router.post("/intel/password/check")
async def intel_password_check(
    user: Annotated[AuthUser, Depends(require_user)],
    body: PasswordCheckBody,
):
    """Check password exposure via HIBP k-anonymity. Send password in JSON body only — never as a query param."""
    try:
        return await check_password_pwned(body.password)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=502, detail=f"Password check unavailable: {exc}") from exc


@router.get("/reports/risks.xlsx")
async def report_risks_xlsx(user: Annotated[AuthUser, Depends(require_user)]):
    risks = list_risks(user.id)
    headers = ["Asset", "Threat", "Impact", "Likelihood", "Score", "Owner", "Status"]
    rows = [
        [
            r.get("asset_name"),
            r.get("threat"),
            r.get("impact"),
            r.get("likelihood"),
            r.get("risk_score"),
            r.get("owner"),
            r.get("status"),
        ]
        for r in risks
    ]
    data = build_xlsx(headers, rows, sheet_name="Risks")
    return Response(
        content=data,
        media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        headers={"Content-Disposition": 'attachment; filename="securaiq-risks.xlsx"'},
    )


@router.get("/reports/vulns.xlsx")
async def report_vulns_xlsx(user: Annotated[AuthUser, Depends(require_user)]):
    vulns = list_vulnerabilities(user.id)
    headers = ["CVE", "Severity", "Title", "Asset", "Owner", "Status", "Source"]
    rows = [
        [
            v.get("cve"),
            v.get("severity"),
            v.get("title"),
            v.get("asset_name"),
            v.get("owner"),
            v.get("status"),
            v.get("source"),
        ]
        for v in vulns
    ]
    data = build_xlsx(headers, rows, sheet_name="Vulnerabilities")
    return Response(
        content=data,
        media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        headers={"Content-Disposition": 'attachment; filename="securaiq-vulns.xlsx"'},
    )


@router.get("/reports/executive.docx")
async def report_executive_docx(user: Annotated[AuthUser, Depends(require_user)]):
    dash = enterprise_dashboard(user.id)
    mc = dash.get("mission_control") or {}
    lines = [
        f"Organization: {mc.get('organization')}",
        f"Security score: {mc.get('security_score')}",
        f"Framework: {mc.get('framework')} ({mc.get('framework_score')}%)",
        f"Environment: {mc.get('environment')}",
        "",
        "Today",
        f"- Critical/high findings: {(mc.get('today') or {}).get('critical_findings')}",
        f"- Open risks: {(mc.get('today') or {}).get('open_risks')}",
        f"- Open actions: {(mc.get('today') or {}).get('open_actions')}",
        "",
        "Work queue",
    ]
    for w in (dash.get("work_queue") or [])[:8]:
        lines.append(f"- [{w.get('priority')}] {w.get('title')} (owner: {w.get('owner')})")
    lines.append("")
    lines.append(export_risk_markdown(user.id)[:4000])
    docx = markdown_to_docx("\n".join(lines), title="SecuraIQ Executive Report")
    return Response(
        content=docx,
        media_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        headers={"Content-Disposition": 'attachment; filename="securaiq-executive.docx"'},
    )


@router.get("/reports/compliance.docx")
async def report_compliance_docx(user: Annotated[AuthUser, Depends(require_user)]):
    dash = enterprise_dashboard(user.id)
    lines = ["# Compliance report", ""]
    for f in dash.get("framework_control_stats") or dash.get("frameworks") or []:
        lines.append(
            f"- {f.get('framework_id') or f.get('id')}: {f.get('compliance_percent')}% "
            f"(controls {f.get('controls_total') or 'n/a'})"
        )
    lines.append("")
    lines.append(export_vuln_markdown(user.id)[:3000])
    docx = markdown_to_docx("\n".join(lines), title="SecuraIQ Compliance Report")
    return Response(
        content=docx,
        media_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        headers={"Content-Disposition": 'attachment; filename="securaiq-compliance.docx"'},
    )


@router.get("/webhooks")
async def webhooks_list(user: Annotated[AuthUser, Depends(require_user)]):
    return {"webhooks": list_webhooks(user.id)}


@router.post("/webhooks")
async def webhooks_create(req: WebhookCreate, user: Annotated[AuthUser, Depends(require_user)]):
    if not str(req.url).startswith(("http://", "https://")):
        raise HTTPException(status_code=400, detail="URL must be http(s)")
    return create_webhook(user.id, name=req.name, url=str(req.url), events=req.events)


@router.delete("/webhooks/{webhook_id}")
async def webhooks_delete(webhook_id: str, user: Annotated[AuthUser, Depends(require_user)]):
    if not delete_webhook(user.id, webhook_id):
        raise HTTPException(status_code=404, detail="Not found")
    return {"ok": True}


@router.post("/webhooks/dispatch")
async def webhooks_dispatch(req: WebhookDispatch, user: Annotated[AuthUser, Depends(require_user)]):
    return await dispatch_webhooks(user.id, req.event, req.payload)


@router.get("/platform/status")
async def platform_status(user: Annotated[AuthUser, Depends(require_user)]):
    from app.scanner_adapters import list_import_adapters

    return {
        "vector_store": "qdrant" if settings.qdrant_url else "chroma",
        "qdrant_url": settings.qdrant_url or None,
        "qdrant_collection": settings.qdrant_collection,
        "embedding_model": settings.embedding_model,
        "scanners": [*list_import_adapters(), "burp", "csv", "json", "xml"],
        "office_exports": ["pdf", "docx", "xlsx", "markdown"],
        "intel_feeds": [
            "cisa_kev",
            "nvd",
            "greynoise",
            "otx",
            "urlscan",
            "msrc",
            "filterlists",
            "phishstats",
            "free_apis_security",
        ],
    }


@router.get("/integrations/catalog")
async def integrations_catalog(user: Annotated[AuthUser, Depends(require_user)]):
    from app.integrations_catalog import catalog_payload

    return catalog_payload()


@router.get("/ops/mission-control")
async def ops_mission_control(user: Annotated[AuthUser, Depends(require_user)]):
    """Platform Mission Control — component health + queue lag / agents / SSE.

    Lab honesty: process-local when Redis unset. Not a multi-node HA console.
    """
    from app.mission_control import mission_control_snapshot

    return mission_control_snapshot(user_id=user.id)
