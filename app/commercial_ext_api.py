"""API: organizations, evidence links, PDF export, Jira."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import Response
from pydantic import BaseModel, Field
from starlette.concurrency import run_in_threadpool

from app.fast_cache import run_fast

from app.auth import AuthUser
from app.commercial_api import require_user
from app.commercial_ext import (
    ROLES,
    add_org_member,
    build_executive_pdf,
    create_org,
    delete_evidence_link,
    ensure_org_schema,
    jira_create_issue,
    link_evidence,
    list_evidence_links,
    list_org_members,
    list_orgs,
    markdown_to_simple_pdf,
    update_evidence_link,
)
from app.enterprise import export_risk_markdown, export_vuln_markdown, list_remediations

router = APIRouter(prefix="/api", tags=["commercial-ext"])


class OrgCreate(BaseModel):
    name: str = Field(min_length=1, max_length=200)


class OrgMemberAdd(BaseModel):
    username: str = Field(min_length=1, max_length=100)
    role: str = "analyst"


class EvidenceLinkCreate(BaseModel):
    file_id: str
    remediation_id: str | None = None
    control_id: str = ""
    notes: str = ""
    owner: str = ""
    status: str = "accepted"
    expiry: str = ""
    engagement_id: str | None = None


class EvidenceLinkUpdate(BaseModel):
    control_id: str | None = None
    notes: str | None = None
    owner: str | None = None
    status: str | None = None
    expiry: str | None = None
    remediation_id: str | None = None


class JiraIssueCreate(BaseModel):
    summary: str = Field(min_length=1, max_length=255)
    description: str = ""
    issue_type: str = "Task"
    remediation_id: str | None = None


class ServiceNowIncidentCreate(BaseModel):
    short_description: str = Field(min_length=1, max_length=160)
    description: str = ""
    urgency: str = "2"
    remediation_id: str | None = None


@router.get("/orgs")
async def orgs_list(user: Annotated[AuthUser, Depends(require_user)]):
    ensure_org_schema()
    orgs = await run_fast(list_orgs, user.id)
    return {"organizations": orgs, "roles": list(ROLES)}


@router.post("/orgs")
async def orgs_create(req: OrgCreate, user: Annotated[AuthUser, Depends(require_user)]):
    return create_org(user.id, req.name)


@router.get("/orgs/{org_id}/members")
async def orgs_members(org_id: str, user: Annotated[AuthUser, Depends(require_user)]):
    try:
        return {"members": list_org_members(user.id, org_id)}
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc


@router.post("/orgs/{org_id}/members")
async def orgs_add_member(
    org_id: str, req: OrgMemberAdd, user: Annotated[AuthUser, Depends(require_user)]
):
    try:
        return add_org_member(user.id, org_id, req.username, req.role)
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/evidence")
async def evidence_list(
    user: Annotated[AuthUser, Depends(require_user)],
    remediation_id: str | None = None,
    engagement_id: str | None = None,
):
    return {
        "evidence": list_evidence_links(
            user.id, remediation_id=remediation_id, engagement_id=engagement_id
        )
    }


@router.post("/evidence")
async def evidence_create(req: EvidenceLinkCreate, user: Annotated[AuthUser, Depends(require_user)]):
    try:
        return link_evidence(user.id, **req.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.patch("/evidence/{link_id}")
async def evidence_update(
    link_id: str, req: EvidenceLinkUpdate, user: Annotated[AuthUser, Depends(require_user)]
):
    out = update_evidence_link(user.id, link_id, req.model_dump(exclude_none=True))
    if not out:
        raise HTTPException(status_code=404, detail="Not found")
    return out


@router.delete("/evidence/{link_id}")
async def evidence_delete(link_id: str, user: Annotated[AuthUser, Depends(require_user)]):
    if not delete_evidence_link(user.id, link_id):
        raise HTTPException(status_code=404, detail="Not found")
    return {"ok": True}


@router.get("/reports/executive.pdf")
async def report_executive_pdf(user: Annotated[AuthUser, Depends(require_user)]):
    pdf = build_executive_pdf(user.id)
    return Response(
        content=pdf,
        media_type="application/pdf",
        headers={"Content-Disposition": 'attachment; filename="securaiq-executive.pdf"'},
    )


@router.get("/reports/risks.pdf")
async def report_risks_pdf(user: Annotated[AuthUser, Depends(require_user)]):
    md = export_risk_markdown(user.id)
    pdf = markdown_to_simple_pdf(md, title="SecuraIQ Risk Report")
    return Response(
        content=pdf,
        media_type="application/pdf",
        headers={"Content-Disposition": 'attachment; filename="securaiq-risks.pdf"'},
    )


@router.get("/reports/vulns.pdf")
async def report_vulns_pdf(user: Annotated[AuthUser, Depends(require_user)]):
    md = export_vuln_markdown(user.id)
    pdf = markdown_to_simple_pdf(md, title="SecuraIQ Vulnerability Report")
    return Response(
        content=pdf,
        media_type="application/pdf",
        headers={"Content-Disposition": 'attachment; filename="securaiq-vulns.pdf"'},
    )


@router.post("/integrations/jira/issue")
async def jira_issue(req: JiraIssueCreate, user: Annotated[AuthUser, Depends(require_user)]):
    summary = req.summary
    description = req.description
    if req.remediation_id:
        rems = list_remediations(user.id)
        rem = next((r for r in rems if r.get("id") == req.remediation_id), None)
        if rem:
            summary = summary or f"[SecuraIQ] {rem.get('control_id')} — {rem.get('title')}"
            description = (
                description
                or f"Control: {rem.get('control_id')}\n{rem.get('title')}\n\n"
                f"Recommendation: {rem.get('recommendation') or rem.get('notes') or ''}\n"
                f"Owner: {rem.get('owner') or 'unassigned'}\nStatus: {rem.get('status')}"
            )
    try:
        return await jira_create_issue(summary=summary, description=description, issue_type=req.issue_type)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post("/integrations/servicenow/incident")
async def servicenow_incident(req: ServiceNowIncidentCreate, user: Annotated[AuthUser, Depends(require_user)]):
    from app.connectors.servicenow import create_incident as sn_create_incident

    short_description = req.short_description
    description = req.description
    if req.remediation_id:
        rems = list_remediations(user.id)
        rem = next((r for r in rems if r.get("id") == req.remediation_id), None)
        if rem:
            short_description = short_description or f"[SecuraIQ] {rem.get('control_id')} — {rem.get('title')}"
            description = (
                description
                or f"Control: {rem.get('control_id')}\n{rem.get('title')}\n\n"
                f"Recommendation: {rem.get('recommendation') or rem.get('notes') or ''}\n"
                f"Owner: {rem.get('owner') or 'unassigned'}\nStatus: {rem.get('status')}"
            )
    try:
        return await sn_create_incident(
            short_description=short_description, description=description, urgency=req.urgency
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
