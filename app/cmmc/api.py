"""CMMC assessment API — objectives, methods, POA&M, CUI program, SPRS prep."""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

from app.auth import AuthUser
from app.cmmc.cui_program import list_cui_programs, upsert_cui_program
from app.cmmc.methods import list_method_evidence, record_method_evidence
from app.cmmc.objectives import (
    get_control_assessment,
    list_objectives,
    seed_objectives_for_framework,
    set_objective_status,
)
from app.cmmc.poam_items import close_poam_item, list_poam_items, open_poam_item
from app.cmmc.poam_policy import poam_policy_for_control, poam_policy_for_framework
from app.cmmc.sprs_prep import sprs_preparation_snapshot
from app.cmmc.versioning import framework_version_info
from app.commercial_api import require_user

router = APIRouter(prefix="/api/cmmc", tags=["cmmc-assessment"])


class ObjectiveStatusIn(BaseModel):
    status: str = Field(min_length=1, max_length=40)
    evidence_ids: list[str] = Field(default_factory=list)
    reviewer: str = ""
    notes: str = ""
    org_id: str | None = None


class MethodEvidenceIn(BaseModel):
    framework_id: str = "cmmc_l2"
    control_id: str = Field(min_length=1, max_length=80)
    method: str = Field(min_length=1, max_length=20)
    title: str = Field(min_length=1, max_length=300)
    detail: dict[str, Any] = Field(default_factory=dict)
    objective_id: str = ""
    result: str = "unknown"
    reviewer: str = ""
    org_id: str | None = None


class PoamOpenIn(BaseModel):
    framework_id: str = "cmmc_l2"
    control_id: str = Field(min_length=1, max_length=80)
    weakness: str = Field(min_length=1, max_length=4000)
    owner: str = Field(min_length=1, max_length=200)
    risk_level: str = "medium"
    finding_id: str = ""
    milestones: list[dict[str, Any]] = Field(default_factory=list)
    org_id: str | None = None
    remediation_id: str = ""


class PoamCloseIn(BaseModel):
    evidence_ids: list[str] = Field(default_factory=list)
    verified: bool = False


class CuiProgramIn(BaseModel):
    name: str = Field(min_length=1, max_length=300)
    description: str = ""
    boundary_notes: str = ""
    categories: list[str] = Field(default_factory=list)
    external_providers: list[dict[str, Any]] = Field(default_factory=list)
    data_flows: list[dict[str, Any]] = Field(default_factory=list)
    org_id: str | None = None
    program_id: str | None = None


@router.get("/version")
async def api_cmmc_version(framework_id: str = Query("cmmc_l2")):
    return framework_version_info(framework_id)


@router.post("/objectives/seed")
async def api_seed_objectives(
    user: Annotated[AuthUser, Depends(require_user)],
    framework_id: str = Query("cmmc_l2"),
    force: bool = False,
):
    return seed_objectives_for_framework(framework_id, force=force)


@router.get("/objectives")
async def api_list_objectives(
    user: Annotated[AuthUser, Depends(require_user)],
    framework_id: str = Query("cmmc_l2"),
    control_id: str = Query(""),
):
    seed_objectives_for_framework(framework_id)
    return {"ok": True, "objectives": list_objectives(framework_id, control_id=control_id)}


@router.post("/objectives/{objective_id}/status")
async def api_set_objective_status(
    objective_id: str,
    body: ObjectiveStatusIn,
    user: Annotated[AuthUser, Depends(require_user)],
):
    try:
        return set_objective_status(
            user.id,
            objective_id,
            status=body.status,
            evidence_ids=body.evidence_ids,
            reviewer=body.reviewer or user.username,
            notes=body.notes,
            org_id=body.org_id,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/controls/{control_id}/assessment")
async def api_control_assessment(
    control_id: str,
    user: Annotated[AuthUser, Depends(require_user)],
    framework_id: str = Query("cmmc_l2"),
):
    return get_control_assessment(user.id, framework_id, control_id)


@router.post("/method-evidence")
async def api_record_method_evidence(
    body: MethodEvidenceIn,
    user: Annotated[AuthUser, Depends(require_user)],
):
    try:
        return record_method_evidence(
            user.id,
            framework_id=body.framework_id,
            control_id=body.control_id,
            method=body.method,
            title=body.title,
            detail=body.detail,
            objective_id=body.objective_id,
            result=body.result,
            reviewer=body.reviewer or user.username,
            org_id=body.org_id,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/method-evidence")
async def api_list_method_evidence(
    user: Annotated[AuthUser, Depends(require_user)],
    framework_id: str = Query(""),
    control_id: str = Query(""),
    method: str = Query(""),
):
    return {
        "ok": True,
        "items": list_method_evidence(
            user.id, framework_id=framework_id, control_id=control_id, method=method
        ),
    }


@router.get("/poam/policy")
async def api_poam_policy(
    user: Annotated[AuthUser, Depends(require_user)],
    framework_id: str = Query("cmmc_l2"),
    control_id: str = Query(""),
):
    if control_id:
        return poam_policy_for_control(framework_id, control_id)
    return poam_policy_for_framework(framework_id)


@router.post("/poam")
async def api_open_poam(body: PoamOpenIn, user: Annotated[AuthUser, Depends(require_user)]):
    try:
        return open_poam_item(
            user.id,
            framework_id=body.framework_id,
            control_id=body.control_id,
            weakness=body.weakness,
            owner=body.owner,
            risk_level=body.risk_level,
            finding_id=body.finding_id,
            milestones=body.milestones,
            org_id=body.org_id,
            remediation_id=body.remediation_id,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/poam")
async def api_list_poam(
    user: Annotated[AuthUser, Depends(require_user)],
    framework_id: str = Query("cmmc_l2"),
    status: str = Query(""),
):
    return {"ok": True, "items": list_poam_items(user.id, framework_id=framework_id, status=status)}


@router.post("/poam/{poam_id}/close")
async def api_close_poam(
    poam_id: str,
    body: PoamCloseIn,
    user: Annotated[AuthUser, Depends(require_user)],
):
    try:
        out = close_poam_item(
            user.id, poam_id, evidence_ids=body.evidence_ids, verified=body.verified
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    if not out:
        raise HTTPException(status_code=404, detail="POA&M not found")
    return out


@router.post("/cui-programs")
async def api_upsert_cui_program(
    body: CuiProgramIn, user: Annotated[AuthUser, Depends(require_user)]
):
    try:
        return upsert_cui_program(
            user.id,
            name=body.name,
            description=body.description,
            boundary_notes=body.boundary_notes,
            categories=body.categories,
            external_providers=body.external_providers,
            data_flows=body.data_flows,
            org_id=body.org_id,
            program_id=body.program_id,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/cui-programs")
async def api_list_cui_programs(user: Annotated[AuthUser, Depends(require_user)]):
    return {"ok": True, "programs": list_cui_programs(user.id)}


@router.get("/sprs-preparation")
async def api_sprs_preparation(
    user: Annotated[AuthUser, Depends(require_user)],
    framework_id: str = Query("cmmc_l2"),
):
    return sprs_preparation_snapshot(user.id, framework_id=framework_id)
