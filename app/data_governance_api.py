"""HTTP API for data governance / DPDP data-map foundations."""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field
from starlette.concurrency import run_in_threadpool

from app.auth import AuthUser
from app.commercial_api import require_user
from app.data_governance import (
    dpdp_overview,
    family_posture,
    get_org_privacy_profile,
    list_data_elements,
    list_data_flows,
    list_processors,
    list_processing_activities,
    list_principal_requests,
    list_retention_policies,
    set_org_privacy_profile,
    upsert_data_element,
    upsert_data_flow,
    upsert_processor,
    upsert_processing_activity,
    upsert_principal_request,
    upsert_retention_policy,
)

router = APIRouter(prefix="/api/data-governance", tags=["data-governance"])


class PrivacyProfileBody(BaseModel):
    sdf_status: str = "unknown"
    jurisdiction: str = "IN"
    notes: str = ""
    meta: dict[str, Any] = Field(default_factory=dict)


class ElementBody(BaseModel):
    id: str | None = None
    name: str = Field(min_length=1, max_length=200)
    classification: str = "personal_data"
    purpose: str = ""
    source_system: str = ""
    storage_system: str = ""
    owner: str = ""
    retention_days: int | None = None
    meta: dict[str, Any] = Field(default_factory=dict)


class ActivityBody(BaseModel):
    id: str | None = None
    name: str = Field(min_length=1, max_length=200)
    purpose: str = ""
    lawful_basis: str = ""
    data_element_ids: list[str] = Field(default_factory=list)
    systems: list[str] = Field(default_factory=list)
    meta: dict[str, Any] = Field(default_factory=dict)


class FlowBody(BaseModel):
    id: str | None = None
    name: str = Field(min_length=1, max_length=200)
    from_system: str = ""
    to_system: str = ""
    data_element_ids: list[str] = Field(default_factory=list)
    processor_id: str = ""
    cross_border: bool = False
    meta: dict[str, Any] = Field(default_factory=dict)


class ProcessorBody(BaseModel):
    id: str | None = None
    name: str = Field(min_length=1, max_length=200)
    role: str = "processor"
    purposes: str = ""
    data_categories: str = ""
    contract_ref: str = ""
    security_requirements: str = ""
    sub_processors: str = ""
    offboarded: bool = False
    meta: dict[str, Any] = Field(default_factory=dict)


class RetentionBody(BaseModel):
    id: str | None = None
    name: str = Field(min_length=1, max_length=200)
    purpose: str = ""
    retention_days: int | None = None
    deletion_method: str = ""
    backup_handling: str = ""
    data_element_ids: list[str] = Field(default_factory=list)
    meta: dict[str, Any] = Field(default_factory=dict)


class RequestBody(BaseModel):
    id: str | None = None
    request_type: str = "access"
    principal_ref: str = ""
    status: str = "open"
    sla_due_at: float | None = None
    closed_at: float | None = None
    notes: str = ""
    meta: dict[str, Any] = Field(default_factory=dict)


@router.get("/profile")
async def api_get_profile(user: Annotated[AuthUser, Depends(require_user)]):
    return get_org_privacy_profile(user.id)


@router.put("/profile")
async def api_put_profile(
    body: PrivacyProfileBody, user: Annotated[AuthUser, Depends(require_user)]
):
    return set_org_privacy_profile(
        user.id,
        sdf_status=body.sdf_status,
        jurisdiction=body.jurisdiction,
        notes=body.notes,
        meta=body.meta,
    )


@router.get("/posture")
async def api_posture(user: Annotated[AuthUser, Depends(require_user)]):
    """DPDP-style family dashboard from declared inventory (not legal compliance)."""
    return family_posture(user.id)


@router.get("/dpdp-overview")
async def api_dpdp_overview(
    user: Annotated[AuthUser, Depends(require_user)],
    as_of: str | None = None,
):
    """India DPDP dashboard: inventory posture, phased Rules commencement, gap scores."""
    return await run_in_threadpool(dpdp_overview, user.id, as_of=as_of)


@router.get("/data-map")
async def api_data_map(user: Annotated[AuthUser, Depends(require_user)]):
    return {
        "elements": list_data_elements(user.id),
        "activities": list_processing_activities(user.id),
        "flows": list_data_flows(user.id),
        "processors": list_processors(user.id),
        "retention_policies": list_retention_policies(user.id),
        "legal_disclaimer": get_org_privacy_profile(user.id).get("legal_disclaimer"),
    }


@router.get("/elements")
async def api_list_elements(user: Annotated[AuthUser, Depends(require_user)]):
    return {"elements": list_data_elements(user.id)}


@router.post("/elements")
async def api_upsert_element(
    body: ElementBody, user: Annotated[AuthUser, Depends(require_user)]
):
    return upsert_data_element(user.id, body.model_dump())


@router.get("/activities")
async def api_list_activities(user: Annotated[AuthUser, Depends(require_user)]):
    return {"activities": list_processing_activities(user.id)}


@router.post("/activities")
async def api_upsert_activity(
    body: ActivityBody, user: Annotated[AuthUser, Depends(require_user)]
):
    return upsert_processing_activity(user.id, body.model_dump())


@router.get("/flows")
async def api_list_flows(user: Annotated[AuthUser, Depends(require_user)]):
    return {"flows": list_data_flows(user.id)}


@router.post("/flows")
async def api_upsert_flow(body: FlowBody, user: Annotated[AuthUser, Depends(require_user)]):
    return upsert_data_flow(user.id, body.model_dump())


@router.get("/processors")
async def api_list_processors(user: Annotated[AuthUser, Depends(require_user)]):
    return {"processors": list_processors(user.id)}


@router.post("/processors")
async def api_upsert_processor(
    body: ProcessorBody, user: Annotated[AuthUser, Depends(require_user)]
):
    return upsert_processor(user.id, body.model_dump())


@router.get("/retention")
async def api_list_retention(user: Annotated[AuthUser, Depends(require_user)]):
    return {"retention_policies": list_retention_policies(user.id)}


@router.post("/retention")
async def api_upsert_retention(
    body: RetentionBody, user: Annotated[AuthUser, Depends(require_user)]
):
    return upsert_retention_policy(user.id, body.model_dump())


@router.get("/requests")
async def api_list_requests(user: Annotated[AuthUser, Depends(require_user)]):
    return {"requests": list_principal_requests(user.id)}


@router.post("/requests")
async def api_upsert_request(
    body: RequestBody, user: Annotated[AuthUser, Depends(require_user)]
):
    return upsert_principal_request(user.id, body.model_dump())
