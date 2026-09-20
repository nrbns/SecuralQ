"""API for Evidence Spine — Observation/Document → Evidence → Control."""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from app.auth import AuthUser
from app.commercial_api import require_user
from app.evidence_spine.evaluate import evaluate_control_from_evidence
from app.evidence_spine.ingest import ingest_document_as_evidence, ingest_observation_as_evidence
from app.evidence_spine.mapping import (
    link_evidence_to_control,
    list_controls_for_evidence,
    list_evidence_for_control,
    unlink_evidence_from_control,
)

router = APIRouter(prefix="/api/evidence-spine", tags=["evidence-spine"])


class ObservationIn(BaseModel):
    result: str = Field(min_length=1, max_length=40)
    summary: str = ""
    data_source: str = "agent"
    source_ref: str = ""
    check_id: str = ""
    agent_id: str = ""
    asset_id: str = ""
    hostname: str = ""
    test_name: str = ""
    framework_id: str = ""
    control_id: str = ""
    controls: list[dict[str, str]] = Field(default_factory=list)
    detail: dict[str, Any] = Field(default_factory=dict)


class DocumentIn(BaseModel):
    title: str = Field(min_length=1, max_length=300)
    summary: str = ""
    file_id: str = ""
    document_id: str = ""
    control_id: str = ""
    framework_id: str = ""
    controls: list[dict[str, str]] = Field(default_factory=list)
    owner: str = ""


class LinkIn(BaseModel):
    evidence_id: str = Field(min_length=1)
    control_id: str = Field(min_length=1)
    framework_id: str = ""
    role: str = "supports"


@router.post("/observations")
async def api_ingest_observation(
    body: ObservationIn,
    user: Annotated[AuthUser, Depends(require_user)],
):
    controls = list(body.controls)
    if body.control_id:
        controls.append({"control_id": body.control_id, "framework_id": body.framework_id})
    try:
        return ingest_observation_as_evidence(
            user.id,
            result=body.result,
            summary=body.summary,
            data_source=body.data_source,
            source_ref=body.source_ref,
            check_id=body.check_id,
            agent_id=body.agent_id,
            asset_id=body.asset_id,
            hostname=body.hostname,
            test_name=body.test_name,
            controls=controls,
            detail=body.detail,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post("/documents")
async def api_ingest_document(
    body: DocumentIn,
    user: Annotated[AuthUser, Depends(require_user)],
):
    try:
        return ingest_document_as_evidence(
            user.id,
            title=body.title,
            summary=body.summary,
            file_id=body.file_id,
            document_id=body.document_id,
            control_id=body.control_id,
            framework_id=body.framework_id,
            controls=body.controls,
            owner=body.owner,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post("/link")
async def api_link(body: LinkIn, user: Annotated[AuthUser, Depends(require_user)]):
    try:
        return {
            "ok": True,
            "link": link_evidence_to_control(
                user.id,
                body.evidence_id,
                control_id=body.control_id,
                framework_id=body.framework_id,
                role=body.role,
            ),
        }
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.delete("/link")
async def api_unlink(
    user: Annotated[AuthUser, Depends(require_user)],
    evidence_id: str,
    control_id: str,
    framework_id: str = "",
):
    ok = unlink_evidence_from_control(
        user.id, evidence_id, control_id=control_id, framework_id=framework_id
    )
    return {"ok": ok}


@router.get("/controls/{control_id}/evidence")
async def api_control_evidence(
    control_id: str,
    user: Annotated[AuthUser, Depends(require_user)],
    framework_id: str = "",
):
    return {
        "ok": True,
        "control_id": control_id,
        "framework_id": framework_id,
        "evidence": list_evidence_for_control(
            user.id, control_id=control_id, framework_id=framework_id
        ),
    }


@router.get("/controls/{control_id}/evaluate")
async def api_evaluate(
    control_id: str,
    user: Annotated[AuthUser, Depends(require_user)],
    framework_id: str = "",
):
    return evaluate_control_from_evidence(
        user.id, control_id=control_id, framework_id=framework_id
    )


@router.get("/evidence/{evidence_id}/controls")
async def api_evidence_controls(
    evidence_id: str,
    user: Annotated[AuthUser, Depends(require_user)],
):
    return {
        "ok": True,
        "evidence_id": evidence_id,
        "controls": list_controls_for_evidence(user.id, evidence_id),
    }
