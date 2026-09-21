"""API for Evidence Spine — Observation/Document → Evidence → Control + Vault."""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile
from pydantic import BaseModel, Field

from app.auth import AuthUser
from app.commercial_api import require_user
from app.evidence_spine.control_state import (
    get_control_state,
    list_control_states,
    reconcile_control,
    run_stale_tick,
    transition_control_state,
)
from app.evidence_spine.dependencies import (
    evaluate_dependencies,
    list_requirements,
    seed_default_packs,
    upsert_requirement,
)
from app.evidence_spine.evaluate import evaluate_control_from_evidence
from app.evidence_spine.freshness import apply_freshness_to_result, list_freshness_policies
from app.evidence_spine.ingest import ingest_document_as_evidence, ingest_observation_as_evidence
from app.evidence_spine.mapping import (
    link_evidence_to_control,
    list_controls_for_evidence,
    list_evidence_for_control,
    unlink_evidence_from_control,
)
from app.evidence_spine.vault import (
    create_vault_document,
    get_vault_item,
    list_vault,
    set_review_status,
    supersede_vault_document,
)
from app.upload_validation import UploadValidationError

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


class ReviewIn(BaseModel):
    status: str = Field(min_length=1, max_length=40)
    note: str = ""


class FreshnessIn(BaseModel):
    result: str = "pass"
    last_observed: float | None = None
    control_or_test: str = Field(min_length=1, max_length=120)


class RequirementIn(BaseModel):
    control_id: str = Field(min_length=1, max_length=120)
    slot_key: str = Field(min_length=1, max_length=80)
    title: str = ""
    framework_id: str = ""
    required_role: str = "supports"
    min_count: int = 1


class ReconcileIn(BaseModel):
    framework_id: str = ""
    test_name: str = ""


class TransitionIn(BaseModel):
    control_id: str = Field(min_length=1, max_length=120)
    state: str = Field(min_length=1, max_length=40)
    framework_id: str = ""
    source: str = "api"
    evidence_ids: list[str] = Field(default_factory=list)
    detail: dict[str, Any] = Field(default_factory=dict)


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


@router.get("/vault")
async def api_list_vault(
    user: Annotated[AuthUser, Depends(require_user)],
    kind: str = "",
    limit: int = 100,
):
    return {"ok": True, "items": list_vault(user.id, kind=kind, limit=limit)}


@router.get("/vault/{vault_id}")
async def api_get_vault(vault_id: str, user: Annotated[AuthUser, Depends(require_user)]):
    item = get_vault_item(user.id, vault_id)
    if not item:
        raise HTTPException(status_code=404, detail="vault item not found")
    return item


@router.post("/vault/upload")
async def api_vault_upload(
    user: Annotated[AuthUser, Depends(require_user)],
    file: UploadFile = File(...),
    title: str = Form(""),
    control_id: str = Form(""),
    framework_id: str = Form(""),
    kind: str = Form("document"),
    notes: str = Form(""),
    retention_days: int | None = Form(None),
):
    raw = await file.read()
    try:
        return create_vault_document(
            user.id,
            title=title or (file.filename or "Evidence"),
            filename=file.filename or "upload.bin",
            data=raw,
            kind=kind,
            control_id=control_id,
            framework_id=framework_id,
            notes=notes,
            retention_days=retention_days,
        )
    except (ValueError, UploadValidationError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post("/vault/{vault_id}/supersede")
async def api_vault_supersede(
    vault_id: str,
    user: Annotated[AuthUser, Depends(require_user)],
    file: UploadFile = File(...),
    notes: str = Form(""),
):
    raw = await file.read()
    try:
        return supersede_vault_document(
            user.id,
            vault_id,
            filename=file.filename or "upload.bin",
            data=raw,
            notes=notes,
        )
    except (ValueError, UploadValidationError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post("/vault/{vault_id}/review")
async def api_vault_review(
    vault_id: str,
    body: ReviewIn,
    user: Annotated[AuthUser, Depends(require_user)],
):
    try:
        return set_review_status(user.id, vault_id, status=body.status, note=body.note)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/freshness-policies")
async def api_freshness_policies(_user: Annotated[AuthUser, Depends(require_user)]):
    return {"ok": True, "policies": list_freshness_policies()}


@router.post("/freshness/apply")
async def api_freshness_apply(
    body: FreshnessIn,
    _user: Annotated[AuthUser, Depends(require_user)],
):
    return apply_freshness_to_result(
        result=body.result,
        last_observed=body.last_observed,
        control_or_test=body.control_or_test,
    )


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


# ── Dependency packs ─────────────────────────────────────────────────────────


@router.get("/dependencies")
async def api_list_dependencies(
    user: Annotated[AuthUser, Depends(require_user)],
    control_id: str = "",
    framework_id: str = "",
):
    return {
        "ok": True,
        "requirements": list_requirements(
            user.id, control_id=control_id, framework_id=framework_id
        ),
    }


@router.post("/dependencies")
async def api_upsert_dependency(
    body: RequirementIn,
    user: Annotated[AuthUser, Depends(require_user)],
):
    try:
        return {
            "ok": True,
            "requirement": upsert_requirement(
                user.id,
                control_id=body.control_id,
                slot_key=body.slot_key,
                title=body.title,
                framework_id=body.framework_id,
                required_role=body.required_role,
                min_count=body.min_count,
            ),
        }
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post("/dependencies/seed")
async def api_seed_dependencies(
    user: Annotated[AuthUser, Depends(require_user)],
    force: bool = False,
):
    return seed_default_packs(user.id, force=force)


@router.get("/controls/{control_id}/dependencies")
async def api_control_dependencies(
    control_id: str,
    user: Annotated[AuthUser, Depends(require_user)],
    framework_id: str = "",
):
    return evaluate_dependencies(
        user.id, control_id=control_id, framework_id=framework_id
    )


# ── Control runtime state ─────────────────────────────────────────────────────


@router.get("/control-state")
async def api_list_control_state(
    user: Annotated[AuthUser, Depends(require_user)],
    state: str = "",
    limit: int = 200,
):
    return {"ok": True, "states": list_control_states(user.id, state=state, limit=limit)}


@router.get("/controls/{control_id}/state")
async def api_get_control_state(
    control_id: str,
    user: Annotated[AuthUser, Depends(require_user)],
    framework_id: str = "",
):
    row = get_control_state(user.id, control_id=control_id, framework_id=framework_id)
    if not row:
        return {"ok": True, "state": None, "control_id": control_id, "framework_id": framework_id}
    return {"ok": True, "state": row}


@router.post("/controls/{control_id}/reconcile")
async def api_reconcile_control(
    control_id: str,
    user: Annotated[AuthUser, Depends(require_user)],
    body: ReconcileIn | None = None,
):
    body = body or ReconcileIn()
    return reconcile_control(
        user.id,
        control_id=control_id,
        framework_id=body.framework_id,
        test_name=body.test_name,
    )


@router.post("/control-state/transition")
async def api_transition_control(
    body: TransitionIn,
    user: Annotated[AuthUser, Depends(require_user)],
):
    try:
        return {
            "ok": True,
            "state": transition_control_state(
                user.id,
                control_id=body.control_id,
                new_state=body.state,
                framework_id=body.framework_id,
                source=body.source,
                evidence_ids=body.evidence_ids,
                detail=body.detail,
            ),
        }
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post("/control-state/stale-tick")
async def api_stale_tick(user: Annotated[AuthUser, Depends(require_user)]):
    return run_stale_tick(user.id)
