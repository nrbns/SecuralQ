"""Gap analysis catalog & assessment read/export APIs."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import PlainTextResponse, Response

from app.auth import AuthUser
from app.commercial_api import require_user
from app.evidence_workflow import (
    build_audit_pack_zip,
    evidence_coverage_for_assessment,
    missing_evidence_queue,
)
from app.gap_analysis import (
    delete_assessment,
    ensure_gap_schema,
    export_gap_markdown,
    get_assessment,
    list_assessments,
    list_frameworks,
    load_framework,
)
from app.services.compliance_center import audit_center_overview, compliance_overview
from app.services.control_testing import controls_with_live_tests, run_live_tests_for_framework

router = APIRouter(prefix="/api", tags=["gap-analysis"])


@router.get("/frameworks")
async def frameworks():
    return {"frameworks": list_frameworks()}


@router.get("/frameworks/{framework_id}")
async def framework_detail(framework_id: str):
    try:
        return load_framework(framework_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.get("/gap/assessments")
async def gap_list(
    user: Annotated[AuthUser, Depends(require_user)],
    engagement_id: str | None = None,
):
    ensure_gap_schema()
    return {"assessments": list_assessments(user.id, engagement_id)}


@router.get("/gap/assessments/{assessment_id}")
async def gap_get(assessment_id: str, user: Annotated[AuthUser, Depends(require_user)]):
    data = get_assessment(user.id, assessment_id)
    if not data:
        raise HTTPException(status_code=404, detail="Not found")
    return data


@router.delete("/gap/assessments/{assessment_id}")
async def gap_delete(assessment_id: str, user: Annotated[AuthUser, Depends(require_user)]):
    if not delete_assessment(user.id, assessment_id):
        raise HTTPException(status_code=404, detail="Not found")
    return {"ok": True}


@router.get("/gap/assessments/{assessment_id}/export")
async def gap_export(assessment_id: str, user: Annotated[AuthUser, Depends(require_user)]):
    try:
        md = export_gap_markdown(user.id, assessment_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    return PlainTextResponse(md, media_type="text/markdown; charset=utf-8")


@router.get("/gap/assessments/{assessment_id}/coverage")
async def gap_coverage(assessment_id: str, user: Annotated[AuthUser, Depends(require_user)]):
    try:
        return evidence_coverage_for_assessment(user.id, assessment_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.get("/gap/assessments/{assessment_id}/audit-pack")
async def gap_audit_pack(assessment_id: str, user: Annotated[AuthUser, Depends(require_user)]):
    """ZIP audit pack: matrix + evidence index + accepted artifacts (not a certification)."""
    try:
        data = build_audit_pack_zip(user.id, assessment_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    return Response(
        content=data,
        media_type="application/zip",
        headers={
            "Content-Disposition": f'attachment; filename="securaiq-audit-pack-{assessment_id[:12]}.zip"'
        },
    )


@router.get("/gap/live-tests/{framework_id}")
async def gap_live_tests(framework_id: str, user: Annotated[AuthUser, Depends(require_user)]):
    """Control status computed directly from real product data (assets,
    vulnerabilities, patch inventory) -- no pasted evidence text required.
    Only controls with an explicit, hand-curated live test mapping (see
    app.services.control_testing._CONTROL_TEST_MAP) are included; every
    other control in the framework simply has no live test yet. Each
    result is also recorded to the Evidence Store."""
    try:
        load_framework(framework_id)  # 404s on an unknown framework id/alias
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    return {
        "framework_id": framework_id,
        "tested_control_ids": sorted(controls_with_live_tests(framework_id)),
        "results": run_live_tests_for_framework(user.id, framework_id),
    }


@router.get("/compliance/overview")
async def compliance_overview_route(
    user: Annotated[AuthUser, Depends(require_user)], org_id: str | None = None
):
    """Compliance Center: overall %, per-framework breakdown, evidence
    expiring soon, exception coverage -- built entirely from real
    gap_assessments/evidence_links/securaiq_exceptions rows, never
    hardcoded, and never counting an unassessed framework toward the
    percentage."""
    return compliance_overview(user.id, org_id=org_id)


@router.get("/compliance/audit-center")
async def audit_center_route(
    user: Annotated[AuthUser, Depends(require_user)], org_id: str | None = None
):
    """Audit Center: evidence requested/supplied/missing and control
    passing/failing/pending, rolled up across every framework's latest
    assessment. Per-assessment ZIP export stays at
    /gap/assessments/{id}/audit-pack."""
    return audit_center_overview(user.id, org_id=org_id)


@router.get("/gap/evidence-queue")
async def gap_evidence_queue(
    user: Annotated[AuthUser, Depends(require_user)],
    assessment_id: str | None = None,
    limit: int = 80,
):
    """Missing/partial controls with no accepted evidence — collect-next queue."""
    try:
        return missing_evidence_queue(
            user.id, assessment_id=assessment_id, limit=min(200, max(1, limit))
        )
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
