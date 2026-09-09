"""FastAPI routes for the Control & Configuration Engine (Sprint 1).

Prefix: ``/api/controls``
"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query

from app.auth import AuthUser
from app.commercial_api import require_user
from app.controls.catalog import (
    control_center_summary,
    framework_meta,
    get_control,
    list_framework_controls,
    verifiability_map,
)
from app.controls.test_engine import get_control_with_live_results, run_control_tests
from app.gap_analysis import load_framework

router = APIRouter(prefix="/api/controls", tags=["controls"])


def _ensure_framework(framework_id: str) -> dict:
    try:
        return load_framework(framework_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.get("/summary")
async def api_control_summary(
    user: Annotated[AuthUser, Depends(require_user)],
    framework_id: str = Query(default="cmmc_l2"),
):
    """Control Center counts — live test rollups when available; honest zeros otherwise."""
    _ensure_framework(framework_id)
    return control_center_summary(user.id, framework_id=framework_id)


@router.get("/catalog/{framework_id}")
async def api_catalog(framework_id: str, _user: Annotated[AuthUser, Depends(require_user)]):
    """Full normalized control catalog for a framework."""
    meta = framework_meta(framework_id)
    controls = list_framework_controls(framework_id)
    return {
        "framework": meta.to_dict(),
        "controls": [c.to_dict() for c in controls],
        "control_count": len(controls),
    }


@router.get("/catalog/{framework_id}/{control_id}")
async def api_get_control(
    framework_id: str,
    control_id: str,
    user: Annotated[AuthUser, Depends(require_user)],
):
    """One control with last live-test results + why-failing detail when available."""
    _ensure_framework(framework_id)
    result = get_control_with_live_results(user.id, framework_id, control_id)
    if not result:
        # Distinguish unknown framework (already 404) vs unknown control
        if get_control(framework_id, control_id) is None:
            raise HTTPException(status_code=404, detail="Control not found")
        raise HTTPException(status_code=404, detail="Control not found")
    return result


@router.post("/test/{framework_id}/{control_id}")
async def api_run_control_test(
    framework_id: str,
    control_id: str,
    user: Annotated[AuthUser, Depends(require_user)],
):
    """Run curated live tests for this control now (explicit map only)."""
    _ensure_framework(framework_id)
    if get_control(framework_id, control_id) is None:
        raise HTTPException(status_code=404, detail="Control not found")
    return run_control_tests(user.id, framework_id, control_id)


@router.get("/verifiability/{framework_id}")
async def api_verifiability(
    framework_id: str, _user: Annotated[AuthUser, Depends(require_user)]
):
    """machine | partial | human | unknown per control based on live-test map."""
    _ensure_framework(framework_id)
    return verifiability_map(framework_id)
