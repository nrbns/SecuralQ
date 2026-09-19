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


@router.get("/results/history")
async def api_control_results_history(
    user: Annotated[AuthUser, Depends(require_user)],
    framework_id: str | None = Query(default=None),
    control_id: str | None = Query(default=None),
    agent_id: str | None = Query(default=None),
    limit: int = Query(default=100, ge=1, le=500),
):
    """Append-only control_results history (PASS/FAIL trail)."""
    from app.controls.history import list_control_results

    rows = list_control_results(
        user.id,
        framework_id=framework_id,
        control_id=control_id,
        agent_id=agent_id,
        limit=limit,
    )
    return {"ok": True, "count": len(rows), "results": rows}


@router.get("/production-profile")
async def api_controls_production_profile(_user: Annotated[AuthUser, Depends(require_user)]):
    """Agent-security production toggles (read-only status)."""
    from app.production_profile import production_profile_status

    return production_profile_status()


@router.get("/registry")
async def api_controls_registry(_user: Annotated[AuthUser, Depends(require_user)]):
    """Curated + optional custom control-test registry (read-only)."""
    from app.controls.test_registry import list_registry, load_custom_registry_overrides

    curated = list_registry()
    custom = load_custom_registry_overrides()
    return {
        "ok": True,
        "count": len(curated),
        "custom_override_count": len(custom),
        "tests": curated,
        "note": (
            "Custom bindings: data/controls/custom_tests.json (see custom_tests.example.json). "
            "New test_names need an evaluator in control_testing to execute."
        ),
    }


@router.get("/requirements")
async def api_requirements_index(user: Annotated[AuthUser, Depends(require_user)]):
    """First-class Requirement index across frameworks (domain groupings)."""
    from app.controls.requirements import requirements_index

    return requirements_index(user_id=user.id)


@router.get("/requirements/{framework_id}")
async def api_list_requirements(
    framework_id: str,
    user: Annotated[AuthUser, Depends(require_user)],
):
    """List Requirement entities for one framework."""
    _ensure_framework(framework_id)
    from app.controls.requirements import list_requirements

    rows = list_requirements(framework_id, user_id=user.id)
    return {
        "ok": True,
        "framework_id": framework_id,
        "count": len(rows),
        "requirements": rows,
        "chain": [
            "framework",
            "requirement",
            "control",
            "test",
            "evidence",
            "finding",
            "remediation",
            "verification",
        ],
        "note": "Domain groupings of catalog controls — helps assess requirements, not certify.",
    }


@router.get("/requirements/{framework_id}/{requirement_id}")
async def api_get_requirement(
    framework_id: str,
    requirement_id: str,
    user: Annotated[AuthUser, Depends(require_user)],
):
    """One Requirement with nested controls + live-test bindings."""
    _ensure_framework(framework_id)
    from app.controls.requirements import get_requirement

    row = get_requirement(framework_id, requirement_id, user_id=user.id)
    if not row:
        raise HTTPException(status_code=404, detail="Requirement not found")
    return {"ok": True, "requirement": row}
