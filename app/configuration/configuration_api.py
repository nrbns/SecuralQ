"""Configuration Center API — baselines, observations, drift (Sprint 2).

Honesty: operating-effectiveness signals only — not CMMC certification / SPRS.
"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, Query

from app.auth import AuthUser
from app.commercial_api import require_user
from app.configuration.baselines import default_baseline_id, get_baseline, list_baselines
from app.configuration.drift import list_drift_for_user
from app.configuration.observe import ensure_observations_schema, list_observations

router = APIRouter(prefix="/api/configuration", tags=["configuration"])


@router.get("/baselines")
async def api_list_baselines(_user: Annotated[AuthUser, Depends(require_user)]):
    return {
        "baselines": list_baselines(),
        "default_baseline_id": default_baseline_id(),
        "disclaimer": (
            "Baselines drive observe/drift signals from agent telemetry. "
            "Not a CMMC certification or SPRS score."
        ),
    }


@router.get("/baselines/{baseline_id}")
async def api_get_baseline(baseline_id: str, _user: Annotated[AuthUser, Depends(require_user)]):
    b = get_baseline(baseline_id)
    if not b:
        from fastapi import HTTPException

        raise HTTPException(status_code=404, detail="Baseline not found")
    return b


@router.get("/drift")
async def api_list_drift(
    user: Annotated[AuthUser, Depends(require_user)],
    baseline_id: str | None = Query(default=None),
    limit: int = Query(default=50, ge=1, le=200),
):
    ensure_observations_schema()
    items = list_drift_for_user(user.id, baseline_id=baseline_id, limit=limit)
    return {
        "baseline_id": (baseline_id or default_baseline_id()).strip(),
        "drift": items,
        "count": len(items),
        "disclaimer": "Live drift vs seeded baseline — not an assessment finding.",
    }


@router.get("/observations")
async def api_list_observations(
    user: Annotated[AuthUser, Depends(require_user)],
    key: str | None = Query(default=None),
    agent_id: str | None = Query(default=None),
    limit: int = Query(default=100, ge=1, le=500),
):
    ensure_observations_schema()
    rows = list_observations(user.id, key=key, agent_id=agent_id, limit=limit)
    return {"observations": rows, "count": len(rows)}
