"""Continuous Posture Engine API — dashboard, refresh now, history, drift."""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

from app.auth import AuthUser
from app.commercial_api import require_user
from app.posture.drift import create_baseline, detect_drift, latest_baseline
from app.posture.orchestrator import run_posture_refresh
from app.posture.refresh_policy import (
    architecture_layers,
    get_org_interval,
    list_refresh_policies,
    set_org_interval,
)
from app.posture.refresh_run import get_refresh_run, list_refresh_runs
from app.posture.views import (
    posture_dashboard,
    posture_health,
    posture_history,
    what_changed_since,
)

router = APIRouter(prefix="/api/posture", tags=["posture-engine"])


class RefreshNowIn(BaseModel):
    force: bool = False
    async_enqueue: bool = True


class SettingsIn(BaseModel):
    interval_sec: int = Field(ge=60, le=86400)
    jitter_sec: int | None = Field(default=None, ge=0, le=3600)
    enabled: bool = True


class BaselineIn(BaseModel):
    name: str = "Baseline"


@router.get("/dashboard")
async def api_posture_dashboard(user: Annotated[AuthUser, Depends(require_user)]):
    return posture_dashboard(user.id)


@router.get("/health")
async def api_posture_health():
    """Unauthenticated-ish ops probe — still require user for consistency."""
    return posture_health()


@router.get("/health/auth")
async def api_posture_health_auth(_user: Annotated[AuthUser, Depends(require_user)]):
    return posture_health()


@router.get("/runs")
async def api_list_runs(
    user: Annotated[AuthUser, Depends(require_user)],
    limit: int = Query(20, ge=1, le=100),
    status: str = Query(""),
):
    return {"ok": True, "runs": list_refresh_runs(user.id, limit=limit, status=status)}


@router.get("/runs/{run_id}")
async def api_get_run(run_id: str, user: Annotated[AuthUser, Depends(require_user)]):
    row = get_refresh_run(user.id, run_id)
    if not row:
        raise HTTPException(status_code=404, detail="Refresh run not found")
    return {"ok": True, "run": row}


@router.post("/refresh")
async def api_refresh_now(
    user: Annotated[AuthUser, Depends(require_user)],
    body: RefreshNowIn | None = None,
):
    """Refresh Now — org lock + optional async job enqueue (never deep scanners)."""
    force = bool(body.force) if body else False
    async_q = True if body is None else bool(body.async_enqueue)
    if async_q:
        try:
            from app.jobs import enqueue_job

            job = enqueue_job(
                "posture_refresh",
                {
                    "user_id": user.id,
                    "manual": True,
                    "force": force,
                    "priority": "P2",
                },
            )
            return {
                "ok": True,
                "queued": True,
                "job_id": job.get("id"),
                "status": "queued",
                "note": "Posture refresh queued — Layer B only (no Nmap/Nuclei/ZAP).",
            }
        except Exception:
            pass
    return run_posture_refresh(user.id, trigger="manual", force=force)


@router.get("/history")
async def api_history(
    user: Annotated[AuthUser, Depends(require_user)],
    limit: int = Query(48, ge=1, le=200),
):
    return posture_history(user.id, limit=limit)


@router.get("/what-changed")
async def api_what_changed(user: Annotated[AuthUser, Depends(require_user)]):
    return what_changed_since(user.id)


@router.get("/policies")
async def api_policies(_user: Annotated[AuthUser, Depends(require_user)]):
    return {
        "ok": True,
        "policies": list_refresh_policies(),
        "layers": architecture_layers(),
    }


@router.get("/settings")
async def api_get_settings(user: Annotated[AuthUser, Depends(require_user)]):
    return {"ok": True, **get_org_interval(user.id)}


@router.post("/settings")
async def api_set_settings(
    body: SettingsIn, user: Annotated[AuthUser, Depends(require_user)]
):
    try:
        return {
            "ok": True,
            **set_org_interval(
                user.id,
                interval_sec=body.interval_sec,
                jitter_sec=body.jitter_sec,
                enabled=body.enabled,
            ),
        }
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post("/baseline")
async def api_create_baseline(
    user: Annotated[AuthUser, Depends(require_user)],
    body: BaselineIn | None = None,
):
    try:
        return create_baseline(user.id, name=(body.name if body else "Baseline"))
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/baseline")
async def api_latest_baseline(user: Annotated[AuthUser, Depends(require_user)]):
    b = latest_baseline(user.id)
    return {"ok": True, "baseline": b}


@router.get("/drift")
async def api_drift(user: Annotated[AuthUser, Depends(require_user)]):
    return detect_drift(user.id)
