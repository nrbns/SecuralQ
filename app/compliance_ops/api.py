"""FastAPI routes for Compliance Operations (Calendar + Workflow Engine).

Prefix: ``/api/compliance-ops``
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

from app.auth import AuthUser
from app.commercial_api import require_user
from app.compliance_ops.automation import run_compliance_ops_tick
from app.compliance_ops.schedules import create_schedule, list_schedules, materialize_due_from_schedules
from app.compliance_ops.seed import seed_default_schedules
from app.compliance_ops.tasks import (
    calendar_month,
    complete_task,
    create_task,
    escalate_task,
    get_task,
    list_tasks,
    management_summary,
    my_work_queue,
    submit_evidence,
    update_task,
)

router = APIRouter(prefix="/api/compliance-ops", tags=["compliance-ops"])


class TaskCreate(BaseModel):
    title: str = Field(min_length=1, max_length=300)
    description: str = ""
    task_kind: str = "manual"
    department: str = ""
    owner_id: str = ""
    reviewer_id: str = ""
    manager_id: str = ""
    framework_id: str = ""
    requirement_id: str = ""
    control_id: str = ""
    status: str = "upcoming"
    priority: str = "medium"
    due_at: float | None = None
    evidence_due_at: float | None = None
    recurrence: str = "one_time"
    evidence_required: bool = True
    approval_required: bool = False
    risk_weight: float = 1.0
    live_test_name: str = ""
    schedule_id: str = ""


class TaskPatch(BaseModel):
    title: str | None = None
    description: str | None = None
    department: str | None = None
    owner_id: str | None = None
    reviewer_id: str | None = None
    manager_id: str | None = None
    status: str | None = None
    priority: str | None = None
    due_at: float | None = None
    evidence_due_at: float | None = None
    evidence_required: bool | None = None
    approval_required: bool | None = None


class EvidenceBody(BaseModel):
    note: str = ""
    evidence_id: str = ""


class EscalateBody(BaseModel):
    reason: str = ""


class ScheduleCreate(BaseModel):
    title: str = Field(min_length=1, max_length=300)
    description: str = ""
    task_kind: str = "manual"
    department: str = ""
    owner_id: str = ""
    reviewer_id: str = ""
    manager_id: str = ""
    framework_id: str = ""
    requirement_id: str = ""
    control_id: str = ""
    recurrence: str = "quarterly"
    next_due_at: float | None = None
    evidence_required: bool = True
    approval_required: bool = False
    risk_weight: float = 1.0
    live_test_name: str = ""
    enabled: bool = True


@router.get("/summary")
async def api_summary(user: Annotated[AuthUser, Depends(require_user)]):
    return management_summary(user.id)


@router.get("/my-work")
async def api_my_work(
    user: Annotated[AuthUser, Depends(require_user)],
    owner_id: str | None = None,
):
    return my_work_queue(user.id, owner_id=owner_id or user.id)


@router.get("/calendar")
async def api_calendar(
    user: Annotated[AuthUser, Depends(require_user)],
    year: int | None = None,
    month: int | None = None,
):
    now = datetime.now(timezone.utc)
    y = year or now.year
    m = month or now.month
    if m < 1 or m > 12:
        raise HTTPException(status_code=400, detail="month must be 1-12")
    return calendar_month(user.id, year=y, month=m)


@router.get("/tasks")
async def api_list_tasks(
    user: Annotated[AuthUser, Depends(require_user)],
    status: str | None = None,
    department: str | None = None,
    owner_id: str | None = None,
    limit: int = Query(default=200, ge=1, le=500),
):
    return {
        "ok": True,
        "tasks": list_tasks(
            user.id,
            status=status,
            department=department,
            owner_id=owner_id,
            limit=limit,
        ),
    }


@router.post("/tasks")
async def api_create_task(
    body: TaskCreate,
    user: Annotated[AuthUser, Depends(require_user)],
):
    try:
        task = create_task(user.id, body.model_dump())
        return {"ok": True, "task": task}
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/tasks/{task_id}")
async def api_get_task(task_id: str, user: Annotated[AuthUser, Depends(require_user)]):
    task = get_task(user.id, task_id)
    if not task:
        raise HTTPException(status_code=404, detail="task not found")
    return {"ok": True, "task": task}


@router.patch("/tasks/{task_id}")
async def api_patch_task(
    task_id: str,
    body: TaskPatch,
    user: Annotated[AuthUser, Depends(require_user)],
):
    try:
        patch = {k: v for k, v in body.model_dump().items() if v is not None}
        task = update_task(user.id, task_id, patch)
        return {"ok": True, "task": task}
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post("/tasks/{task_id}/evidence")
async def api_evidence(
    task_id: str,
    body: EvidenceBody,
    user: Annotated[AuthUser, Depends(require_user)],
):
    try:
        task = submit_evidence(user.id, task_id, note=body.note, evidence_id=body.evidence_id)
        return {"ok": True, "task": task}
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post("/tasks/{task_id}/complete")
async def api_complete(
    task_id: str,
    user: Annotated[AuthUser, Depends(require_user)],
    force: bool = False,
):
    try:
        task = complete_task(user.id, task_id, force=force)
        return {"ok": True, "task": task}
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post("/tasks/{task_id}/escalate")
async def api_escalate(
    task_id: str,
    body: EscalateBody,
    user: Annotated[AuthUser, Depends(require_user)],
):
    try:
        task = escalate_task(user.id, task_id, reason=body.reason)
        return {"ok": True, "task": task}
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/schedules")
async def api_list_schedules(user: Annotated[AuthUser, Depends(require_user)]):
    return {"ok": True, "schedules": list_schedules(user.id)}


@router.post("/schedules")
async def api_create_schedule(
    body: ScheduleCreate,
    user: Annotated[AuthUser, Depends(require_user)],
):
    try:
        sched = create_schedule(user.id, body.model_dump())
        return {"ok": True, "schedule": sched}
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post("/seed")
async def api_seed(
    user: Annotated[AuthUser, Depends(require_user)],
    force: bool = False,
):
    return seed_default_schedules(user.id, force=force)


@router.post("/materialize")
async def api_materialize(
    user: Annotated[AuthUser, Depends(require_user)],
    horizon_days: int = Query(default=21, ge=1, le=90),
):
    return materialize_due_from_schedules(user.id, horizon_days=horizon_days)


@router.post("/tick")
async def api_tick(user: Annotated[AuthUser, Depends(require_user)]):
    """Run reminder/escalation tick for the current user (also scheduled globally)."""
    return run_compliance_ops_tick(user.id)
