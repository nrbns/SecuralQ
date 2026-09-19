"""Recurring compliance schedules → materialize ComplianceTask instances."""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from typing import Any

from app.compliance_ops.schema import ensure_compliance_ops_schema
from app.compliance_ops.tasks import create_task
from app.db import get_conn, new_id, now, row_to_dict

RECURRENCE_DAYS = {
    "daily": 1,
    "weekly": 7,
    "monthly": 30,
    "quarterly": 90,
    "half_yearly": 182,
    "yearly": 365,
}


def _next_working_day(ts: float) -> float:
    """Skip Sat/Sun — simple working-day adjust (no holiday calendar yet)."""
    dt = datetime.fromtimestamp(ts, tz=timezone.utc)
    while dt.weekday() >= 5:  # 5=Sat 6=Sun
        dt += timedelta(days=1)
    return dt.timestamp()


def advance_due(recurrence: str, from_ts: float | None = None) -> float:
    base = from_ts if from_ts is not None else now()
    days = RECURRENCE_DAYS.get((recurrence or "").lower(), 90)
    return _next_working_day(base + days * 86400)


def create_schedule(user_id: str, payload: dict[str, Any], *, org_id: str | None = None) -> dict[str, Any]:
    ensure_compliance_ops_schema()
    from app.tenancy import primary_org_id

    title = (payload.get("title") or "").strip()
    if not title:
        raise ValueError("title required")
    recurrence = (payload.get("recurrence") or "quarterly").strip().lower()
    next_due = payload.get("next_due_at")
    if next_due is None:
        next_due = advance_due(recurrence)
    else:
        next_due = _next_working_day(float(next_due))
    sid = new_id()
    t = now()
    oid = org_id or primary_org_id(user_id)
    get_conn().execute(
        """
        INSERT INTO compliance_schedules (
            id, user_id, org_id, framework_id, requirement_id, control_id,
            title, description, task_kind, department, owner_id, reviewer_id, manager_id,
            recurrence, next_due_at, evidence_required, approval_required, risk_weight,
            live_test_name, enabled, meta_json, created_at, updated_at
        ) VALUES (?,?,?,?,?,?, ?,?,?,?,?,?,?, ?,?,?,?,?, ?,?,?,?,?)
        """,
        (
            sid,
            user_id,
            oid,
            (payload.get("framework_id") or "").strip(),
            (payload.get("requirement_id") or "").strip(),
            (payload.get("control_id") or "").strip(),
            title[:300],
            (payload.get("description") or "")[:4000],
            (payload.get("task_kind") or "manual").strip().lower(),
            (payload.get("department") or "").strip()[:120],
            (payload.get("owner_id") or user_id).strip()[:120],
            (payload.get("reviewer_id") or "").strip()[:120],
            (payload.get("manager_id") or "").strip()[:120],
            recurrence,
            next_due,
            1 if payload.get("evidence_required", True) else 0,
            1 if payload.get("approval_required") else 0,
            float(payload.get("risk_weight") or 1.0),
            (payload.get("live_test_name") or "").strip()[:120],
            1 if payload.get("enabled", True) else 0,
            json.dumps(payload.get("meta") or {}),
            t,
            t,
        ),
    )
    get_conn().commit()
    return get_schedule(user_id, sid) or {}


def get_schedule(user_id: str, schedule_id: str) -> dict[str, Any] | None:
    ensure_compliance_ops_schema()
    row = get_conn().execute(
        "SELECT * FROM compliance_schedules WHERE id = ? AND user_id = ?",
        (schedule_id, user_id),
    ).fetchone()
    return row_to_dict(row) if row else None


def list_schedules(user_id: str, *, enabled_only: bool = False) -> list[dict[str, Any]]:
    ensure_compliance_ops_schema()
    q = "SELECT * FROM compliance_schedules WHERE user_id = ?"
    args: list[Any] = [user_id]
    if enabled_only:
        q += " AND enabled = 1"
    q += " ORDER BY next_due_at ASC"
    return [row_to_dict(r) for r in get_conn().execute(q, args).fetchall()]


def materialize_due_from_schedules(user_id: str, *, horizon_days: int = 14) -> dict[str, Any]:
    """Create tasks for schedules whose next_due_at is within horizon (and not already open)."""
    ensure_compliance_ops_schema()
    horizon = now() + max(1, horizon_days) * 86400
    created: list[str] = []
    for sched in list_schedules(user_id, enabled_only=True):
        due = float(sched.get("next_due_at") or 0)
        if not due or due > horizon:
            continue
        # Skip if an open task already exists for this schedule near this due
        existing = get_conn().execute(
            """
            SELECT id FROM compliance_tasks
            WHERE user_id = ? AND schedule_id = ? AND status NOT IN ('completed','cancelled')
            LIMIT 1
            """,
            (user_id, sched["id"]),
        ).fetchone()
        if existing:
            continue
        task = create_task(
            user_id,
            {
                "schedule_id": sched["id"],
                "framework_id": sched.get("framework_id"),
                "requirement_id": sched.get("requirement_id"),
                "control_id": sched.get("control_id"),
                "title": sched.get("title"),
                "description": sched.get("description"),
                "task_kind": sched.get("task_kind") or "manual",
                "department": sched.get("department"),
                "owner_id": sched.get("owner_id") or user_id,
                "reviewer_id": sched.get("reviewer_id"),
                "manager_id": sched.get("manager_id"),
                "due_at": due,
                "evidence_due_at": due,
                "recurrence": sched.get("recurrence"),
                "evidence_required": bool(sched.get("evidence_required")),
                "approval_required": bool(sched.get("approval_required")),
                "risk_weight": sched.get("risk_weight"),
                "live_test_name": sched.get("live_test_name"),
                "status": "upcoming",
            },
            org_id=sched.get("org_id"),
        )
        created.append(task["id"])
        # Advance schedule next due
        nxt = advance_due(str(sched.get("recurrence") or "quarterly"), from_ts=due)
        get_conn().execute(
            "UPDATE compliance_schedules SET next_due_at = ?, updated_at = ? WHERE id = ?",
            (nxt, now(), sched["id"]),
        )
        get_conn().commit()
    return {"ok": True, "created_task_ids": created, "count": len(created)}
