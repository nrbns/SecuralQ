"""Compliance task CRUD + work queue + management summary."""

from __future__ import annotations

import json
import time
from datetime import datetime, timezone
from typing import Any

from app.compliance_ops.schema import ensure_compliance_ops_schema
from app.db import get_conn, new_id, now, row_to_dict

STATUSES = {
    "backlog",
    "upcoming",
    "in_progress",
    "review",
    "approval",
    "completed",
    "cancelled",
}
OPEN_STATUSES = {"backlog", "upcoming", "in_progress", "review", "approval"}
TASK_KINDS = {"automated", "assisted", "manual"}
PRIORITIES = {"critical", "high", "medium", "low"}
RECURRENCES = {
    "one_time",
    "daily",
    "weekly",
    "monthly",
    "quarterly",
    "half_yearly",
    "yearly",
    "custom",
}


def _publish(event_type: str, user_id: str, **extra: Any) -> None:
    try:
        from app.realtime_bus import publish

        publish(
            type=event_type,
            event_type=event_type,
            user_id=user_id,
            **extra,
        )
    except Exception:
        pass


def _notify(user_id: str, title: str, body: str, *, link: str = "/#compliance_ops") -> None:
    if not user_id:
        return
    try:
        from app.notifications import notify

        notify(user_id, "remediation_due", title, body, link=link)
    except Exception:
        try:
            from app.notifications import create_notification

            create_notification(user_id, "info", title, body, link=link)
        except Exception:
            pass


def _record_event(task_id: str, user_id: str, event_type: str, detail: str = "") -> None:
    c = get_conn()
    c.execute(
        "INSERT INTO compliance_task_events (id, task_id, user_id, event_type, detail, created_at) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        (new_id(), task_id, user_id, event_type, (detail or "")[:2000], now()),
    )
    c.commit()


def _row(task_id: str) -> dict[str, Any] | None:
    row = get_conn().execute(
        "SELECT * FROM compliance_tasks WHERE id = ?", (task_id,)
    ).fetchone()
    return row_to_dict(row) if row else None


def _enrich(task: dict[str, Any]) -> dict[str, Any]:
    out = dict(task)
    due = float(out.get("due_at") or 0)
    status = str(out.get("status") or "")
    t = time.time()
    out["overdue"] = bool(due and status in OPEN_STATUSES and due < t)
    out["days_until_due"] = None
    if due:
        out["days_until_due"] = int((due - t) / 86400)
    out["due_label"] = (
        datetime.fromtimestamp(due, tz=timezone.utc).strftime("%Y-%m-%d") if due else None
    )
    try:
        meta = json.loads(out.get("meta_json") or "{}")
        out["meta"] = meta if isinstance(meta, dict) else {}
    except Exception:
        out["meta"] = {}
    if out["meta"].get("evidence_id"):
        out["evidence_id"] = out["meta"]["evidence_id"]
    return out


def create_task(
    user_id: str,
    payload: dict[str, Any],
    *,
    org_id: str | None = None,
) -> dict[str, Any]:
    ensure_compliance_ops_schema()
    from app.tenancy import primary_org_id

    title = (payload.get("title") or "").strip()
    if not title:
        raise ValueError("title required")
    kind = (payload.get("task_kind") or "manual").strip().lower()
    if kind not in TASK_KINDS:
        kind = "manual"
    status = (payload.get("status") or "upcoming").strip().lower()
    if status not in STATUSES:
        status = "upcoming"
    priority = (payload.get("priority") or "medium").strip().lower()
    if priority not in PRIORITIES:
        priority = "medium"
    recurrence = (payload.get("recurrence") or "one_time").strip().lower()
    if recurrence not in RECURRENCES:
        recurrence = "one_time"
    due_at = payload.get("due_at")
    if due_at is not None:
        due_at = float(due_at)
    evidence_due = payload.get("evidence_due_at")
    if evidence_due is None:
        evidence_due = due_at
    elif evidence_due is not None:
        evidence_due = float(evidence_due)
    oid = org_id or primary_org_id(user_id)
    tid = new_id()
    t = now()
    owner = (payload.get("owner_id") or user_id or "").strip()
    c = get_conn()
    c.execute(
        """
        INSERT INTO compliance_tasks (
            id, user_id, org_id, schedule_id, framework_id, requirement_id, control_id,
            title, description, task_kind, department, owner_id, reviewer_id, manager_id,
            status, priority, due_at, evidence_due_at, completed_at, recurrence,
            evidence_required, approval_required, evidence_attached, risk_weight,
            live_test_name, escalation_level, last_reminded_at, last_escalated_at,
            overdue_notified, auto_result_json, meta_json, created_at, updated_at
        ) VALUES (
            ?,?,?,?,?,?,?, ?,?,?,?,?,?,?, ?,?,?,?,?,?, ?,?,?,?, ?,?,?,?, ?,?,?,?,?
        )
        """,
        (
            tid,
            user_id,
            oid,
            (payload.get("schedule_id") or "") or None,
            (payload.get("framework_id") or "").strip(),
            (payload.get("requirement_id") or "").strip(),
            (payload.get("control_id") or "").strip(),
            title[:300],
            (payload.get("description") or "")[:4000],
            kind,
            (payload.get("department") or "").strip()[:120],
            owner[:120],
            (payload.get("reviewer_id") or "").strip()[:120],
            (payload.get("manager_id") or "").strip()[:120],
            status,
            priority,
            due_at,
            evidence_due,
            None,
            recurrence,
            1 if payload.get("evidence_required", True) else 0,
            1 if payload.get("approval_required") else 0,
            0,
            float(payload.get("risk_weight") or 1.0),
            (payload.get("live_test_name") or "").strip()[:120],
            0,
            None,
            None,
            0,
            "",
            json.dumps(payload.get("meta") or {}),
            t,
            t,
        ),
    )
    c.commit()
    _record_event(tid, user_id, "created", title)
    task = _enrich(_row(tid) or {})
    _publish("compliance.task.created", user_id, task_id=tid, title=title, status=status)
    if owner and owner != user_id:
        _notify(owner, f"Compliance task assigned — {title}", f"Due: {task.get('due_label') or 'unset'}")
    return task


def list_tasks(
    user_id: str,
    *,
    status: str | None = None,
    department: str | None = None,
    owner_id: str | None = None,
    from_ts: float | None = None,
    to_ts: float | None = None,
    limit: int = 200,
) -> list[dict[str, Any]]:
    ensure_compliance_ops_schema()
    q = "SELECT * FROM compliance_tasks WHERE user_id = ?"
    args: list[Any] = [user_id]
    if status:
        q += " AND status = ?"
        args.append(status)
    if department:
        q += " AND department = ?"
        args.append(department)
    if owner_id:
        q += " AND owner_id = ?"
        args.append(owner_id)
    if from_ts is not None:
        q += " AND due_at >= ?"
        args.append(float(from_ts))
    if to_ts is not None:
        q += " AND due_at <= ?"
        args.append(float(to_ts))
    q += " ORDER BY CASE WHEN due_at IS NULL THEN 1 ELSE 0 END, due_at ASC LIMIT ?"
    args.append(max(1, min(int(limit), 500)))
    rows = get_conn().execute(q, args).fetchall()
    return [_enrich(row_to_dict(r)) for r in rows]


def get_task(user_id: str, task_id: str) -> dict[str, Any] | None:
    ensure_compliance_ops_schema()
    row = get_conn().execute(
        "SELECT * FROM compliance_tasks WHERE id = ? AND user_id = ?",
        (task_id, user_id),
    ).fetchone()
    if not row:
        return None
    task = _enrich(row_to_dict(row))
    evs = get_conn().execute(
        "SELECT * FROM compliance_task_events WHERE task_id = ? ORDER BY created_at DESC LIMIT 50",
        (task_id,),
    ).fetchall()
    task["events"] = [row_to_dict(e) for e in evs]
    return task


def update_task(user_id: str, task_id: str, patch: dict[str, Any]) -> dict[str, Any]:
    ensure_compliance_ops_schema()
    existing = get_task(user_id, task_id)
    if not existing:
        raise ValueError("task not found")
    fields = []
    args: list[Any] = []
    allowed = {
        "title",
        "description",
        "department",
        "owner_id",
        "reviewer_id",
        "manager_id",
        "status",
        "priority",
        "due_at",
        "evidence_due_at",
        "evidence_required",
        "approval_required",
    }
    for k, v in patch.items():
        if k not in allowed:
            continue
        if k == "status" and v not in STATUSES:
            continue
        if k == "priority" and v not in PRIORITIES:
            continue
        if k in ("evidence_required", "approval_required"):
            v = 1 if v else 0
        fields.append(f"{k} = ?")
        args.append(v)
    if not fields:
        return existing
    fields.append("updated_at = ?")
    args.append(now())
    args.extend([task_id, user_id])
    get_conn().execute(
        f"UPDATE compliance_tasks SET {', '.join(fields)} WHERE id = ? AND user_id = ?",
        args,
    )
    get_conn().commit()
    if patch.get("status"):
        _record_event(task_id, user_id, "status", str(patch["status"]))
        _publish(
            "compliance.task.updated",
            user_id,
            task_id=task_id,
            status=patch["status"],
        )
    return get_task(user_id, task_id) or existing


def submit_evidence(
    user_id: str,
    task_id: str,
    *,
    note: str = "",
    evidence_id: str = "",
) -> dict[str, Any]:
    ensure_compliance_ops_schema()
    task = get_task(user_id, task_id)
    if not task:
        raise ValueError("task not found")
    linked_id = (evidence_id or "").strip()
    # Create first-class Evidence when only a note is provided, and map to
    # the task's control when known (Document/note → Evidence, not attachment).
    if not linked_id and (note or "").strip():
        try:
            from app.evidence_spine.ingest import ingest_document_as_evidence

            spine = ingest_document_as_evidence(
                user_id,
                title=f"Task evidence — {task.get('title') or task_id}",
                summary=(note or "")[:500],
                document_id=f"task:{task_id}",
                control_id=str(task.get("control_id") or ""),
                framework_id=str(task.get("framework_id") or ""),
                detail={"task_id": task_id, "task_kind": task.get("task_kind")},
            )
            linked_id = str(spine.get("evidence_id") or "")
        except Exception:
            linked_id = ""
    elif linked_id and (task.get("control_id") or "").strip():
        try:
            from app.evidence_spine.mapping import link_evidence_to_control

            link_evidence_to_control(
                user_id,
                linked_id,
                control_id=str(task["control_id"]),
                framework_id=str(task.get("framework_id") or ""),
                role="supports",
            )
        except Exception:
            pass

    meta = {}
    try:
        meta = json.loads(task.get("meta_json") or "{}")
        if not isinstance(meta, dict):
            meta = {}
    except Exception:
        meta = {}
    if linked_id:
        meta["evidence_id"] = linked_id
        ids = meta.get("evidence_ids") if isinstance(meta.get("evidence_ids"), list) else []
        if linked_id not in ids:
            ids.append(linked_id)
        meta["evidence_ids"] = ids[-20:]

    get_conn().execute(
        """
        UPDATE compliance_tasks
        SET evidence_attached = 1, updated_at = ?, meta_json = ?
        WHERE id = ? AND user_id = ?
        """,
        (now(), json.dumps(meta)[:8000], task_id, user_id),
    )
    get_conn().commit()
    detail = note or linked_id or evidence_id or "evidence attached"
    _record_event(task_id, user_id, "evidence", detail[:500])
    _publish(
        "compliance.task.evidence_attached",
        user_id,
        task_id=task_id,
        evidence_id=linked_id or None,
    )
    return get_task(user_id, task_id) or task


def complete_task(
    user_id: str,
    task_id: str,
    *,
    force: bool = False,
) -> dict[str, Any]:
    """Mark complete — blocked if evidence_required and none attached (unless force)."""
    ensure_compliance_ops_schema()
    task = get_task(user_id, task_id)
    if not task:
        raise ValueError("task not found")
    if task.get("status") == "completed":
        return task
    if int(task.get("evidence_required") or 0) and not int(task.get("evidence_attached") or 0):
        if not force:
            raise ValueError(
                "Cannot complete — required evidence missing. Attach evidence first."
            )
    if int(task.get("approval_required") or 0) and task.get("status") not in {
        "approval",
        "completed",
    }:
        # Move to approval first
        return update_task(user_id, task_id, {"status": "approval"})

    # Automated: attempt live control rollup before closing
    auto_json = ""
    if task.get("task_kind") == "automated" and (task.get("live_test_name") or "").strip():
        auto_json = json.dumps(_run_automated_check(user_id, str(task["live_test_name"])))

    t = now()
    get_conn().execute(
        """
        UPDATE compliance_tasks SET
            status = 'completed', completed_at = ?, updated_at = ?,
            auto_result_json = CASE WHEN ? != '' THEN ? ELSE auto_result_json END
        WHERE id = ? AND user_id = ?
        """,
        (t, t, auto_json, auto_json, task_id, user_id),
    )
    get_conn().commit()
    _record_event(task_id, user_id, "completed", "task completed")
    _publish("compliance.task.completed", user_id, task_id=task_id, title=task.get("title"))
    owner = task.get("owner_id") or user_id
    _notify(owner, f"Compliance task completed — {task.get('title')}", "Recorded in Compliance Operations")
    return get_task(user_id, task_id) or task


def _run_automated_check(user_id: str, live_test_name: str) -> dict[str, Any]:
    try:
        from app.services.control_testing import evaluate_agent_host_controls
        from app.agents import list_agents

        agents = list_agents(user_id, limit=200) or []
        online = [a for a in agents if (a.get("status") or "") in {"online", "ok", "healthy"}]
        if not online:
            return {"ok": False, "summary": "No online agents for automated check", "pass": 0, "fail": 0}
        # Use aggregate path via evaluate on first agent payloads already stored —
        # prefer control_testing aggregate helpers when present.
        from app.controls.test_registry import (
            TEST_HOST_DISK_ENCRYPTION,
            TEST_HOST_FIREWALL,
            TEST_HOST_RISKY_LISTENERS,
            TEST_HOST_DEFENDER,
            TEST_HOST_SSH_ROOT,
        )
        from app.services import control_testing as ct

        name = live_test_name.strip()
        fn_map = {
            TEST_HOST_FIREWALL: getattr(ct, "_test_host_firewall", None),
            TEST_HOST_DEFENDER: getattr(ct, "_test_host_defender", None),
            TEST_HOST_SSH_ROOT: getattr(ct, "_test_host_ssh_root", None),
            TEST_HOST_DISK_ENCRYPTION: getattr(ct, "_test_host_disk_encryption", None),
            TEST_HOST_RISKY_LISTENERS: getattr(ct, "_test_host_risky_listeners", None),
        }
        fn = fn_map.get(name)
        if callable(fn):
            result = fn(user_id)
            return {
                "ok": True,
                "test": name,
                "status": result.get("status"),
                "summary": result.get("summary"),
                "raw": {k: result.get(k) for k in ("status", "summary", "pass_count", "fail_count") if k in result},
            }
        # Fallback: recompute per first agent
        aid = str(online[0].get("id") or "")
        out = evaluate_agent_host_controls(user_id, aid, only_tests={name})
        return {"ok": True, "test": name, "agent_id": aid, "result": out}
    except Exception as exc:
        return {"ok": False, "error": str(exc)[:300]}


def escalate_task(
    user_id: str,
    task_id: str,
    *,
    reason: str = "",
) -> dict[str, Any]:
    ensure_compliance_ops_schema()
    task = get_task(user_id, task_id)
    if not task:
        raise ValueError("task not found")
    level = int(task.get("escalation_level") or 0) + 1
    # Priority ladder: escalate → at least high; L3 → critical
    cur_pri = (task.get("priority") or "medium").lower()
    pri_rank = {"low": 0, "medium": 1, "high": 2, "critical": 3}
    want_pri = "critical" if level >= 3 else "high" if level >= 1 else cur_pri
    if pri_rank.get(want_pri, 0) > pri_rank.get(cur_pri, 0):
        new_pri = want_pri
    else:
        new_pri = cur_pri
    get_conn().execute(
        "UPDATE compliance_tasks SET escalation_level = ?, last_escalated_at = ?, "
        "priority = ?, updated_at = ? WHERE id = ? AND user_id = ?",
        (level, now(), new_pri, now(), task_id, user_id),
    )
    get_conn().commit()
    _record_event(task_id, user_id, "escalated", reason or f"level {level}")
    title = f"Compliance escalation — {task.get('title')} (L{level})"
    body = reason or f"Overdue / escalated. Due: {task.get('due_label')}"
    # Fan-out: owner always; manager L1+; reviewer L2+; org admins L3
    recipients: set[str] = set()
    recipients.add(str(task.get("owner_id") or user_id))
    if task.get("manager_id"):
        recipients.add(str(task["manager_id"]))
    if level >= 2 and task.get("reviewer_id"):
        recipients.add(str(task["reviewer_id"]))
    if level >= 3:
        try:
            from app.commercial_ext import list_org_members
            from app.tenancy import primary_org_id

            oid = primary_org_id(user_id)
            if oid:
                for m in list_org_members(user_id, oid) or []:
                    if (m.get("role") or "").lower() in {"admin", "owner"}:
                        recipients.add(str(m.get("user_id") or m.get("id") or ""))
        except Exception:
            recipients.add(user_id)
    recipients.discard("")
    for rid in recipients:
        _notify(rid, title, body)
    _publish(
        "compliance.task.escalated",
        user_id,
        task_id=task_id,
        escalation_level=level,
        priority=new_pri,
        title=task.get("title"),
    )
    if level >= 2:
        _publish(
            "compliance.sla.breach",
            user_id,
            task_id=task_id,
            escalation_level=level,
            title=task.get("title"),
        )
    # Soft risk signal — open a medium risk when escalation >= 2
    if level >= 2:
        try:
            from app.enterprise import create_risk

            create_risk(
                user_id,
                threat=f"Overdue compliance: {task.get('title')}",
                vulnerability="compliance_ops_escalation",
                impact=4 if level >= 3 else 3,
                likelihood=3,
                mitigation=(
                    f"Escalation level {level}. Complete the Compliance Operations task "
                    "and attach evidence. Not a legal finding."
                ),
                owner=str(task.get("owner_id") or user_id),
            )
        except Exception:
            pass
    return get_task(user_id, task_id) or task


def my_work_queue(user_id: str, *, owner_id: str | None = None) -> dict[str, Any]:
    ensure_compliance_ops_schema()
    oid = (owner_id or user_id).strip()
    tasks = list_tasks(user_id, limit=300)
    mine = [t for t in tasks if (t.get("owner_id") or user_id) == oid and t.get("status") in OPEN_STATUSES]
    t = time.time()
    overdue = [x for x in mine if x.get("overdue")]
    due_today = [
        x
        for x in mine
        if x.get("due_at")
        and not x.get("overdue")
        and 0 <= float(x["due_at"]) - t < 86400
    ]
    this_week = [
        x
        for x in mine
        if x.get("due_at")
        and not x.get("overdue")
        and 86400 <= float(x["due_at"]) - t < 7 * 86400
    ]
    upcoming = [
        x
        for x in mine
        if x.get("due_at") and float(x["due_at"]) - t >= 7 * 86400
    ]
    return {
        "ok": True,
        "owner_id": oid,
        "counts": {
            "overdue": len(overdue),
            "due_today": len(due_today),
            "this_week": len(this_week),
            "upcoming": len(upcoming),
            "open": len(mine),
        },
        "overdue": overdue[:40],
        "due_today": due_today[:40],
        "this_week": this_week[:40],
        "upcoming": upcoming[:40],
        "note": "Work queue for Compliance Operations — not a certification score.",
    }


def management_summary(user_id: str) -> dict[str, Any]:
    ensure_compliance_ops_schema()
    tasks = list_tasks(user_id, limit=500)
    completed = [t for t in tasks if t.get("status") == "completed"]
    open_t = [t for t in tasks if t.get("status") in OPEN_STATUSES]
    overdue = [t for t in open_t if t.get("overdue")]
    escalations = [t for t in open_t if int(t.get("escalation_level") or 0) > 0]
    by_dept: dict[str, dict[str, int]] = {}
    for t in tasks:
        d = (t.get("department") or "Unassigned").strip() or "Unassigned"
        bucket = by_dept.setdefault(d, {"total": 0, "completed": 0, "overdue": 0})
        bucket["total"] += 1
        if t.get("status") == "completed":
            bucket["completed"] += 1
        if t.get("overdue"):
            bucket["overdue"] += 1
    dept_rows = []
    for name, b in sorted(by_dept.items(), key=lambda kv: kv[0].lower()):
        pct = round(100.0 * b["completed"] / b["total"]) if b["total"] else 0
        dept_rows.append(
            {
                "department": name,
                "completion_percent": pct,
                "total": b["total"],
                "completed": b["completed"],
                "overdue": b["overdue"],
            }
        )
    total = len(tasks) or 1
    overall = round(100.0 * len(completed) / total) if tasks else 0
    return {
        "ok": True,
        "overall_percent": overall,
        "counts": {
            "completed": len(completed),
            "in_progress": len([t for t in open_t if t.get("status") == "in_progress"]),
            "due_open": len(open_t),
            "overdue": len(overdue),
            "escalations": len(escalations),
            "total": len(tasks),
        },
        "departments": dept_rows,
        "note": (
            "Management rollup of Compliance Operations tasks — "
            "helps track work completion, not legal compliance."
        ),
    }


def calendar_month(user_id: str, *, year: int, month: int) -> dict[str, Any]:
    ensure_compliance_ops_schema()
    from calendar import monthrange

    start = datetime(year, month, 1, tzinfo=timezone.utc).timestamp()
    last = monthrange(year, month)[1]
    end = datetime(year, month, last, 23, 59, 59, tzinfo=timezone.utc).timestamp()
    tasks = list_tasks(user_id, from_ts=start, to_ts=end, limit=500)
    by_day: dict[str, list[dict[str, Any]]] = {}
    for t in tasks:
        label = t.get("due_label")
        if not label:
            continue
        by_day.setdefault(label, []).append(
            {
                "id": t["id"],
                "title": t["title"],
                "status": t["status"],
                "priority": t["priority"],
                "overdue": t.get("overdue"),
                "department": t.get("department"),
                "task_kind": t.get("task_kind"),
            }
        )
    return {
        "ok": True,
        "year": year,
        "month": month,
        "days": by_day,
        "task_count": len(tasks),
    }


def board_view(user_id: str) -> dict[str, Any]:
    """Kanban columns for Compliance Operations."""
    ensure_compliance_ops_schema()
    tasks = list_tasks(user_id, limit=400)
    columns = [
        ("backlog", "Backlog"),
        ("upcoming", "Upcoming"),
        ("in_progress", "In progress"),
        ("review", "Review"),
        ("approval", "Approval"),
        ("completed", "Completed"),
    ]
    by_status: dict[str, list[dict[str, Any]]] = {k: [] for k, _ in columns}
    for t in tasks:
        st = str(t.get("status") or "upcoming")
        if st == "cancelled":
            continue
        by_status.setdefault(st, []).append(t)
    return {
        "ok": True,
        "columns": [
            {
                "id": cid,
                "label": label,
                "tasks": by_status.get(cid, [])[:60],
                "count": len(by_status.get(cid, [])),
            }
            for cid, label in columns
        ],
        "note": "Board is a work view — not a certification score.",
    }


def transition_task(user_id: str, task_id: str, status: str) -> dict[str, Any]:
    """Move a task to a board column (validated status)."""
    st = (status or "").strip().lower()
    if st not in STATUSES:
        raise ValueError(f"invalid status: {status}")
    return update_task(user_id, task_id, {"status": st})


def submit_for_review(user_id: str, task_id: str, *, note: str = "") -> dict[str, Any]:
    """Owner finished work → Review (evidence required when configured)."""
    ensure_compliance_ops_schema()
    task = get_task(user_id, task_id)
    if not task:
        raise ValueError("task not found")
    if int(task.get("evidence_required") or 0) and not int(task.get("evidence_attached") or 0):
        raise ValueError("Cannot submit for review — required evidence missing.")
    if note:
        _record_event(task_id, user_id, "review_note", note[:500])
    out = update_task(user_id, task_id, {"status": "review"})
    reviewer = task.get("reviewer_id") or task.get("manager_id") or user_id
    _notify(
        str(reviewer),
        f"Compliance review needed — {task.get('title')}",
        note or "Submitted for review",
    )
    _publish("compliance.task.review", user_id, task_id=task_id, title=task.get("title"))
    return out


def approve_task(user_id: str, task_id: str, *, note: str = "") -> dict[str, Any]:
    """Reviewer/approver signs off → completed (or approval column first)."""
    ensure_compliance_ops_schema()
    task = get_task(user_id, task_id)
    if not task:
        raise ValueError("task not found")
    if task.get("status") not in {"review", "approval", "in_progress"}:
        raise ValueError("Task must be in review or approval to approve")
    if int(task.get("evidence_required") or 0) and not int(task.get("evidence_attached") or 0):
        raise ValueError("Cannot approve — required evidence missing.")
    _record_event(task_id, user_id, "approved", note or "approved")
    _notify(
        str(task.get("owner_id") or user_id),
        f"Compliance task approved — {task.get('title')}",
        note or "Approved",
    )
    _publish("compliance.task.approved", user_id, task_id=task_id, title=task.get("title"))
    # Force-complete past the approval_required gate
    if task.get("status") != "approval" and int(task.get("approval_required") or 0):
        update_task(user_id, task_id, {"status": "approval"})
    return complete_task(user_id, task_id, force=True)


def reject_task(user_id: str, task_id: str, *, reason: str = "") -> dict[str, Any]:
    """Send back to in_progress for rework."""
    ensure_compliance_ops_schema()
    task = get_task(user_id, task_id)
    if not task:
        raise ValueError("task not found")
    _record_event(task_id, user_id, "rejected", reason or "rejected")
    _notify(
        str(task.get("owner_id") or user_id),
        f"Compliance task returned — {task.get('title')}",
        reason or "Returned for rework",
    )
    _publish("compliance.task.rejected", user_id, task_id=task_id, title=task.get("title"))
    return update_task(user_id, task_id, {"status": "in_progress"})
