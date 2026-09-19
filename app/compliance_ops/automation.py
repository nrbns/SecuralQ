"""Event-driven reminder / overdue / escalation tick for Compliance Operations."""

from __future__ import annotations

import time
from typing import Any

from app.compliance_ops.schema import ensure_compliance_ops_schema
from app.compliance_ops.schedules import materialize_due_from_schedules
from app.compliance_ops.tasks import OPEN_STATUSES, escalate_task, list_tasks
from app.db import get_conn, now

# Default ladder (days relative to due): remind / escalate
# negative = before due, positive = after due
DEFAULT_RULES = [
    {"trigger": "due_soon", "days": -7, "action": "remind_owner"},
    {"trigger": "due_soon", "days": -3, "action": "remind_owner"},
    {"trigger": "due", "days": 0, "action": "remind_owner"},
    {"trigger": "overdue", "days": 1, "action": "remind_owner"},
    {"trigger": "overdue", "days": 2, "action": "escalate"},
    {"trigger": "overdue", "days": 7, "action": "escalate"},
]


def _publish(event_type: str, user_id: str, **extra: Any) -> None:
    try:
        from app.realtime_bus import publish

        publish(type=event_type, event_type=event_type, user_id=user_id, **extra)
    except Exception:
        pass


def _notify(user_id: str, title: str, body: str) -> None:
    if not user_id:
        return
    try:
        from app.notifications import notify

        notify(user_id, "remediation_due", title, body, link="/#compliance_ops")
    except Exception:
        try:
            from app.notifications import create_notification

            create_notification(user_id, "info", title, body, link="/#compliance_ops")
        except Exception:
            pass


def _days_from_due(due_at: float, now_ts: float) -> float:
    return (now_ts - due_at) / 86400.0


def run_compliance_ops_tick(
    user_id: str,
    *,
    materialize: bool = True,
) -> dict[str, Any]:
    """Materialize schedules + fire reminders/escalations. Idempotent-ish via last_* stamps."""
    ensure_compliance_ops_schema()
    materialized = {"count": 0}
    if materialize:
        try:
            materialized = materialize_due_from_schedules(user_id, horizon_days=21)
        except Exception as exc:
            materialized = {"ok": False, "error": str(exc)[:200]}

    now_ts = time.time()
    actions: list[dict[str, Any]] = []
    tasks = list_tasks(user_id, limit=500)
    open_tasks = [t for t in tasks if t.get("status") in OPEN_STATUSES and t.get("due_at")]

    for task in open_tasks:
        due = float(task["due_at"])
        delta_days = _days_from_due(due, now_ts)
        tid = task["id"]
        owner = str(task.get("owner_id") or user_id)
        title = str(task.get("title") or "Compliance task")
        last_rem = float(task.get("last_reminded_at") or 0)
        last_esc = float(task.get("last_escalated_at") or 0)

        # due soon: within 7 days before due
        if -7.5 <= delta_days < -2.5 and (now_ts - last_rem) > 20 * 3600:
            _notify(owner, f"Compliance task due in 7 days — {title}", f"Due {task.get('due_label')}")
            get_conn().execute(
                "UPDATE compliance_tasks SET last_reminded_at = ?, updated_at = ? WHERE id = ?",
                (now(), now(), tid),
            )
            get_conn().commit()
            _publish("compliance.task.due_soon", user_id, task_id=tid, title=title, days=7)
            actions.append({"task_id": tid, "action": "remind_7d"})

        elif -3.5 <= delta_days < -0.5 and (now_ts - last_rem) > 20 * 3600:
            _notify(owner, f"Compliance task due in 3 days — {title}", f"Due {task.get('due_label')}")
            get_conn().execute(
                "UPDATE compliance_tasks SET last_reminded_at = ?, updated_at = ? WHERE id = ?",
                (now(), now(), tid),
            )
            get_conn().commit()
            _publish("compliance.task.due_soon", user_id, task_id=tid, title=title, days=3)
            actions.append({"task_id": tid, "action": "remind_3d"})

        elif -0.5 <= delta_days < 0.5 and (now_ts - last_rem) > 12 * 3600:
            _notify(owner, f"Compliance task due today — {title}", "Action required today")
            get_conn().execute(
                "UPDATE compliance_tasks SET last_reminded_at = ?, updated_at = ? WHERE id = ?",
                (now(), now(), tid),
            )
            get_conn().commit()
            _publish("compliance.task.due", user_id, task_id=tid, title=title)
            actions.append({"task_id": tid, "action": "due_today"})

        elif delta_days >= 1 and not int(task.get("overdue_notified") or 0):
            _notify(owner, f"OVERDUE — {title}", f"Overdue since {task.get('due_label')}")
            get_conn().execute(
                "UPDATE compliance_tasks SET overdue_notified = 1, last_reminded_at = ?, updated_at = ? WHERE id = ?",
                (now(), now(), tid),
            )
            get_conn().commit()
            _publish("compliance.task.overdue", user_id, task_id=tid, title=title)
            actions.append({"task_id": tid, "action": "overdue_notify"})

        elif delta_days >= 2 and int(task.get("escalation_level") or 0) < 1 and (now_ts - last_esc) > 12 * 3600:
            escalate_task(user_id, tid, reason=f"Auto-escalate: overdue {int(delta_days)}d")
            actions.append({"task_id": tid, "action": "escalate_l1"})

        elif delta_days >= 7 and int(task.get("escalation_level") or 0) < 2 and (now_ts - last_esc) > 12 * 3600:
            escalate_task(user_id, tid, reason=f"Auto-escalate L2: overdue {int(delta_days)}d")
            actions.append({"task_id": tid, "action": "escalate_l2"})

    return {
        "ok": True,
        "user_id": user_id,
        "materialized": materialized,
        "actions": actions,
        "open_tasks": len(open_tasks),
        "disclaimer": "Automation manages work reminders — not a legal compliance determination.",
    }


def run_tick_all_users(*, limit_users: int = 50) -> dict[str, Any]:
    """Scheduler entry: tick distinct task owners / schedule owners."""
    ensure_compliance_ops_schema()
    rows = get_conn().execute(
        """
        SELECT DISTINCT user_id FROM compliance_schedules WHERE enabled = 1
        UNION
        SELECT DISTINCT user_id FROM compliance_tasks WHERE status NOT IN ('completed','cancelled')
        LIMIT ?
        """,
        (max(1, limit_users),),
    ).fetchall()
    results = []
    for r in rows:
        uid = str(r["user_id"])
        try:
            results.append(run_compliance_ops_tick(uid))
        except Exception as exc:
            results.append({"ok": False, "user_id": uid, "error": str(exc)[:200]})
    return {"ok": True, "users": len(results), "results": results}
