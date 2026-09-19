"""Compliance Operations — calendar-driven workflow engine.

Framework → Requirement → Control → ComplianceTask → Owner → Due →
Reminder → Evidence → Review → Approval → Complete
(+ overdue → escalate → compliance risk).

Honesty: scheduling and escalation help manage work — they are not a legal
compliance determination or certification.
"""

from __future__ import annotations

from app.compliance_ops.schema import ensure_compliance_ops_schema
from app.compliance_ops.tasks import (
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
from app.compliance_ops.automation import run_compliance_ops_tick
from app.compliance_ops.schedules import materialize_due_from_schedules
from app.compliance_ops.seed import seed_default_schedules

__all__ = [
    "ensure_compliance_ops_schema",
    "create_task",
    "list_tasks",
    "get_task",
    "update_task",
    "complete_task",
    "escalate_task",
    "submit_evidence",
    "my_work_queue",
    "management_summary",
    "run_compliance_ops_tick",
    "materialize_due_from_schedules",
    "seed_default_schedules",
]
