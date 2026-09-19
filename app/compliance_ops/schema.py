"""SQLite schema for Compliance Operations."""

from __future__ import annotations

from app.db import get_conn


def ensure_compliance_ops_schema() -> None:
    """Idempotent — always safe to call (CREATE IF NOT EXISTS).

    Do not cache readiness globally: tests swap DB paths per case.
    """
    c = get_conn()
    c.executescript(
        """
        CREATE TABLE IF NOT EXISTS compliance_schedules (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            org_id TEXT,
            framework_id TEXT NOT NULL DEFAULT '',
            requirement_id TEXT NOT NULL DEFAULT '',
            control_id TEXT NOT NULL DEFAULT '',
            title TEXT NOT NULL,
            description TEXT NOT NULL DEFAULT '',
            task_kind TEXT NOT NULL DEFAULT 'manual',
            department TEXT NOT NULL DEFAULT '',
            owner_id TEXT NOT NULL DEFAULT '',
            reviewer_id TEXT NOT NULL DEFAULT '',
            manager_id TEXT NOT NULL DEFAULT '',
            recurrence TEXT NOT NULL DEFAULT 'quarterly',
            next_due_at REAL,
            evidence_required INTEGER NOT NULL DEFAULT 1,
            approval_required INTEGER NOT NULL DEFAULT 0,
            risk_weight REAL NOT NULL DEFAULT 1.0,
            live_test_name TEXT NOT NULL DEFAULT '',
            enabled INTEGER NOT NULL DEFAULT 1,
            meta_json TEXT NOT NULL DEFAULT '{}',
            created_at REAL NOT NULL,
            updated_at REAL NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_co_sched_user
            ON compliance_schedules(user_id, next_due_at);

        CREATE TABLE IF NOT EXISTS compliance_tasks (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            org_id TEXT,
            schedule_id TEXT,
            framework_id TEXT NOT NULL DEFAULT '',
            requirement_id TEXT NOT NULL DEFAULT '',
            control_id TEXT NOT NULL DEFAULT '',
            title TEXT NOT NULL,
            description TEXT NOT NULL DEFAULT '',
            task_kind TEXT NOT NULL DEFAULT 'manual',
            department TEXT NOT NULL DEFAULT '',
            owner_id TEXT NOT NULL DEFAULT '',
            reviewer_id TEXT NOT NULL DEFAULT '',
            manager_id TEXT NOT NULL DEFAULT '',
            status TEXT NOT NULL DEFAULT 'upcoming',
            priority TEXT NOT NULL DEFAULT 'medium',
            due_at REAL,
            evidence_due_at REAL,
            completed_at REAL,
            recurrence TEXT NOT NULL DEFAULT 'one_time',
            evidence_required INTEGER NOT NULL DEFAULT 1,
            approval_required INTEGER NOT NULL DEFAULT 0,
            evidence_attached INTEGER NOT NULL DEFAULT 0,
            risk_weight REAL NOT NULL DEFAULT 1.0,
            live_test_name TEXT NOT NULL DEFAULT '',
            escalation_level INTEGER NOT NULL DEFAULT 0,
            last_reminded_at REAL,
            last_escalated_at REAL,
            overdue_notified INTEGER NOT NULL DEFAULT 0,
            auto_result_json TEXT NOT NULL DEFAULT '',
            meta_json TEXT NOT NULL DEFAULT '{}',
            created_at REAL NOT NULL,
            updated_at REAL NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_co_tasks_user_due
            ON compliance_tasks(user_id, due_at);
        CREATE INDEX IF NOT EXISTS idx_co_tasks_owner
            ON compliance_tasks(owner_id, status);
        CREATE INDEX IF NOT EXISTS idx_co_tasks_status
            ON compliance_tasks(user_id, status);

        CREATE TABLE IF NOT EXISTS compliance_task_events (
            id TEXT PRIMARY KEY,
            task_id TEXT NOT NULL,
            user_id TEXT NOT NULL,
            event_type TEXT NOT NULL,
            detail TEXT NOT NULL DEFAULT '',
            created_at REAL NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_co_task_events
            ON compliance_task_events(task_id, created_at);

        CREATE TABLE IF NOT EXISTS compliance_escalation_rules (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            org_id TEXT,
            name TEXT NOT NULL,
            trigger_kind TEXT NOT NULL,
            days_offset INTEGER NOT NULL DEFAULT 0,
            action TEXT NOT NULL,
            recipient_role TEXT NOT NULL DEFAULT 'owner',
            escalation_level INTEGER NOT NULL DEFAULT 0,
            enabled INTEGER NOT NULL DEFAULT 1,
            created_at REAL NOT NULL
        );
        """
    )
    c.commit()
