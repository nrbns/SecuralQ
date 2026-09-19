"""Seed default Compliance Operations schedules (lab / first-run)."""

from __future__ import annotations

from typing import Any

from app.compliance_ops.schedules import create_schedule, list_schedules
from app.compliance_ops.schema import ensure_compliance_ops_schema

# Representative annual / quarterly obligations — not invented legal text.
DEFAULT_SCHEDULES: list[dict[str, Any]] = [
    {
        "title": "Quarterly access review",
        "description": "Review privileged and standard access; attach review report.",
        "task_kind": "manual",
        "department": "IT",
        "recurrence": "quarterly",
        "framework_id": "iso27001",
        "evidence_required": True,
        "approval_required": True,
        "risk_weight": 1.5,
    },
    {
        "title": "Verify endpoint disk encryption",
        "description": "Automated rollup of host_disk_encryption live tests across enrolled agents.",
        "task_kind": "automated",
        "department": "Security",
        "recurrence": "monthly",
        "live_test_name": "host_disk_encryption",
        "evidence_required": False,
        "risk_weight": 1.2,
    },
    {
        "title": "Host firewall posture check",
        "description": "Automated host_firewall live-test rollup.",
        "task_kind": "automated",
        "department": "Security",
        "recurrence": "monthly",
        "live_test_name": "host_firewall",
        "evidence_required": False,
        "risk_weight": 1.2,
    },
    {
        "title": "DPDP retention review",
        "description": "Assisted: review retention policies and attach sign-off evidence.",
        "task_kind": "assisted",
        "department": "Privacy",
        "recurrence": "quarterly",
        "framework_id": "dpdp_rules_2025",
        "evidence_required": True,
        "risk_weight": 1.4,
    },
    {
        "title": "Vendor / processor security review",
        "description": "Manual governance: review processor contracts and security schedules.",
        "task_kind": "manual",
        "department": "Legal",
        "recurrence": "yearly",
        "evidence_required": True,
        "approval_required": True,
        "risk_weight": 1.3,
    },
    {
        "title": "Security awareness training completion",
        "description": "Assisted: confirm training completion report uploaded for the period.",
        "task_kind": "assisted",
        "department": "HR",
        "recurrence": "yearly",
        "evidence_required": True,
        "risk_weight": 1.0,
    },
    {
        "title": "Annual management review",
        "description": "Manual: management review of security/privacy posture for the compliance year.",
        "task_kind": "manual",
        "department": "Management",
        "recurrence": "yearly",
        "evidence_required": True,
        "approval_required": True,
        "risk_weight": 1.6,
    },
]


def seed_default_schedules(user_id: str, *, force: bool = False) -> dict[str, Any]:
    ensure_compliance_ops_schema()
    existing = list_schedules(user_id)
    if existing and not force:
        return {
            "ok": True,
            "seeded": 0,
            "skipped": True,
            "existing": len(existing),
            "note": "Schedules already present — pass force=true to add defaults again.",
        }
    created = []
    for spec in DEFAULT_SCHEDULES:
        row = create_schedule(user_id, {**spec, "owner_id": user_id})
        created.append(row.get("id"))
    return {
        "ok": True,
        "seeded": len(created),
        "schedule_ids": created,
        "note": "Default Compliance Year schedules — customize owners/departments for your org.",
    }
