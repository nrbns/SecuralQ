"""Bridge host control FAIL/PASS → Compliance Operations tasks.

Automated compliance work: when live controls fail, open (or refresh) a
department-owned task instead of only a POA&M remediation.
"""

from __future__ import annotations

import time
from typing import Any

from app.compliance_ops.schema import ensure_compliance_ops_schema
from app.compliance_ops.tasks import OPEN_STATUSES, create_task, get_task, list_tasks, update_task
from app.db import get_conn, now

# Map live tests → default department + title template
_TEST_META: dict[str, dict[str, str]] = {
    "host_firewall": {
        "department": "Security",
        "title": "Remediate host firewall failures",
        "kind": "automated",
    },
    "host_defender": {
        "department": "Security",
        "title": "Remediate Windows Defender failures",
        "kind": "automated",
    },
    "host_ssh_root": {
        "department": "IT",
        "title": "Remediate SSH root login exposure",
        "kind": "automated",
    },
    "host_disk_encryption": {
        "department": "Security",
        "title": "Remediate disk encryption failures",
        "kind": "automated",
    },
    "host_risky_listeners": {
        "department": "Security",
        "title": "Remediate high-risk listening ports",
        "kind": "automated",
    },
}


def _find_open_for_test(user_id: str, live_test_name: str) -> dict[str, Any] | None:
    for t in list_tasks(user_id, limit=300):
        if t.get("status") not in OPEN_STATUSES:
            continue
        if (t.get("live_test_name") or "").strip() == live_test_name:
            return t
    return None


def upsert_task_from_control_result(
    user_id: str,
    *,
    test_name: str,
    status: str,
    summary: str = "",
    agent_id: str = "",
    hostname: str = "",
    framework_id: str | None = None,
    control_id: str | None = None,
) -> dict[str, Any] | None:
    """On FAIL: ensure an open automated compliance task. On PASS-after-FAIL: note recovery."""
    ensure_compliance_ops_schema()
    name = (test_name or "").strip()
    if not name:
        return None
    meta = _TEST_META.get(name) or {
        "department": "Security",
        "title": f"Remediate control failure: {name}",
        "kind": "automated",
    }
    st = (status or "").strip().lower()

    if st == "fail":
        existing = _find_open_for_test(user_id, name)
        detail = summary or f"{name} FAIL"
        if hostname:
            detail = f"{hostname}: {detail}"
        if existing:
            # Bump priority / refresh description; keep open
            patch = {
                "priority": "high",
                "description": (
                    f"{existing.get('description') or ''}\n[{time.strftime('%Y-%m-%d')}] {detail}"
                )[:4000],
            }
            if existing.get("status") in {"backlog", "upcoming"}:
                patch["status"] = "in_progress"
            return update_task(user_id, existing["id"], patch)

        due = now() + 7 * 86400  # one week to address
        return create_task(
            user_id,
            {
                "title": meta["title"],
                "description": (
                    f"Opened from live control FAIL ({name}).\n{detail}\n"
                    "Automated task — re-run host controls after remediation; "
                    "attach evidence if required by policy."
                ),
                "task_kind": meta["kind"],
                "department": meta["department"],
                "live_test_name": name,
                "framework_id": framework_id or "",
                "control_id": control_id or "",
                "due_at": due,
                "evidence_due_at": due,
                "evidence_required": False,
                "priority": "high",
                "status": "in_progress",
                "owner_id": user_id,
                "meta": {"source": "control_fail", "agent_id": agent_id},
            },
        )

    if st == "pass":
        existing = _find_open_for_test(user_id, name)
        if not existing:
            return None
        # Auto-complete when the live test recovers (no evidence gate for automated)
        from app.compliance_ops.tasks import complete_task, submit_evidence

        note = f"Auto-verified PASS after re-check ({hostname or agent_id or 'fleet'})."
        submit_evidence(user_id, existing["id"], note=note)
        try:
            return complete_task(user_id, existing["id"], force=True)
        except ValueError:
            return update_task(user_id, existing["id"], {"status": "review"})
    return None
