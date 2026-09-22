"""Evidence Gap Autopilot — prepare a CMMC evidence plan from objectives + spine.

Does not invent evidence. Lists missing/stale/conflicting signals and drafts tasks.
Honesty: plan is advisory; humans own assessment claims.
"""

from __future__ import annotations

from typing import Any

from app.cmmc.objectives import (
    get_objective_status_row,
    list_objectives,
    seed_objectives_for_framework,
)
from app.cmmc.schema import ensure_cmmc_assessment_schema
from app.controls.catalog import list_framework_controls
from app.db import get_conn, now


def build_evidence_gap_plan(
    user_id: str,
    framework_id: str = "cmmc_l2",
    *,
    owner_default: str = "",
    days_to_close: int = 30,
) -> dict[str, Any]:
    """Prepare CMMC Evidence Plan: required vs existing vs missing vs tasks."""
    ensure_cmmc_assessment_schema()
    seed_objectives_for_framework(framework_id)

    method_rows = get_conn().execute(
        """
        SELECT control_id, method, result, collected_at, evidence_id
        FROM cmmc_method_evidence WHERE user_id = ? AND framework_id = ?
        """,
        (user_id, framework_id),
    ).fetchall()
    methods_by_ctrl: dict[str, set[str]] = {}
    for r in method_rows:
        methods_by_ctrl.setdefault(r["control_id"], set()).add(r["method"])

    # Stale objective statuses
    stale_objectives: list[dict[str, Any]] = []
    missing_methods: list[dict[str, Any]] = []
    missing_objective_status: list[dict[str, Any]] = []
    tasks: list[dict[str, Any]] = []

    required_methods = ("examine", "interview", "test")
    controls = list_framework_controls(framework_id)
    for c in controls:
        objs = list_objectives(framework_id, control_id=c.id)
        have = methods_by_ctrl.get(c.id) or set()
        for method in required_methods:
            if method not in have:
                gap = {
                    "control_id": c.id,
                    "title": c.title,
                    "gap_type": "missing_method",
                    "method": method,
                    "severity": f"Collect {method} evidence for {c.id}",
                }
                missing_methods.append(gap)
                tasks.append(
                    {
                        **gap,
                        "owner": owner_default or "",
                        "due_days": days_to_close,
                        "priority": "high" if method == "test" else "medium",
                    }
                )
        for o in objs:
            st = get_objective_status_row(user_id, o["id"])
            if not st:
                missing_objective_status.append(
                    {
                        "control_id": c.id,
                        "objective_id": o["id"],
                        "method": o.get("method"),
                        "gap_type": "unassessed_objective",
                    }
                )
                tasks.append(
                    {
                        "control_id": c.id,
                        "objective_id": o["id"],
                        "method": o.get("method"),
                        "gap_type": "unassessed_objective",
                        "severity": f"Assess objective {o.get('method')} for {c.id}",
                        "owner": owner_default or "",
                        "due_days": days_to_close,
                        "priority": "medium",
                    }
                )
            elif (st.get("freshness_status") or "").lower() in {"stale", "expired"}:
                stale_objectives.append(
                    {
                        "control_id": c.id,
                        "objective_id": o["id"],
                        "freshness_status": st.get("freshness_status"),
                        "gap_type": "stale_evidence",
                    }
                )
                tasks.append(
                    {
                        "control_id": c.id,
                        "objective_id": o["id"],
                        "gap_type": "stale_evidence",
                        "severity": f"Refresh {st.get('freshness_status')} evidence for {c.id}",
                        "owner": owner_default or "",
                        "due_days": max(7, days_to_close // 2),
                        "priority": "high",
                    }
                )

    # Conflicting evidence from spine reconciliation (best-effort)
    conflicts: list[dict[str, Any]] = []
    try:
        rows = get_conn().execute(
            """
            SELECT id, subject_key, check_id, conflict_status, canonical_result, changed_at
            FROM observation_canonical_state
            WHERE user_id = ? AND conflict_status = 'conflict'
            LIMIT 100
            """,
            (user_id,),
        ).fetchall()
        for r in rows:
            conflicts.append(
                {
                    "canonical_id": r["id"],
                    "subject_key": r["subject_key"],
                    "check_id": r["check_id"],
                    "status": r["conflict_status"],
                    "gap_type": "conflicting_evidence",
                }
            )
            tasks.append(
                {
                    "gap_type": "conflicting_evidence",
                    "canonical_id": r["id"],
                    "check_id": r["check_id"],
                    "severity": f"Resolve evidence conflict {r['check_id']} / {r['subject_key']}",
                    "owner": owner_default or "",
                    "due_days": 14,
                    "priority": "high",
                }
            )
    except Exception:
        conflicts = []

    total_controls = len(controls)
    return {
        "ok": True,
        "framework_id": framework_id,
        "plan_name": f"CMMC Evidence Plan ({framework_id})",
        "requirements_total": total_controls,
        "objectives_per_control": 3,
        "summary": {
            "missing_method_gaps": len(missing_methods),
            "unassessed_objectives": len(missing_objective_status),
            "stale_objectives": len(stale_objectives),
            "conflicts": len(conflicts),
            "tasks_generated": len(tasks),
        },
        "gaps": {
            "missing_methods": missing_methods[:500],
            "unassessed_objectives": missing_objective_status[:500],
            "stale_objectives": stale_objectives[:500],
            "conflicts": conflicts,
        },
        "tasks": tasks[:1000],
        "generated_at": now(),
        "disclaimer": (
            "Evidence Gap Autopilot drafts a collection plan from local SecuraIQ data. "
            "It does not create assessment claims, SPRS submissions, or certified findings. "
            "Owners must collect, review, and attest evidence before readiness claims."
        ),
    }
