"""CMMC-specific POA&M items — policy-gated, 180-day close target for L2."""

from __future__ import annotations

import json
from typing import Any

from app.cmmc.poam_policy import L2_POAM_CLOSE_DAYS, poam_policy_for_control
from app.cmmc.schema import ensure_cmmc_assessment_schema
from app.db import get_conn, new_id, now, row_to_dict

VALID_POAM_STATUS = frozenset({"open", "in_progress", "pending_verify", "closed", "cancelled"})


def open_poam_item(
    user_id: str,
    *,
    framework_id: str,
    control_id: str,
    weakness: str,
    owner: str,
    risk_level: str = "medium",
    finding_id: str = "",
    milestones: list[dict[str, Any]] | None = None,
    org_id: str | None = None,
    remediation_id: str = "",
) -> dict[str, Any]:
    ensure_cmmc_assessment_schema()
    policy = poam_policy_for_control(framework_id, control_id)
    if not policy.get("poam_permitted_for_control"):
        raise ValueError(
            f"POA&M not permitted for {control_id}: {policy.get('reason')}"
        )
    if not (weakness or "").strip():
        raise ValueError("weakness is required")
    if not (owner or "").strip():
        raise ValueError("owner is required")
    from app.tenancy import primary_org_id

    oid = org_id or primary_org_id(user_id)
    t = now()
    close_days = int(policy.get("close_within_days") or L2_POAM_CLOSE_DAYS)
    due = t + close_days * 86400
    rid = new_id()
    get_conn().execute(
        """
        INSERT INTO cmmc_poam_items
        (id, user_id, org_id, framework_id, control_id, finding_id, weakness, risk_level,
         owner, due_at, milestone_json, status, evidence_ids_json, remediation_id,
         closed_at, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'open', '[]', ?, NULL, ?, ?)
        """,
        (
            rid,
            user_id,
            oid,
            framework_id,
            control_id,
            finding_id or "",
            weakness[:4000],
            (risk_level or "medium")[:40],
            owner[:200],
            due,
            json.dumps(milestones or [])[:4000],
            remediation_id or "",
            t,
            t,
        ),
    )
    get_conn().commit()
    try:
        from app.realtime_bus import publish

        publish(
            type="cmmc",
            event_type="cmmc.poam.opened",
            user_id=user_id,
            org_id=oid,
            control_id=control_id,
            poam_id=rid,
            due_at=due,
        )
    except Exception:
        pass
    return get_poam_item(user_id, rid) or {"id": rid}


def get_poam_item(user_id: str, poam_id: str) -> dict[str, Any] | None:
    ensure_cmmc_assessment_schema()
    row = get_conn().execute(
        "SELECT * FROM cmmc_poam_items WHERE id = ? AND user_id = ?",
        (poam_id, user_id),
    ).fetchone()
    return _hydrate(row_to_dict(row)) if row else None


def list_poam_items(
    user_id: str,
    *,
    framework_id: str = "",
    status: str = "",
    limit: int = 200,
) -> list[dict[str, Any]]:
    ensure_cmmc_assessment_schema()
    from app.tenancy import tenant_visibility_sql

    where, args = tenant_visibility_sql(user_id)
    q = f"SELECT * FROM cmmc_poam_items WHERE {where}"
    if framework_id:
        q += " AND framework_id = ?"
        args.append(framework_id)
    if status:
        q += " AND status = ?"
        args.append(status)
    q += " ORDER BY due_at ASC LIMIT ?"
    args.append(max(1, min(limit, 500)))
    return [_hydrate(row_to_dict(r)) for r in get_conn().execute(q, args).fetchall()]


def close_poam_item(
    user_id: str,
    poam_id: str,
    *,
    evidence_ids: list[str] | None = None,
    verified: bool = False,
) -> dict[str, Any] | None:
    ensure_cmmc_assessment_schema()
    row = get_poam_item(user_id, poam_id)
    if not row:
        return None
    if not verified:
        raise ValueError("POA&M close requires verified=True after independent verification")
    t = now()
    get_conn().execute(
        """
        UPDATE cmmc_poam_items SET status = 'closed', closed_at = ?, updated_at = ?,
            evidence_ids_json = ?
        WHERE id = ? AND user_id = ?
        """,
        (t, t, json.dumps(evidence_ids or row.get("evidence_ids") or [])[:4000], poam_id, user_id),
    )
    get_conn().commit()
    return get_poam_item(user_id, poam_id)


def _hydrate(d: dict[str, Any]) -> dict[str, Any]:
    try:
        d["milestones"] = json.loads(d.get("milestone_json") or "[]")
    except Exception:
        d["milestones"] = []
    try:
        d["evidence_ids"] = json.loads(d.get("evidence_ids_json") or "[]")
    except Exception:
        d["evidence_ids"] = []
    due = d.get("due_at")
    if due is not None:
        try:
            d["days_until_due"] = round((float(due) - now()) / 86400, 1)
            d["overdue"] = float(due) < now() and d.get("status") != "closed"
        except (TypeError, ValueError):
            d["days_until_due"] = None
            d["overdue"] = False
    return d
