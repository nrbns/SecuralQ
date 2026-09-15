"""Append-only ``control_results`` history (P1 certification trail).

Last-result upserts remain in ``securaiq_control_test_results`` (Control Center
KPIs). This module keeps every PASS/FAIL transition for timeline / audit.
"""

from __future__ import annotations

import json
from typing import Any

from app.db import get_conn, new_id, now, row_to_dict


def ensure_history_schema() -> None:
    c = get_conn()
    c.execute(
        """
        CREATE TABLE IF NOT EXISTS securaiq_control_results (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            org_id TEXT,
            framework_id TEXT NOT NULL DEFAULT '',
            control_id TEXT NOT NULL DEFAULT '',
            check_id TEXT NOT NULL DEFAULT '',
            test_name TEXT NOT NULL DEFAULT '',
            result TEXT NOT NULL DEFAULT 'unknown',
            summary TEXT NOT NULL DEFAULT '',
            detail_json TEXT NOT NULL DEFAULT '{}',
            agent_id TEXT NOT NULL DEFAULT '',
            asset_id TEXT NOT NULL DEFAULT '',
            evidence_id TEXT NOT NULL DEFAULT '',
            event_id TEXT NOT NULL DEFAULT '',
            previous_result_id TEXT NOT NULL DEFAULT '',
            content_hash TEXT NOT NULL DEFAULT '',
            observed_at REAL NOT NULL,
            created_at REAL NOT NULL
        )
        """
    )
    c.execute(
        "CREATE INDEX IF NOT EXISTS idx_ctrl_results_user_ctrl "
        "ON securaiq_control_results(user_id, framework_id, control_id, observed_at DESC)"
    )
    c.execute(
        "CREATE INDEX IF NOT EXISTS idx_ctrl_results_agent "
        "ON securaiq_control_results(user_id, agent_id, observed_at DESC)"
    )
    c.commit()


def append_control_result(
    user_id: str,
    *,
    framework_id: str = "",
    control_id: str = "",
    test_name: str = "",
    result: str = "unknown",
    summary: str = "",
    detail: dict[str, Any] | None = None,
    agent_id: str = "",
    asset_id: str = "",
    evidence_id: str = "",
    event_id: str = "",
    org_id: str | None = None,
    observed_at: float | None = None,
) -> dict[str, Any]:
    """Insert one immutable control result row."""
    ensure_history_schema()
    ts = float(observed_at if observed_at is not None else now())
    st = (result or "unknown").strip().lower() or "unknown"
    fid = (framework_id or "").strip()
    cid = (control_id or "").strip()
    tname = (test_name or "").strip()
    detail = detail or {}
    # Link to previous result for same control/test/agent when present
    prev_id = ""
    c = get_conn()
    prev = c.execute(
        """
        SELECT id FROM securaiq_control_results
        WHERE user_id = ? AND framework_id = ? AND control_id = ? AND test_name = ?
          AND agent_id = ?
        ORDER BY observed_at DESC LIMIT 1
        """,
        (user_id, fid, cid, tname, agent_id or ""),
    ).fetchone()
    if prev:
        prev_id = prev["id"] if hasattr(prev, "keys") else prev[0]

    import hashlib

    payload = {
        "framework_id": fid,
        "control_id": cid,
        "test_name": tname,
        "result": st,
        "agent_id": agent_id,
        "observed_at": ts,
    }
    content_hash = hashlib.sha256(
        json.dumps(payload, sort_keys=True, default=str).encode("utf-8")
    ).hexdigest()
    rid = new_id()
    oid = org_id
    if not oid:
        try:
            from app.tenancy import primary_org_id

            oid = primary_org_id(user_id)
        except Exception:
            oid = None
    c.execute(
        """
        INSERT INTO securaiq_control_results
        (id, user_id, org_id, framework_id, control_id, check_id, test_name, result,
         summary, detail_json, agent_id, asset_id, evidence_id, event_id,
         previous_result_id, content_hash, observed_at, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            rid,
            user_id,
            oid,
            fid,
            cid,
            tname,
            tname,
            st,
            (summary or "")[:500],
            json.dumps(detail, default=str)[:8000],
            agent_id or "",
            asset_id or "",
            evidence_id or "",
            event_id or "",
            prev_id or "",
            content_hash,
            ts,
            now(),
        ),
    )
    c.commit()
    return {
        "id": rid,
        "user_id": user_id,
        "framework_id": fid,
        "control_id": cid,
        "test_name": tname,
        "result": st,
        "previous_result_id": prev_id,
        "content_hash": content_hash,
        "observed_at": ts,
        "evidence_id": evidence_id or "",
    }


def list_control_results(
    user_id: str,
    *,
    framework_id: str | None = None,
    control_id: str | None = None,
    agent_id: str | None = None,
    limit: int = 100,
) -> list[dict[str, Any]]:
    ensure_history_schema()
    limit = max(1, min(int(limit or 100), 500))
    clauses = ["user_id = ?"]
    args: list[Any] = [user_id]
    if framework_id:
        clauses.append("framework_id = ?")
        args.append(framework_id)
    if control_id:
        clauses.append("control_id = ?")
        args.append(control_id)
    if agent_id:
        clauses.append("agent_id = ?")
        args.append(agent_id)
    where = " AND ".join(clauses)
    c = get_conn()
    rows = c.execute(
        f"""
        SELECT * FROM securaiq_control_results
        WHERE {where}
        ORDER BY observed_at DESC
        LIMIT ?
        """,
        (*args, limit),
    ).fetchall()
    out: list[dict[str, Any]] = []
    for row in rows:
        d = row_to_dict(row) or {}
        try:
            d["detail"] = json.loads(d.pop("detail_json", None) or "{}")
        except Exception:
            d["detail"] = {}
            d.pop("detail_json", None)
        out.append(d)
    return out
