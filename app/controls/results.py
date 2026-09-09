"""Optional SQLite store for last live-test result per control/test.

Table: ``securaiq_control_test_results``
Key: (user_id, framework_id, control_id, test_name) — last result wins.
"""

from __future__ import annotations

import json
from typing import Any

from app.db import get_conn, new_id, now, row_to_dict


def ensure_schema() -> None:
    c = get_conn()
    c.execute(
        """
        CREATE TABLE IF NOT EXISTS securaiq_control_test_results (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            framework_id TEXT NOT NULL,
            control_id TEXT NOT NULL,
            test_name TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'unknown',
            summary TEXT NOT NULL DEFAULT '',
            detail_json TEXT NOT NULL DEFAULT '{}',
            tested_at REAL NOT NULL,
            updated_at REAL NOT NULL,
            UNIQUE(user_id, framework_id, control_id, test_name)
        )
        """
    )
    c.execute(
        "CREATE INDEX IF NOT EXISTS idx_ctrl_test_results_user_fw "
        "ON securaiq_control_test_results(user_id, framework_id)"
    )
    c.commit()


def record_test_result(
    user_id: str,
    framework_id: str,
    control_id: str,
    *,
    test_name: str,
    status: str,
    summary: str = "",
    detail: dict[str, Any] | None = None,
    tested_at: float | None = None,
) -> dict[str, Any]:
    """Upsert the last result for this user/framework/control/test."""
    ensure_schema()
    ts = float(tested_at if tested_at is not None else now())
    st = (status or "unknown").strip().lower() or "unknown"
    detail_json = json.dumps(detail or {}, default=str)
    c = get_conn()
    existing = c.execute(
        """
        SELECT id FROM securaiq_control_test_results
        WHERE user_id = ? AND framework_id = ? AND control_id = ? AND test_name = ?
        """,
        (user_id, framework_id, control_id, test_name),
    ).fetchone()
    if existing:
        rid = existing["id"]
        c.execute(
            """
            UPDATE securaiq_control_test_results
            SET status = ?, summary = ?, detail_json = ?, tested_at = ?, updated_at = ?
            WHERE id = ?
            """,
            (st, summary or "", detail_json, ts, now(), rid),
        )
    else:
        rid = new_id()
        c.execute(
            """
            INSERT INTO securaiq_control_test_results
            (id, user_id, framework_id, control_id, test_name, status, summary,
             detail_json, tested_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                rid,
                user_id,
                framework_id,
                control_id,
                test_name,
                st,
                summary or "",
                detail_json,
                ts,
                now(),
            ),
        )
    c.commit()
    return {
        "id": rid,
        "user_id": user_id,
        "framework_id": framework_id,
        "control_id": control_id,
        "test_name": test_name,
        "status": st,
        "summary": summary or "",
        "detail": detail or {},
        "tested_at": ts,
    }


def get_results_for_control(
    user_id: str, framework_id: str, control_id: str
) -> list[dict[str, Any]]:
    ensure_schema()
    c = get_conn()
    rows = c.execute(
        """
        SELECT * FROM securaiq_control_test_results
        WHERE user_id = ? AND framework_id = ? AND control_id = ?
        ORDER BY test_name
        """,
        (user_id, framework_id, control_id),
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


def list_results_for_framework(user_id: str, framework_id: str) -> list[dict[str, Any]]:
    ensure_schema()
    c = get_conn()
    rows = c.execute(
        """
        SELECT * FROM securaiq_control_test_results
        WHERE user_id = ? AND framework_id = ?
        ORDER BY control_id, test_name
        """,
        (user_id, framework_id),
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


def _rollup_status(statuses: list[str]) -> str:
    """Worst-wins rollup across tests for one control."""
    normalized = [(s or "unknown").lower() for s in statuses]
    if not normalized:
        return "unknown"
    if any(s == "fail" for s in normalized):
        return "fail"
    if any(s == "partial" for s in normalized):
        return "partial"
    if any(s == "unknown" for s in normalized) and not all(s == "pass" for s in normalized):
        # mix of unknown + pass → unknown; all unknown → unknown
        if any(s == "pass" for s in normalized) and all(s in ("pass", "unknown") for s in normalized):
            return "unknown"
        if all(s == "unknown" for s in normalized):
            return "unknown"
    if all(s == "pass" for s in normalized):
        return "pass"
    if any(s == "na" for s in normalized) and all(s in ("na", "pass") for s in normalized):
        return "na" if all(s == "na" for s in normalized) else "pass"
    if any(s == "unknown" for s in normalized):
        return "unknown"
    return normalized[0]


def aggregate_control_statuses(user_id: str, framework_id: str) -> dict[str, Any]:
    """Counts of controls by rolled-up last-result status. Honest zeros if empty."""
    rows = list_results_for_framework(user_id, framework_id)
    by_control: dict[str, list[str]] = {}
    last_test: float | None = None
    for r in rows:
        cid = r.get("control_id") or ""
        by_control.setdefault(cid, []).append(str(r.get("status") or "unknown"))
        ta = r.get("tested_at")
        if ta is not None:
            try:
                taf = float(ta)
            except (TypeError, ValueError):
                continue
            if last_test is None or taf > last_test:
                last_test = taf

    passing = failing = unknown = na = 0
    for statuses in by_control.values():
        rolled = _rollup_status(statuses)
        if rolled == "pass":
            passing += 1
        elif rolled == "fail":
            failing += 1
        elif rolled == "na":
            na += 1
        else:
            # partial and unknown both count as unknown for the summary buckets
            # (summary schema has passing/failing/unknown/na — no partial bucket)
            if rolled == "partial":
                failing += 1  # treat soft-fail as failing for Control Center
            else:
                unknown += 1

    return {
        "passing": passing,
        "failing": failing,
        "unknown": unknown,
        "na": na,
        "controls_with_results": len(by_control),
        "last_test": last_test,
    }
