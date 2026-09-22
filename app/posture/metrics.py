"""Posture refresh metrics — lightweight counters for Mission Control."""

from __future__ import annotations

from typing import Any

from app.db import get_conn, now
from app.posture.schema import ensure_posture_schema


def refresh_metrics(*, since_sec: float = 86400) -> dict[str, Any]:
    ensure_posture_schema()
    since = now() - since_sec
    rows = get_conn().execute(
        """
        SELECT status, COUNT(*) AS n, AVG(duration_ms) AS avg_ms
        FROM posture_refresh_runs
        WHERE created_at >= ?
        GROUP BY status
        """,
        (since,),
    ).fetchall()
    by_status = {r["status"]: {"count": r["n"], "avg_duration_ms": r["avg_ms"]} for r in rows}
    return {
        "ok": True,
        "window_sec": since_sec,
        "by_status": by_status,
        "note": "Process-local SQLite metrics — not multi-node Prometheus.",
    }
