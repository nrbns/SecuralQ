"""Data retention TTL purge (#237).

Deletes aged audit/events/idempotency rows per configured day thresholds.
Never deletes organizations or users. Safe for scheduled ops / admin API.
"""

from __future__ import annotations

from typing import Any

from app.config import settings
from app.db import audit, get_conn, now, table_columns


def _days(name: str, default: int) -> int:
    v = getattr(settings, name, default)
    try:
        return max(0, int(v))
    except (TypeError, ValueError):
        return default


def purge_expired(*, dry_run: bool = False) -> dict[str, Any]:
    """Purge aged rows. dry_run counts only."""
    ts = now()
    c = get_conn()
    deleted: dict[str, int] = {}

    plans = [
        ("audit_log", "created_at", _days("retention_audit_days", 365), "audit_log"),
        ("securaiq_processed_events", "created_at", _days("retention_event_idempotency_days", 7), "processed_events"),
    ]
    # Optional tables — only if present
    optional = [
        ("xdr_events", "created_at", _days("retention_xdr_days", 90), "xdr_events"),
        ("notifications", "created_at", _days("retention_notifications_days", 90), "notifications"),
        ("webhook_dlq", "created_at", _days("retention_webhook_dlq_days", 30), "webhook_dlq"),
    ]
    for table, col, days, label in plans + optional:
        if days <= 0:
            deleted[label] = 0
            continue
        cols = table_columns(c, table)
        if not cols or col not in cols:
            deleted[label] = 0
            continue
        cutoff = ts - (days * 86400)
        count_row = c.execute(
            f"SELECT COUNT(*) AS n FROM {table} WHERE {col} > 0 AND {col} < ?",
            (cutoff,),
        ).fetchone()
        n = int(count_row["n"] if count_row else 0)
        if not dry_run and n:
            c.execute(f"DELETE FROM {table} WHERE {col} > 0 AND {col} < ?", (cutoff,))
        deleted[label] = n

    if not dry_run:
        c.commit()
        audit(
            "retention_purge",
            None,
            {"deleted": deleted, "dry_run": False},
        )
    return {"ok": True, "dry_run": dry_run, "deleted": deleted, "at": ts}
