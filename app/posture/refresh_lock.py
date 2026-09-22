"""Org-level posture refresh locks — prevent duplicate identical runs."""

from __future__ import annotations

from typing import Any

from app.db import get_conn, now
from app.posture.schema import ensure_posture_schema


def acquire_refresh_lock(
    lock_key: str,
    *,
    run_id: str,
    user_id: str,
    org_id: str | None = None,
    ttl_sec: int = 1800,
) -> bool:
    """Return True if lock acquired. Expired locks are stolen."""
    ensure_posture_schema()
    t = now()
    c = get_conn()
    row = c.execute(
        "SELECT run_id, expires_at FROM posture_locks WHERE lock_key = ?", (lock_key,)
    ).fetchone()
    if row and float(row["expires_at"] or 0) > t:
        return False
    c.execute(
        """
        INSERT INTO posture_locks (lock_key, run_id, user_id, org_id, acquired_at, expires_at)
        VALUES (?, ?, ?, ?, ?, ?)
        ON CONFLICT(lock_key) DO UPDATE SET
            run_id = excluded.run_id,
            user_id = excluded.user_id,
            org_id = excluded.org_id,
            acquired_at = excluded.acquired_at,
            expires_at = excluded.expires_at
        """,
        (lock_key, run_id, user_id, org_id, t, t + max(60, ttl_sec)),
    )
    c.commit()
    return True


def release_refresh_lock(lock_key: str, *, run_id: str | None = None) -> None:
    ensure_posture_schema()
    if run_id:
        get_conn().execute(
            "DELETE FROM posture_locks WHERE lock_key = ? AND run_id = ?",
            (lock_key, run_id),
        )
    else:
        get_conn().execute("DELETE FROM posture_locks WHERE lock_key = ?", (lock_key,))
    get_conn().commit()


def lock_status(lock_key: str) -> dict[str, Any] | None:
    ensure_posture_schema()
    row = get_conn().execute(
        "SELECT * FROM posture_locks WHERE lock_key = ?", (lock_key,)
    ).fetchone()
    if not row:
        return None
    d = dict(row)
    d["active"] = float(d.get("expires_at") or 0) > now()
    return d
