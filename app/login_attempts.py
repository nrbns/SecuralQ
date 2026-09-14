"""Persistent login/MFA attempt lockout (survives process restarts)."""

from __future__ import annotations

from typing import Any

from app.config import settings
from app.db import audit, get_conn, new_id, now


def ensure_schema() -> None:
    c = get_conn()
    c.execute(
        """
        CREATE TABLE IF NOT EXISTS login_attempts (
            id TEXT PRIMARY KEY,
            username TEXT NOT NULL,
            ip TEXT NOT NULL DEFAULT '',
            success INTEGER NOT NULL DEFAULT 0,
            mfa_stage INTEGER NOT NULL DEFAULT 0,
            created_at REAL NOT NULL
        )
        """
    )
    c.execute(
        "CREATE INDEX IF NOT EXISTS idx_login_attempts_user ON login_attempts(username, created_at DESC)"
    )
    c.execute(
        "CREATE INDEX IF NOT EXISTS idx_login_attempts_ip ON login_attempts(ip, created_at DESC)"
    )
    c.commit()


def _max_failures() -> int:
    try:
        return max(3, int(getattr(settings, "login_lockout_max_failures", 8) or 8))
    except Exception:
        return 8


def _window_sec() -> float:
    try:
        return max(60.0, float(getattr(settings, "login_lockout_window_sec", 900) or 900))
    except Exception:
        return 900.0


def record_login_attempt(
    username: str,
    *,
    ip: str = "",
    success: bool,
    mfa_stage: int = 0,
) -> None:
    ensure_schema()
    user = (username or "").strip().lower() or "unknown"
    c = get_conn()
    c.execute(
        """
        INSERT INTO login_attempts (id, username, ip, success, mfa_stage, created_at)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (new_id(), user, (ip or "").strip()[:128], 1 if success else 0, int(mfa_stage), now()),
    )
    c.commit()


def failed_count(username: str, *, since: float | None = None) -> int:
    ensure_schema()
    user = (username or "").strip().lower()
    if not user:
        return 0
    cutoff = float(since if since is not None else now() - _window_sec())
    row = get_conn().execute(
        "SELECT COUNT(*) AS n FROM login_attempts "
        "WHERE username = ? AND success = 0 AND created_at >= ?",
        (user, cutoff),
    ).fetchone()
    return int((row["n"] if row else 0) or 0)


def is_locked(username: str) -> tuple[bool, dict[str, Any]]:
    """Return (locked, detail)."""
    ensure_schema()
    user = (username or "").strip().lower()
    n = failed_count(user)
    limit = _max_failures()
    detail = {
        "username": user,
        "failures": n,
        "limit": limit,
        "window_sec": int(_window_sec()),
    }
    if n >= limit:
        return True, detail
    return False, detail


def assert_not_locked(username: str) -> None:
    locked, detail = is_locked(username)
    if locked:
        audit(
            "login_lockout",
            None,
            {"username": (username or "").strip().lower(), **detail},
        )
        raise ValueError(
            f"Too many failed login attempts — try again in about "
            f"{int(_window_sec() // 60)} minutes"
        )


def clear_failures_on_success(username: str) -> None:
    """Optional soft clear: record success so rolling window recovers naturally.

    We keep history for audit; lockout is count of failures in the window only.
    """
    # No DELETE — append-only audit-friendly. Success rows don't count as failures.
    pass
