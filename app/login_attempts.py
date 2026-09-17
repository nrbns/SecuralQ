"""Persistent login/MFA attempt lockout (survives process restarts).

DB rows are the audit SoT. When Redis is configured, failure counters are also
mirrored in Redis so multi-replica API nodes share the same lockout window (#228).
"""

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


def _redis_fail_key(username: str) -> str:
    return f"securaiq:login_fail:{(username or '').strip().lower()}"


def _redis_incr_failure(username: str) -> int | None:
    """Increment Redis failure counter; return new count or None if Redis unavailable."""
    try:
        from app.redis_client import get_sync_redis, redis_enabled

        if not redis_enabled():
            return None
        r = get_sync_redis(cached=True)
        if r is None:
            return None
        key = _redis_fail_key(username)
        n = int(r.incr(key))
        if n == 1:
            r.expire(key, int(_window_sec()))
        return n
    except Exception:
        return None


def _redis_get_failures(username: str) -> int | None:
    try:
        from app.redis_client import get_sync_redis, redis_enabled

        if not redis_enabled():
            return None
        r = get_sync_redis(cached=True)
        if r is None:
            return None
        raw = r.get(_redis_fail_key(username))
        if raw is None:
            return 0
        return int(raw)
    except Exception:
        return None


def _redis_clear_failures(username: str) -> None:
    try:
        from app.redis_client import get_sync_redis, redis_enabled

        if not redis_enabled():
            return
        r = get_sync_redis(cached=True)
        if r is None:
            return
        r.delete(_redis_fail_key(username))
    except Exception:
        pass


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
    if success:
        _redis_clear_failures(user)
    else:
        _redis_incr_failure(user)


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
    db_n = int((row["n"] if row else 0) or 0)
    redis_n = _redis_get_failures(user)
    if redis_n is None:
        return db_n
    # Shared counter across replicas — take the stricter signal.
    return max(db_n, int(redis_n))


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
        "distributed": _redis_get_failures(user) is not None,
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
    """Clear Redis counter on success; DB history stays append-only for audit."""
    _redis_clear_failures((username or "").strip().lower())
