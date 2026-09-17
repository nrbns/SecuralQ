"""Per-tenant product quotas (#231).

Combines license max_agents with configurable org caps for uploads,
scans/day, and API calls/minute (enforced via tenant_quotas + rate_limit).
"""

from __future__ import annotations

from typing import Any

from app.config import settings
from app.db import get_conn, table_columns


DEFAULT_QUOTAS = {
    "max_agents": 5,
    "max_upload_mb": 500,
    "max_scans_per_day": 50,
    "api_per_minute": 300,
}


def ensure_quota_schema() -> None:
    c = get_conn()
    c.execute(
        """
        CREATE TABLE IF NOT EXISTS org_quotas (
            org_id TEXT PRIMARY KEY,
            max_agents INTEGER NOT NULL DEFAULT 5,
            max_upload_mb INTEGER NOT NULL DEFAULT 500,
            max_scans_per_day INTEGER NOT NULL DEFAULT 50,
            api_per_minute INTEGER NOT NULL DEFAULT 300,
            updated_at REAL NOT NULL DEFAULT 0
        )
        """
    )
    c.commit()


def get_quotas(org_id: str | None) -> dict[str, Any]:
    ensure_quota_schema()
    oid = (org_id or "").strip()
    base = dict(DEFAULT_QUOTAS)
    # Overlay license plan max_agents when available
    try:
        from app.license_service import effective_entitlements

        if oid:
            ent = effective_entitlements(oid)
            if ent and ent.get("max_agents") is not None:
                base["max_agents"] = int(ent["max_agents"])
    except Exception:
        pass
    if not oid:
        return base
    row = get_conn().execute("SELECT * FROM org_quotas WHERE org_id = ?", (oid,)).fetchone()
    if row:
        for k in DEFAULT_QUOTAS:
            if row[k] is not None:
                base[k] = int(row[k])
    return base


def set_quotas(org_id: str, **kwargs: int) -> dict[str, Any]:
    ensure_quota_schema()
    from app.db import now

    cur = get_quotas(org_id)
    for k, v in kwargs.items():
        if k in DEFAULT_QUOTAS and v is not None:
            cur[k] = int(v)
    get_conn().execute(
        """
        INSERT INTO org_quotas (org_id, max_agents, max_upload_mb, max_scans_per_day, api_per_minute, updated_at)
        VALUES (?, ?, ?, ?, ?, ?)
        ON CONFLICT(org_id) DO UPDATE SET
          max_agents=excluded.max_agents,
          max_upload_mb=excluded.max_upload_mb,
          max_scans_per_day=excluded.max_scans_per_day,
          api_per_minute=excluded.api_per_minute,
          updated_at=excluded.updated_at
        """,
        (
            org_id,
            cur["max_agents"],
            cur["max_upload_mb"],
            cur["max_scans_per_day"],
            cur["api_per_minute"],
            now(),
        ),
    )
    get_conn().commit()
    return get_quotas(org_id)


def usage(org_id: str | None, user_id: str | None = None) -> dict[str, Any]:
    """Current usage counters for quota checks."""
    c = get_conn()
    oid = (org_id or "").strip()
    agents = 0
    upload_bytes = 0
    scans_today = 0
    if oid and table_columns(c, "securaiq_agents") and "org_id" in table_columns(c, "securaiq_agents"):
        row = c.execute(
            "SELECT COUNT(*) AS n FROM securaiq_agents WHERE org_id = ? AND COALESCE(revoked,0)=0",
            (oid,),
        ).fetchone()
        agents = int(row["n"] if row else 0)
    elif user_id and table_columns(c, "securaiq_agents"):
        row = c.execute(
            "SELECT COUNT(*) AS n FROM securaiq_agents WHERE user_id = ? AND COALESCE(revoked,0)=0",
            (user_id,),
        ).fetchone()
        agents = int(row["n"] if row else 0)

    if user_id and table_columns(c, "files"):
        row = c.execute(
            "SELECT COALESCE(SUM(size_bytes),0) AS total FROM files WHERE user_id = ?",
            (user_id,),
        ).fetchone()
        upload_bytes = int(row["total"] if row else 0)

    if table_columns(c, "scans"):
        from app.db import now as _now

        day_start = _now() - 86400
        if oid and "org_id" in table_columns(c, "scans"):
            row = c.execute(
                "SELECT COUNT(*) AS n FROM scans WHERE org_id = ? AND created_at >= ?",
                (oid, day_start),
            ).fetchone()
        elif user_id:
            row = c.execute(
                "SELECT COUNT(*) AS n FROM scans WHERE user_id = ? AND created_at >= ?",
                (user_id, day_start),
            ).fetchone()
        else:
            row = None
        scans_today = int(row["n"] if row else 0)

    q = get_quotas(oid or None)
    return {
        "org_id": oid or None,
        "quotas": q,
        "usage": {
            "agents": agents,
            "upload_mb": round(upload_bytes / (1024 * 1024), 2),
            "scans_today": scans_today,
        },
        "ok_agents": agents < int(q["max_agents"]),
        "ok_uploads": (upload_bytes / (1024 * 1024)) < float(q["max_upload_mb"]),
        "ok_scans": scans_today < int(q["max_scans_per_day"]),
        "api_per_minute": int(q["api_per_minute"]),
        "enforcement": bool(getattr(settings, "quota_enforcement_enabled", False)),
    }


def assert_can_enroll_agent(org_id: str | None, user_id: str | None = None) -> None:
    if not getattr(settings, "quota_enforcement_enabled", False):
        return
    u = usage(org_id, user_id)
    if not u["ok_agents"]:
        raise ValueError(
            f"Agent quota exceeded ({u['usage']['agents']}/{u['quotas']['max_agents']}). "
            "Upgrade plan or revoke unused agents."
        )


def assert_can_scan(org_id: str | None, user_id: str | None = None) -> None:
    if not getattr(settings, "quota_enforcement_enabled", False):
        return
    u = usage(org_id, user_id)
    if not u["ok_scans"]:
        raise ValueError(
            f"Daily scan quota exceeded ({u['usage']['scans_today']}/{u['quotas']['max_scans_per_day']})."
        )
