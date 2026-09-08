"""Organization / tenant isolation helpers.

Sprint-1 approach: keep SQLite (or DATABASE_URL later) but stamp and enforce
`org_id` on core product rows so one customer never sees another's data.
"""

from __future__ import annotations

from typing import Any

from fastapi import Header, HTTPException, Request

from app.auth import AuthUser
from app.db import get_conn


def ensure_tenant_schema() -> None:
    """Add org_id columns to core product tables (idempotent)."""
    from app.commercial_ext import ensure_org_schema
    from app.db import table_columns

    ensure_org_schema()
    c = get_conn()
    for table in (
        "assets",
        "vulnerabilities",
        "risks",
        "gap_remediations",
        "chats",
        "playbooks",
        "campaigns",
        "incidents",
        "scans",
        "intel_watch",
        "xdr_events",
        "notifications",
    ):
        cols = table_columns(c, table)
        if cols and "org_id" not in cols:
            c.execute(f"ALTER TABLE {table} ADD COLUMN org_id TEXT")
    # xdr_events historically had no user_id — stamp ownership for tenant filters
    xdr_cols = table_columns(c, "xdr_events")
    if xdr_cols and "user_id" not in xdr_cols:
        c.execute("ALTER TABLE xdr_events ADD COLUMN user_id TEXT")
    # Note: users.email already exists via app.db._migrate_users (NOT NULL
    # DEFAULT '') — no migration needed here, just don't insert/compare NULL
    # against it (use '' as the "no email" sentinel).
    c.execute(
        """
        CREATE TABLE IF NOT EXISTS password_reset_tokens (
            token_hash TEXT PRIMARY KEY,
            user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            expires_at REAL NOT NULL,
            created_at REAL NOT NULL,
            used_at REAL
        )
        """
    )
    c.commit()


def user_org_ids(user_id: str) -> list[str]:
    if user_id == "local":
        return []
    ensure_tenant_schema()
    rows = get_conn().execute(
        "SELECT org_id FROM org_members WHERE user_id = ? ORDER BY created_at",
        (user_id,),
    ).fetchall()
    return [str(r["org_id"]) for r in rows]


def primary_org_id(user_id: str) -> str | None:
    ids = user_org_ids(user_id)
    return ids[0] if ids else None


def assert_org_member(user_id: str, org_id: str | None) -> None:
    if not org_id:
        return
    if user_id == "local":
        return
    if org_id not in user_org_ids(user_id):
        raise HTTPException(status_code=403, detail="Not a member of this organization")


def resolve_request_org(
    user: AuthUser,
    *,
    org_id: str | None = None,
    header_org: str | None = None,
) -> str | None:
    """Pick active org from explicit arg, X-SecuraIQ-Org header, or primary membership."""
    ensure_tenant_schema()
    chosen = (org_id or header_org or "").strip() or None
    if chosen:
        assert_org_member(user.id, chosen)
        return chosen
    return primary_org_id(user.id)


def row_visible_to_user(user_id: str, row: dict[str, Any] | None) -> bool:
    if not row:
        return False
    if row.get("user_id") == user_id or user_id == "local":
        return True
    org_id = row.get("org_id")
    if org_id and org_id in user_org_ids(user_id):
        return True
    return False


def tenant_visibility_sql(
    user_id: str,
    *,
    org_id: str | None = None,
    alias: str = "",
) -> tuple[str, list[Any]]:
    """SQL fragment + args for (own rows OR shared org rows), optional org filter."""
    prefix = f"{alias}." if alias else ""
    orgs = user_org_ids(user_id)
    if org_id:
        assert_org_member(user_id, org_id)
        return f"({prefix}org_id = ?)", [org_id]
    if not orgs:
        return f"({prefix}user_id = ?)", [user_id]
    placeholders = ",".join("?" for _ in orgs)
    return (
        f"({prefix}user_id = ? OR ({prefix}org_id IS NOT NULL AND {prefix}org_id IN ({placeholders})))",
        [user_id, *orgs],
    )


async def optional_org_header(
    x_securaiq_org: str | None = Header(default=None, alias="X-SecuraIQ-Org"),
) -> str | None:
    return (x_securaiq_org or "").strip() or None


def org_from_request(request: Request) -> str | None:
    return (request.headers.get("x-securaiq-org") or "").strip() or None
