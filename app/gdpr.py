"""GDPR Art.15/17/20 style subject export + erasure (#238).

Scoped to a user_id (data subject). Org admins call via API with RBAC.
Erasure anonymizes audit rows and deletes personal product data; license/
billing rows are retained as legal obligation stubs when present.
"""

from __future__ import annotations

import json
from typing import Any

from app.db import audit, get_conn, now, row_to_dict, table_columns


def _table_has(c, table: str, col: str) -> bool:
    cols = table_columns(c, table)
    return bool(cols) and col in cols


def export_subject(user_id: str) -> dict[str, Any]:
    """Portable JSON pack of the subject's data."""
    c = get_conn()
    pack: dict[str, Any] = {"user_id": user_id, "exported_at": now(), "tables": {}}

    user = c.execute("SELECT id, username, email, role, created_at, mfa_enabled FROM users WHERE id = ?", (user_id,)).fetchone()
    pack["user"] = row_to_dict(user)
    if pack["user"]:
        pack["user"].pop("password_hash", None)

    for table, uid_col in (
        ("files", "user_id"),
        ("chats", "user_id"),
        ("sessions", "user_id"),
        ("notifications", "user_id"),
        ("audit_log", "user_id"),
        ("securaiq_agents", "user_id"),
        ("webhooks", "user_id"),
        ("incidents", "user_id"),
        ("scans", "user_id"),
    ):
        if not _table_has(c, table, uid_col):
            continue
        rows = c.execute(f"SELECT * FROM {table} WHERE {uid_col} = ? LIMIT 5000", (user_id,)).fetchall()
        items = []
        for r in rows:
            d = row_to_dict(r) or {}
            d.pop("password_hash", None)
            d.pop("agent_key_hash", None)
            d.pop("token", None)
            items.append(d)
        pack["tables"][table] = items

    # Org memberships
    if _table_has(c, "org_members", "user_id"):
        rows = c.execute("SELECT * FROM org_members WHERE user_id = ?", (user_id,)).fetchall()
        pack["tables"]["org_members"] = [row_to_dict(r) for r in rows]

    audit("gdpr_export", user_id, {"tables": list(pack["tables"].keys())})
    return pack


def erase_subject(user_id: str, *, keep_audit_tombstones: bool = True) -> dict[str, Any]:
    """Erase / anonymize subject data. Returns counts."""
    c = get_conn()
    counts: dict[str, int] = {}

    def _del(table: str, col: str = "user_id") -> None:
        if not _table_has(c, table, col):
            counts[table] = 0
            return
        cur = c.execute(f"DELETE FROM {table} WHERE {col} = ?", (user_id,))
        counts[table] = int(cur.rowcount or 0)

    # Sessions and tokens first
    _del("sessions")
    if _table_has(c, "password_reset_tokens", "user_id"):
        _del("password_reset_tokens")

    for table in (
        "files",
        "chats",
        "notifications",
        "webhooks",
        "incidents",
        "scans",
        "intel_watch",
        "playbooks",
        "campaigns",
    ):
        _del(table)

    # Agents: revoke then delete
    if _table_has(c, "securaiq_agents", "user_id"):
        c.execute("UPDATE securaiq_agents SET revoked = 1 WHERE user_id = ?", (user_id,))
        _del("securaiq_agents")

    if keep_audit_tombstones and _table_has(c, "audit_log", "user_id"):
        cur = c.execute(
            "UPDATE audit_log SET detail = ?, user_id = ? WHERE user_id = ?",
            (json.dumps({"redacted": True, "reason": "gdpr_erasure"}), f"erased:{user_id[:8]}", user_id),
        )
        counts["audit_log_redacted"] = int(cur.rowcount or 0)
    else:
        _del("audit_log")

    if _table_has(c, "org_members", "user_id"):
        _del("org_members")

    # Anonymize user row (keep id for FK integrity on retained legal rows)
    if _table_has(c, "users", "id"):
        anon = f"erased_{user_id[:12]}"
        c.execute(
            "UPDATE users SET username = ?, email = '', password_hash = '', mfa_enabled = 0, "
            "mfa_secret = '', role = 'viewer' WHERE id = ?",
            (anon, user_id),
        )
        counts["users_anonymized"] = 1

    c.commit()
    audit("gdpr_erasure", f"erased:{user_id[:8]}", {"counts": counts})
    return {"ok": True, "user_id": user_id, "counts": counts}
