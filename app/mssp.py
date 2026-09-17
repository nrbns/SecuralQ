"""MSSP multi-org hierarchy (#259).

Parent (MSSP) orgs can list / switch into child customer orgs.
Soft: tables migrate on first use; single-org deployments unchanged.
"""

from __future__ import annotations

from typing import Any

from app.commercial_ext import ensure_org_schema
from app.db import audit, get_conn, new_id, now, row_to_dict, table_columns


def ensure_mssp_schema() -> None:
    ensure_org_schema()
    c = get_conn()
    cols = table_columns(c, "organizations")
    if cols and "parent_org_id" not in cols:
        c.execute("ALTER TABLE organizations ADD COLUMN parent_org_id TEXT")
    if cols and "org_type" not in cols:
        c.execute("ALTER TABLE organizations ADD COLUMN org_type TEXT NOT NULL DEFAULT 'customer'")
    c.execute(
        """
        CREATE TABLE IF NOT EXISTS mssp_org_links (
            id TEXT PRIMARY KEY,
            parent_org_id TEXT NOT NULL,
            child_org_id TEXT NOT NULL,
            created_at REAL NOT NULL,
            UNIQUE(parent_org_id, child_org_id)
        )
        """
    )
    c.commit()


def link_child(parent_org_id: str, child_org_id: str, *, actor_user_id: str | None = None) -> dict[str, Any]:
    ensure_mssp_schema()
    if parent_org_id == child_org_id:
        raise ValueError("Cannot link org to itself")
    c = get_conn()
    for oid in (parent_org_id, child_org_id):
        if not c.execute("SELECT 1 FROM organizations WHERE id = ?", (oid,)).fetchone():
            raise ValueError(f"Unknown org {oid}")
    lid = new_id()
    c.execute(
        "INSERT OR IGNORE INTO mssp_org_links (id, parent_org_id, child_org_id, created_at) VALUES (?, ?, ?, ?)",
        (lid, parent_org_id, child_org_id, now()),
    )
    c.execute(
        "UPDATE organizations SET parent_org_id = ?, org_type = 'customer' WHERE id = ?",
        (parent_org_id, child_org_id),
    )
    c.execute(
        "UPDATE organizations SET org_type = 'mssp' WHERE id = ?",
        (parent_org_id,),
    )
    c.commit()
    audit("mssp_link", actor_user_id, {"parent": parent_org_id, "child": child_org_id})
    return {"ok": True, "parent_org_id": parent_org_id, "child_org_id": child_org_id}


def list_children(parent_org_id: str) -> list[dict[str, Any]]:
    ensure_mssp_schema()
    c = get_conn()
    rows = c.execute(
        """
        SELECT o.* FROM organizations o
        JOIN mssp_org_links l ON l.child_org_id = o.id
        WHERE l.parent_org_id = ?
        ORDER BY o.name
        """,
        (parent_org_id,),
    ).fetchall()
    return [row_to_dict(r) for r in rows if r]


def is_mssp_parent(org_id: str) -> bool:
    ensure_mssp_schema()
    row = get_conn().execute(
        "SELECT 1 FROM mssp_org_links WHERE parent_org_id = ? LIMIT 1", (org_id,)
    ).fetchone()
    return bool(row)


def can_access_child(actor_org_id: str, target_org_id: str) -> bool:
    if actor_org_id == target_org_id:
        return True
    ensure_mssp_schema()
    row = get_conn().execute(
        "SELECT 1 FROM mssp_org_links WHERE parent_org_id = ? AND child_org_id = ?",
        (actor_org_id, target_org_id),
    ).fetchone()
    return bool(row)


def mssp_status(org_id: str | None) -> dict[str, Any]:
    if not org_id:
        return {"mssp": False, "children": []}
    kids = list_children(org_id)
    return {
        "mssp": bool(kids) or is_mssp_parent(org_id),
        "org_id": org_id,
        "children": [{"id": k["id"], "name": k.get("name"), "slug": k.get("slug")} for k in kids if k],
    }
