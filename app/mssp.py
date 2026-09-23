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
    if cols and "white_label_name" not in cols:
        c.execute("ALTER TABLE organizations ADD COLUMN white_label_name TEXT NOT NULL DEFAULT ''")
    if cols and "white_label_accent" not in cols:
        c.execute("ALTER TABLE organizations ADD COLUMN white_label_accent TEXT NOT NULL DEFAULT ''")
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
    row = get_conn().execute(
        "SELECT white_label_name, white_label_accent FROM organizations WHERE id = ?",
        (org_id,),
    ).fetchone()
    wl_name = (row["white_label_name"] if row else "") or ""
    wl_accent = (row["white_label_accent"] if row else "") or ""
    return {
        "mssp": bool(kids) or is_mssp_parent(org_id),
        "org_id": org_id,
        "children": [{"id": k["id"], "name": k.get("name"), "slug": k.get("slug")} for k in kids if k],
        "delegated_admin": bool(kids) or is_mssp_parent(org_id),
        "white_label": {"name": wl_name, "accent": wl_accent, "enabled": bool(wl_name)},
        "disclaimer": "Lab MSSP parent→child switch — not a full white-label SaaS SKU",
    }


def set_white_label(org_id: str, *, name: str = "", accent: str = "") -> dict[str, Any]:
    ensure_mssp_schema()
    get_conn().execute(
        "UPDATE organizations SET white_label_name = ?, white_label_accent = ?, updated_at = ? WHERE id = ?",
        ((name or "")[:80], (accent or "")[:20], now(), org_id),
    )
    get_conn().commit()
    audit("mssp_white_label", None, {"org_id": org_id, "name": name[:80]})
    return mssp_status(org_id)


def central_soc_summary(parent_org_id: str) -> dict[str, Any]:
    """Aggregate child-org counts for a parent MSSP (lab central SOC)."""
    kids = list_children(parent_org_id)
    from app.db import get_conn as _gc

    c = _gc()
    child_ids = [k["id"] for k in kids if k.get("id")]
    asset_n = 0
    if child_ids:
        placeholders = ",".join("?" * len(child_ids))
        try:
            row = c.execute(
                f"SELECT COUNT(*) AS n FROM assets WHERE org_id IN ({placeholders})",
                child_ids,
            ).fetchone()
            asset_n = int((row["n"] if row else 0) or 0)
        except Exception:
            asset_n = 0
    return {
        "ok": True,
        "parent_org_id": parent_org_id,
        "customers": len(child_ids),
        "child_assets": asset_n,
        "delegated_admin": True,
        "disclaimer": "Lab central SOC rollup — not a multi-tenant MDR console",
    }
