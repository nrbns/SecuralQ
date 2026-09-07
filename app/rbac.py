"""Central permission checks for SecuraIQ commercial RBAC.

Global roles (users.role): admin | user
Org roles (org_members.role): admin | analyst | viewer | client

Lab mode (AUTH_ENABLED=false, synthetic user `local`) is treated as global admin.
"""

from __future__ import annotations

from typing import Any

from fastapi import HTTPException

from app.auth import AuthUser

# action -> minimum org role (when operating inside an org)
# global admin always bypasses
ORG_ROLE_RANK = {"client": 0, "viewer": 1, "analyst": 2, "admin": 3}

PERMISSIONS: dict[str, dict[str, Any]] = {
    # action: {global: set[role], org_min: role | None}
    "workspace.read": {"global": {"admin", "user"}, "org_min": "viewer"},
    "workspace.write": {"global": {"admin", "user"}, "org_min": "analyst"},
    "asset.read": {"global": {"admin", "user"}, "org_min": "viewer"},
    "asset.write": {"global": {"admin", "user"}, "org_min": "analyst"},
    "vuln.read": {"global": {"admin", "user"}, "org_min": "viewer"},
    "vuln.write": {"global": {"admin", "user"}, "org_min": "analyst"},
    "vuln.triage": {"global": {"admin", "user"}, "org_min": "analyst"},
    "risk.read": {"global": {"admin", "user"}, "org_min": "viewer"},
    "risk.write": {"global": {"admin", "user"}, "org_min": "analyst"},
    "report.export": {"global": {"admin", "user"}, "org_min": "viewer"},
    "org.manage": {"global": {"admin"}, "org_min": "admin"},
    "audit.read": {"global": {"admin"}, "org_min": "admin"},
    "settings.write": {"global": {"admin"}, "org_min": None},
    "tools.run": {"global": {"admin", "user"}, "org_min": "analyst"},
    "agent.read": {"global": {"admin", "user"}, "org_min": "viewer"},
    "agent.write": {"global": {"admin", "user"}, "org_min": "analyst"},
    "agent.command": {"global": {"admin", "user"}, "org_min": "analyst"},
    "agent.approve": {"global": {"admin"}, "org_min": "admin"},
}


def is_global_admin(user: AuthUser) -> bool:
    return (user.role or "").lower() == "admin" or user.id == "local"


def org_role_for(user_id: str, org_id: str | None) -> str | None:
    if not org_id or user_id == "local":
        return "admin" if user_id == "local" else None
    from app.commercial_ext import ensure_org_schema
    from app.db import get_conn

    ensure_org_schema()
    row = get_conn().execute(
        "SELECT role FROM org_members WHERE org_id = ? AND user_id = ?",
        (org_id, user_id),
    ).fetchone()
    return str(row["role"]) if row else None


def has_perm(user: AuthUser, action: str, *, org_id: str | None = None) -> bool:
    spec = PERMISSIONS.get(action)
    if not spec:
        return False
    if is_global_admin(user):
        return True
    global_ok = (user.role or "user").lower() in spec.get("global", set())
    if not org_id:
        return global_ok
    org_min = spec.get("org_min")
    if org_min is None:
        return global_ok and is_global_admin(user)
    role = org_role_for(user.id, org_id)
    if not role:
        return False
    return ORG_ROLE_RANK.get(role, -1) >= ORG_ROLE_RANK.get(str(org_min), 99)


def require_perm(user: AuthUser, action: str, *, org_id: str | None = None) -> None:
    if not has_perm(user, action, org_id=org_id):
        raise HTTPException(
            status_code=403,
            detail=f"Permission denied for `{action}`"
            + (f" in organization {org_id}" if org_id else ""),
        )
