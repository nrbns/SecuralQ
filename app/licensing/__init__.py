"""Licensing package facade (Sprint 5) — wraps ``app.license_service``.

Keeps the commercial layout the product roadmap expects without rewriting
the signed-license implementation that already lives in ``license_service``.
"""

from __future__ import annotations

from typing import Any

from app.license_service import (  # noqa: F401
    LICENSE_PLANS,
    check_agent_enrollment_allowed,
    effective_entitlements,
    ensure_schema as ensure_license_schema,
    entitlements_for_plan,
    get_active_license,
    issue_license,
    revoke_license,
    validate_license,
)
from app import license_api as api  # noqa: F401
from app import license_service as service  # noqa: F401


def activation_summary(user_id: str, *, org_id: str | None = None) -> dict[str, Any]:
    """Best-effort activation view for an org/user license."""
    try:
        lic = get_active_license(user_id, org_id=org_id)
        if not lic:
            return {"ok": False, "user_id": user_id, "org_id": org_id, "status": "none"}
        ent = effective_entitlements(user_id, org_id=org_id)
        return {
            "ok": True,
            "user_id": user_id,
            "org_id": org_id or lic.get("org_id"),
            "status": lic.get("status") or "unknown",
            "plan": lic.get("plan") or ent.get("plan"),
            "max_agents": ent.get("max_agents"),
            "features": ent.get("features") or [],
        }
    except Exception as exc:
        return {"ok": False, "user_id": user_id, "error": str(exc)[:200]}


# Roadmap alias
validator = validate_license
