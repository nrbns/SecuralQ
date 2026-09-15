"""Licensing package facade (Sprint 5 / Phase B) — wraps ``app.license_service``.

Server + signed entitlement is authoritative. Registry/config is cache only
(see ``app.activation_cache``).
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
    issue_trial_license,
    license_enforcement_enabled,
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
            "mode": ent.get("mode"),
            "enforcement_enabled": license_enforcement_enabled(),
        }
    except Exception as exc:
        return {"ok": False, "user_id": user_id, "error": str(exc)[:200]}


def usage_against_entitlements(user_id: str, *, org_id: str | None = None) -> dict[str, Any]:
    """Agents/users usage vs signed entitlement limits (authoritative server check)."""
    ent = effective_entitlements(user_id, org_id=org_id)
    agents_current = 0
    try:
        from app.agents import list_agents

        agents_current = len(list_agents(user_id, org_id=org_id) or [])
    except Exception:
        agents_current = 0
    max_agents = ent.get("max_agents")
    try:
        max_n = int(max_agents) if max_agents is not None else None
    except (TypeError, ValueError):
        max_n = None
    over = bool(max_n is not None and agents_current > max_n)
    allowed, reason, ent_detail = check_agent_enrollment_allowed(user_id, org_id=org_id)
    return {
        "ok": True,
        "user_id": user_id,
        "org_id": org_id,
        "plan": ent.get("plan"),
        "mode": ent.get("mode"),
        "agents_current": agents_current,
        "max_agents": max_n,
        "over_agent_limit": over,
        "enrollment": {
            "allowed": bool(allowed),
            "reason": reason,
            "agents_current": (ent_detail or {}).get("agents_current", agents_current),
        },
        "features": ent.get("features") or [],
        "enforcement_enabled": license_enforcement_enabled(),
        "disclaimer": (
            "Activation cache on the agent is not license truth — "
            "server validate_license / effective_entitlements is authoritative."
        ),
    }


def activate_trial(
    user_id: str,
    *,
    org_id: str | None = None,
    plan: str = "pro",
    days: int = 30,
) -> dict[str, Any]:
    """Commercial activation helper — issues a signed trial entitlement."""
    issued = issue_trial_license(user_id, org_id=org_id, plan=plan, days=days)
    return {
        "ok": True,
        "action": "activate_trial",
        "license": issued,
        "activation": activation_summary(user_id, org_id=org_id),
        "usage": usage_against_entitlements(user_id, org_id=org_id),
    }


def renew_subscription(
    user_id: str,
    *,
    org_id: str | None = None,
    plan: str | None = None,
    days: int = 365,
) -> dict[str, Any]:
    """Renew by issuing a new signed license (previous active row is superseded)."""
    current = get_active_license(user_id, org_id=org_id)
    use_plan = (plan or (current or {}).get("plan") or "pro").strip() or "pro"
    from app.db import now

    issued = issue_license(
        user_id,
        org_id=org_id,
        plan=use_plan,
        expires_at=now() + max(1, min(int(days), 1095)) * 86400,
    )
    return {
        "ok": True,
        "action": "renew",
        "previous_license_id": (current or {}).get("id"),
        "license": issued,
        "activation": activation_summary(user_id, org_id=org_id),
        "usage": usage_against_entitlements(user_id, org_id=org_id),
    }


def commercial_licensing_status(user_id: str, *, org_id: str | None = None) -> dict[str, Any]:
    """One-shot Phase B gate view: activation + usage + enforcement flags."""
    return {
        "ok": True,
        "activation": activation_summary(user_id, org_id=org_id),
        "usage": usage_against_entitlements(user_id, org_id=org_id),
        "validation": validate_license(user_id, org_id=org_id),
        "plans": list(LICENSE_PLANS.keys()) if isinstance(LICENSE_PLANS, dict) else [],
    }


# Roadmap alias
validator = validate_license
