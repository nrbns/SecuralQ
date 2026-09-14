"""Local activation cache — state only, never the security source of truth.

Agents/installers may persist the server validation response under these paths
(Windows registry / Linux /etc / macOS Application Support). Cryptographic
license validity and entitlements are always re-checked against the SecuraIQ
server (`POST /api/licenses/validate`). Private signing keys must never appear
in local cache, installers, or agents.
"""

from __future__ import annotations

from typing import Any

from app.db import now

# Documented paths for packaging / agent docs (not written by the server process).
LOCAL_ACTIVATION_PATHS = {
    "windows_registry": r"HKLM\Software\SecuraIQ",
    "windows_keys": [
        "LicenseId",
        "OrganizationId",
        "ActivationStatus",
        "LastValidation",
        "LicenseExpiry",
        "AgentId",
        "Mode",
    ],
    "linux_dir": "/etc/securaiq/",
    "linux_license_file": "/etc/securaiq/license.json",
    "linux_agent_conf": "/etc/securaiq/agent.conf",
    "linux_identity_dir": "/etc/securaiq/identity/",
    "macos_dir": "/Library/Application Support/SecuraIQ/",
    "macos_license_file": "/Library/Application Support/SecuraIQ/license.json",
}


def build_activation_cache_payload(
    entitlements: dict[str, Any],
    *,
    agents_current: int = 0,
    org_id: str | None = None,
    agent_id: str | None = None,
) -> dict[str, Any]:
    """Safe JSON blob for local cache. Contains no secrets or private keys."""
    return {
        "schema": "securaiq.activation_cache.v1",
        "license_id": entitlements.get("license_id"),
        "organization_id": org_id,
        "agent_id": agent_id,
        "plan": entitlements.get("plan"),
        "plan_label": entitlements.get("plan_label"),
        "activation_status": entitlements.get("mode") or "none",
        "mode": entitlements.get("mode"),
        "status_reason": entitlements.get("status_reason"),
        "last_validation": now(),
        "license_expiry": entitlements.get("expires_at"),
        "grace_until": entitlements.get("grace_until"),
        "days_remaining": entitlements.get("days_remaining"),
        "max_agents": entitlements.get("max_agents"),
        "agents_current": agents_current,
        "features": list(entitlements.get("features") or []),
        "features_blocked": list(entitlements.get("features_blocked") or []),
        "allow_new_enrollment": entitlements.get("allow_new_enrollment"),
        "allow_premium_writes": entitlements.get("allow_premium_writes"),
        "allow_agent_checkin": entitlements.get("allow_agent_checkin"),
        "paths": LOCAL_ACTIVATION_PATHS,
        "note": (
            "Cache/state only. Re-validate with POST /api/licenses/validate. "
            "Never store LICENSE_ED25519_PRIVATE_KEY or agent signing secrets here."
        ),
    }
