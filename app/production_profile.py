"""Production security profile — opt-in flags for commercial installs."""

from __future__ import annotations

from typing import Any

from app.config import settings


def production_profile_status() -> dict[str, Any]:
    """Report which production agent-security toggles are enabled."""
    flags = {
        "agent_mtls_enabled": bool(getattr(settings, "agent_mtls_enabled", False)),
        "agent_mtls_proxy_verify": bool(getattr(settings, "agent_mtls_proxy_verify", False)),
        "agent_mtls_require_fingerprint_match": bool(
            getattr(settings, "agent_mtls_require_fingerprint_match", False)
        ),
        "agent_require_command_signature": bool(
            getattr(settings, "agent_require_command_signature", False)
        ),
        "agent_require_replay_protection": bool(
            getattr(settings, "agent_require_replay_protection", False)
        ),
        "license_enforcement_enabled": bool(
            getattr(settings, "license_enforcement_enabled", False)
        ),
        "require_postgres_in_production": bool(
            getattr(settings, "require_postgres_in_production", True)
        ),
    }
    ready = all(
        [
            flags["agent_require_command_signature"],
            flags["agent_require_replay_protection"],
            flags["agent_mtls_enabled"],
            flags["agent_mtls_proxy_verify"],
        ]
    )
    return {
        "ok": True,
        "production_ready_agent_security": ready,
        "flags": flags,
        "env_hints": [
            "AGENT_MTLS_ENABLED=true",
            "AGENT_MTLS_PROXY_VERIFY=true",
            "AGENT_MTLS_REQUIRE_FINGERPRINT_MATCH=true",
            "AGENT_REQUIRE_COMMAND_SIGNATURE=true",
            "AGENT_REQUIRE_REPLAY_PROTECTION=true",
        ],
        "disclaimer": (
            "Lab defaults keep these off so local demos work without proxy mTLS. "
            "Enable all flags behind a terminating proxy before commercial claims."
        ),
    }
