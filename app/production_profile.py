"""Production security profile — opt-in flags for commercial installs."""

from __future__ import annotations

import os
from typing import Any

from app.config import settings


def _env_truthy(name: str) -> bool:
    return (os.environ.get(name) or "").strip().lower() in ("1", "true", "yes", "on")


def commercial_profile_enforced() -> bool:
    """True when SECURAIQ_COMMERCIAL_PROFILE / settings demand commercial crypto."""
    if bool(getattr(settings, "commercial_profile_enforce", False)):
        return True
    return _env_truthy("SECURAIQ_COMMERCIAL_PROFILE") or _env_truthy("COMMERCIAL_PROFILE_ENFORCE")


def production_profile_status() -> dict[str, Any]:
    """Report which production agent-security toggles are enabled."""
    alg = str(getattr(settings, "agent_command_signing_alg", "hmac") or "hmac").strip().lower()
    has_ed25519_priv = bool(str(getattr(settings, "agent_ed25519_private_key", "") or "").strip())
    has_ed25519_pub = bool(str(getattr(settings, "agent_ed25519_public_key", "") or "").strip())
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
        "agent_command_signing_alg": alg,
        "commercial_profile_enforce": commercial_profile_enforced(),
    }
    ready = all(
        [
            flags["agent_require_command_signature"],
            flags["agent_require_replay_protection"],
            flags["agent_mtls_enabled"],
            flags["agent_mtls_proxy_verify"],
            flags["agent_mtls_require_fingerprint_match"],
        ]
    )
    # Commercial signing: Ed25519 with server private key; agents hold verify pubkey only.
    commercial_signing = (
        ready
        and alg == "ed25519"
        and has_ed25519_priv
        and has_ed25519_pub
    )
    return {
        "ok": True,
        "production_ready_agent_security": ready,
        "commercial_ready_command_signing": commercial_signing,
        "commercial_profile_enforced": flags["commercial_profile_enforce"],
        "flags": flags,
        "env_hints": [
            "AGENT_MTLS_ENABLED=true",
            "AGENT_MTLS_PROXY_VERIFY=true",
            "AGENT_MTLS_REQUIRE_FINGERPRINT_MATCH=true",
            "AGENT_REQUIRE_COMMAND_SIGNATURE=true",
            "AGENT_REQUIRE_REPLAY_PROTECTION=true",
            "AGENT_COMMAND_SIGNING_ALG=ed25519",
            "AGENT_ED25519_PRIVATE_KEY=…",
            "AGENT_ED25519_PUBLIC_KEY=…",
            "SECURAIQ_COMMERCIAL_PROFILE=1",
        ],
        "disclaimer": (
            "Lab defaults keep mTLS/signature flags off so local demos work without a proxy. "
            "Enable all five agent-security flags behind a terminating proxy before commercial claims. "
            "Commercial builds should set AGENT_COMMAND_SIGNING_ALG=ed25519 (HMAC remains lab-friendly). "
            "Set SECURAIQ_COMMERCIAL_PROFILE=1 to refuse boot without the full commercial crypto set. "
            "Agents present issued client certs (agent.crt/agent.key); never ship the signing private key."
        ),
    }


def assert_commercial_profile() -> None:
    """Refuse startup when commercial profile is enforced but not ready.

    Lab default: no-op. Enable via SECURAIQ_COMMERCIAL_PROFILE=1 or
    COMMERCIAL_PROFILE_ENFORCE=true / settings.commercial_profile_enforce.
    """
    if not commercial_profile_enforced():
        return
    st = production_profile_status()
    if st.get("commercial_ready_command_signing"):
        return
    missing: list[str] = []
    flags = st.get("flags") or {}
    for key in (
        "agent_mtls_enabled",
        "agent_mtls_proxy_verify",
        "agent_mtls_require_fingerprint_match",
        "agent_require_command_signature",
        "agent_require_replay_protection",
    ):
        if not flags.get(key):
            missing.append(key)
    alg = str(flags.get("agent_command_signing_alg") or "hmac")
    if alg != "ed25519":
        missing.append("agent_command_signing_alg=ed25519")
    if not str(getattr(settings, "agent_ed25519_private_key", "") or "").strip():
        missing.append("agent_ed25519_private_key")
    if not str(getattr(settings, "agent_ed25519_public_key", "") or "").strip():
        missing.append("agent_ed25519_public_key")
    raise RuntimeError(
        "SECURAIQ_COMMERCIAL_PROFILE is enabled but commercial agent security is incomplete. "
        f"Missing/incorrect: {', '.join(missing) or 'unknown'}. "
        "Disable SECURAIQ_COMMERCIAL_PROFILE for lab demos, or set all five mTLS/signature "
        "flags plus AGENT_COMMAND_SIGNING_ALG=ed25519 with server-side Ed25519 keys."
    )
