"""Commercial auth surface (Sprint 5 / Phase B).

Re-exports MFA / session helpers. WebAuthn / OIDC / SAML / SCIM stay in their
existing modules — this is the stable commercial import path.
"""

from __future__ import annotations

from typing import Any

from app import mfa as mfa  # noqa: F401
from app.auth import AuthUser, login, register_user  # noqa: F401


def mfa_status(user_id: str) -> dict[str, Any]:
    try:
        from app.mfa import mfa_status as _status

        return dict(_status(user_id) or {})
    except Exception as exc:
        return {"user_id": user_id, "error": str(exc)[:120]}


def identity_v1_status(user_id: str) -> dict[str, Any]:
    """Phase B V1 identity checklist: password + TOTP MFA + RBAC + audit hooks."""
    from app.config import settings
    from app.rbac import permission_matrix

    st = mfa_status(user_id)
    return {
        "ok": True,
        "user_id": user_id,
        "password_auth": True,
        "totp_mfa": {
            "enabled": bool(st.get("enabled") or st.get("mfa_enabled")),
            "enrolled": bool(st.get("enrolled")),
            "recovery_codes_remaining": st.get("recovery_codes_remaining"),
            "mandatory": bool(getattr(settings, "mfa_required", False)),
        },
        "rbac": permission_matrix(),
        "session_management": True,
        "audit_log": True,
        "v2_deferred": ["webauthn", "oidc", "saml", "scim", "conditional_access"],
        "disclaimer": (
            "V1 commercial identity is password + TOTP MFA + org RBAC. "
            "WebAuthn/SSO/SCIM modules may exist but are not claimed complete here."
        ),
    }
