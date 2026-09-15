"""Commercial auth surface (Sprint 5) — re-exports existing MFA / session modules.

WebAuthn / OIDC / SAML / SCIM remain in their existing modules; this package
is the stable import path for commercial docs (``app.auth_commercial``).
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
