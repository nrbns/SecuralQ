"""WebAuthn / passkey scaffold (#256).

Registration + authentication ceremony stubs. Production needs rp_id /
origin aligned to the deployment host and a real authenticator ceremony
via webauthn library when installed. SCIM/OIDC remain in their modules.
"""

from __future__ import annotations

import base64
import hashlib
import secrets
from typing import Any

from app.config import settings
from app.db import audit, get_conn, now, table_columns


def ensure_webauthn_schema() -> None:
    c = get_conn()
    c.execute(
        """
        CREATE TABLE IF NOT EXISTS webauthn_credentials (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            credential_id TEXT NOT NULL UNIQUE,
            public_key_cose TEXT NOT NULL DEFAULT '',
            sign_count INTEGER NOT NULL DEFAULT 0,
            nickname TEXT NOT NULL DEFAULT '',
            created_at REAL NOT NULL,
            last_used_at REAL NOT NULL DEFAULT 0
        )
        """
    )
    c.commit()


def enabled() -> bool:
    return bool(getattr(settings, "webauthn_enabled", False))


def rp_config() -> dict[str, str]:
    return {
        "rp_id": (getattr(settings, "webauthn_rp_id", None) or "localhost").strip(),
        "rp_name": (getattr(settings, "webauthn_rp_name", None) or "SecuraIQ").strip(),
        "origin": (getattr(settings, "webauthn_origin", None) or "http://127.0.0.1:8080").strip(),
    }


def list_credentials(user_id: str) -> list[dict[str, Any]]:
    ensure_webauthn_schema()
    rows = get_conn().execute(
        "SELECT id, credential_id, nickname, sign_count, created_at, last_used_at "
        "FROM webauthn_credentials WHERE user_id = ? ORDER BY created_at DESC",
        (user_id,),
    ).fetchall()
    return [dict(r) for r in rows]


def begin_registration(user_id: str, username: str) -> dict[str, Any]:
    """Return a PublicKeyCredentialCreationOptions-shaped challenge (lab)."""
    if not enabled():
        raise ValueError("WebAuthn is disabled (set WEBAUTHN_ENABLED=true)")
    ensure_webauthn_schema()
    challenge = secrets.token_urlsafe(32)
    cfg = rp_config()
    # Store challenge briefly in-process via audit detail (lab); production should use Redis.
    audit("webauthn_reg_begin", user_id, {"challenge_sha": hashlib.sha256(challenge.encode()).hexdigest()[:16]})
    return {
        "challenge": challenge,
        "rp": {"id": cfg["rp_id"], "name": cfg["rp_name"]},
        "user": {
            "id": base64.urlsafe_b64encode(user_id.encode()).decode().rstrip("="),
            "name": username,
            "displayName": username,
        },
        "pubKeyCredParams": [{"type": "public-key", "alg": -7}, {"type": "public-key", "alg": -257}],
        "timeout": 60000,
        "attestation": "none",
        "authenticatorSelection": {"residentKey": "preferred", "userVerification": "preferred"},
        "note": "Lab scaffold — complete ceremony with platform authenticator client-side",
    }


def finish_registration(
    user_id: str,
    *,
    credential_id: str,
    public_key_cose: str = "",
    nickname: str = "",
) -> dict[str, Any]:
    if not enabled():
        raise ValueError("WebAuthn is disabled")
    ensure_webauthn_schema()
    from app.db import new_id

    rid = new_id()
    cid = (credential_id or "").strip()
    if len(cid) < 8:
        raise ValueError("credential_id required")
    get_conn().execute(
        """
        INSERT INTO webauthn_credentials
        (id, user_id, credential_id, public_key_cose, sign_count, nickname, created_at)
        VALUES (?, ?, ?, ?, 0, ?, ?)
        """,
        (rid, user_id, cid[:512], (public_key_cose or "")[:4000], (nickname or "passkey")[:80], now()),
    )
    get_conn().commit()
    audit("webauthn_reg_finish", user_id, {"credential_id": cid[:24]})
    return {"ok": True, "id": rid, "credential_id": cid}


def begin_authentication(user_id: str) -> dict[str, Any]:
    if not enabled():
        raise ValueError("WebAuthn is disabled")
    creds = list_credentials(user_id)
    if not creds:
        raise ValueError("No WebAuthn credentials enrolled")
    challenge = secrets.token_urlsafe(32)
    cfg = rp_config()
    audit("webauthn_auth_begin", user_id, {"n_creds": len(creds)})
    return {
        "challenge": challenge,
        "rpId": cfg["rp_id"],
        "timeout": 60000,
        "userVerification": "preferred",
        "allowCredentials": [
            {"type": "public-key", "id": c["credential_id"]} for c in creds
        ],
    }


def status(user_id: str | None = None) -> dict[str, Any]:
    out: dict[str, Any] = {
        "enabled": enabled(),
        "rp": rp_config(),
        "saml_deferred": True,  # full IdP SSO until SAML_IDP_X509_CERT + signxml; ACS is fail-closed
        "scim": bool(getattr(settings, "scim_enabled", False)),
        "oidc": bool(getattr(settings, "oidc_enabled", False)),
    }
    if user_id:
        out["credentials"] = list_credentials(user_id)
    return out
