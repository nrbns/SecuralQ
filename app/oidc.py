"""OpenID Connect (OIDC) login — Keycloak / Authentik / Azure AD compatible."""

from __future__ import annotations

import secrets
from typing import Any
from urllib.parse import urlencode

import httpx

from app.auth import AuthUser, hash_password, hash_token
from app.config import settings
from app.db import audit, get_conn, new_id, now


def oidc_configured() -> bool:
    return bool(
        settings.oidc_enabled
        and settings.oidc_issuer.strip()
        and settings.oidc_client_id.strip()
        and settings.oidc_client_secret.strip()
    )


def production_ready() -> bool:
    """Lab/production readiness for OIDC — requires issuer + client credentials."""
    return oidc_configured() and bool((settings.oidc_redirect_uri or "").strip())


def status() -> dict[str, Any]:
    """IdP facade readiness — does not imply a live IdP handshake succeeded."""
    issuer = (settings.oidc_issuer or "").strip()
    return {
        "protocol": "oidc",
        "enabled": bool(settings.oidc_enabled),
        "issuer": issuer or None,
        "client_id_set": bool((settings.oidc_client_id or "").strip()),
        "client_secret_set": bool((settings.oidc_client_secret or "").strip()),
        "redirect_uri": (settings.oidc_redirect_uri or "").strip() or None,
        "scopes": settings.oidc_scopes or "openid profile email",
        "configured": oidc_configured(),
        "production_ready": production_ready(),
        "login_path": "/api/auth/oidc/login",
        "callback_path": "/api/auth/oidc/callback",
        "note": (
            "OIDC facade is ready when OIDC_ENABLED + issuer + client id/secret + redirect are set. "
            "Live IdP discovery/login still requires a reachable issuer. "
            "Not a full enterprise IdP certification."
        ),
    }


async def _discovery() -> dict[str, Any]:
    issuer = settings.oidc_issuer.rstrip("/")
    url = f"{issuer}/.well-known/openid-configuration"
    async with httpx.AsyncClient(timeout=20.0, follow_redirects=True) as client:
        r = await client.get(url)
        r.raise_for_status()
        return r.json()


def create_oidc_state() -> str:
    state = secrets.token_urlsafe(24)
    c = get_conn()
    c.execute(
        "INSERT INTO oidc_states (state, created_at, expires_at) VALUES (?, ?, ?)",
        (state, now(), now() + 600),
    )
    c.commit()
    return state


def consume_oidc_state(state: str) -> bool:
    s = (state or "").strip()
    if not s:
        return False
    c = get_conn()
    row = c.execute(
        "SELECT expires_at FROM oidc_states WHERE state = ?", (s,)
    ).fetchone()
    c.execute("DELETE FROM oidc_states WHERE state = ?", (s,))
    c.commit()
    if not row or float(row["expires_at"]) < now():
        return False
    return True


async def build_authorize_url() -> str:
    meta = await _discovery()
    state = create_oidc_state()
    params = {
        "client_id": settings.oidc_client_id,
        "response_type": "code",
        "scope": settings.oidc_scopes or "openid profile email",
        "redirect_uri": settings.oidc_redirect_uri,
        "state": state,
    }
    return f"{meta['authorization_endpoint']}?{urlencode(params)}"


async def exchange_code(code: str) -> dict[str, Any]:
    meta = await _discovery()
    async with httpx.AsyncClient(timeout=25.0) as client:
        r = await client.post(
            meta["token_endpoint"],
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": settings.oidc_redirect_uri,
                "client_id": settings.oidc_client_id,
                "client_secret": settings.oidc_client_secret,
            },
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        r.raise_for_status()
        tokens = r.json()
        access = tokens.get("access_token")
        if not access:
            raise ValueError("OIDC token response missing access_token")
        ui = meta.get("userinfo_endpoint")
        if not ui:
            raise ValueError("OIDC discovery missing userinfo_endpoint")
        ur = await client.get(ui, headers={"Authorization": f"Bearer {access}"})
        ur.raise_for_status()
        profile = ur.json()
    return profile


def provision_oidc_user(profile: dict[str, Any]) -> AuthUser:
    sub = str(profile.get("sub") or "").strip()
    if not sub:
        raise ValueError("OIDC profile missing sub")
    email = (profile.get("email") or "").strip().lower()
    preferred = (
        profile.get("preferred_username")
        or profile.get("username")
        or (email.split("@")[0] if email else "")
        or f"oidc-{sub[:12]}"
    )
    username = preferred.strip().lower()[:80]
    c = get_conn()
    row = c.execute("SELECT * FROM users WHERE oidc_sub = ?", (sub,)).fetchone()
    if row:
        if email and not (row["email"] or ""):
            c.execute("UPDATE users SET email = ? WHERE id = ?", (email, row["id"]))
            c.commit()
        audit("oidc_login", row["id"], {"sub": sub})
        return AuthUser(id=row["id"], username=row["username"], role=row["role"])

    # New JIT user
    base = username
    n = 0
    while c.execute("SELECT 1 FROM users WHERE username = ?", (username,)).fetchone():
        n += 1
        username = f"{base}{n}"[:80]
    uid = new_id()
    c.execute(
        "INSERT INTO users (id, username, password_hash, role, email, oidc_sub, created_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?)",
        (uid, username, hash_password(secrets.token_urlsafe(32)), "user", email, sub, now()),
    )
    c.commit()
    audit("oidc_register", uid, {"sub": sub, "username": username})
    return AuthUser(id=uid, username=username, role="user")


def create_session_for_user(user: AuthUser) -> str:
    import secrets as _secrets

    from app.auth import SESSION_DAYS

    token = _secrets.token_urlsafe(32)
    expires = now() + SESSION_DAYS * 86400
    c = get_conn()
    c.execute(
        "INSERT INTO sessions (token, user_id, expires_at, created_at) VALUES (?, ?, ?, ?)",
        (hash_token(token), user.id, expires, now()),
    )
    c.commit()
    audit("login", user.id, {"username": user.username, "method": "oidc"})
    return token
