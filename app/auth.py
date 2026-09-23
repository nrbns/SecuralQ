"""Local auth: users, sessions, API keys (stdlib crypto)."""

from __future__ import annotations

import hashlib
import hmac
import secrets
from dataclasses import dataclass
from typing import Any

from app.config import settings
from app.db import audit, get_conn, new_id, now

SESSION_DAYS = 14  # fallback; prefer settings.session_days


def _session_ttl_days() -> int:
    try:
        return max(1, int(getattr(settings, "session_days", SESSION_DAYS) or SESSION_DAYS))
    except Exception:
        return SESSION_DAYS


@dataclass
class AuthUser:
    id: str
    username: str
    role: str


def _is_production_mode() -> bool:
    mode = (getattr(settings, "deployment_mode", "lab") or "lab").lower()
    return mode in {"production", "prod", "commercial", "saas", "cloud"}


def using_postgres_url() -> bool:
    url = (getattr(settings, "database_url", "") or "").strip().lower()
    return url.startswith("postgres://") or url.startswith("postgresql://")


def assert_safe_deployment_auth() -> None:
    """Refuse unsafe auth/bind/database combinations for commercial / internet exposure."""
    host = (settings.host or "").strip()
    open_bind = host in {"0.0.0.0", "::", "[::]"}
    if _is_production_mode() and not settings.auth_enabled:
        raise RuntimeError(
            "DEPLOYMENT_MODE=production requires AUTH_ENABLED=true. "
            "Never expose SecuraIQ without authentication."
        )
    if (
        _is_production_mode()
        and getattr(settings, "require_postgres_in_production", True)
        and not using_postgres_url()
    ):
        raise RuntimeError(
            "DEPLOYMENT_MODE=production requires DATABASE_URL=postgresql://... "
            "(SQLite is for community/lab only). Set REQUIRE_POSTGRES_IN_PRODUCTION=false "
            "only for emergency break-glass — never for public SaaS."
        )
    if open_bind and not settings.auth_enabled and not getattr(settings, "allow_open_lan", False):
        raise RuntimeError(
            f"HOST={host} with AUTH_ENABLED=false is blocked. "
            "Enable AUTH_ENABLED, bind to 127.0.0.1, or set ALLOW_OPEN_LAN=true only on trusted private LANs."
        )


def session_cookie_secure() -> bool:
    if getattr(settings, "cookie_secure", False):
        return True
    if getattr(settings, "force_https_headers", False):
        return True
    return _is_production_mode()


def session_cookie_kwargs() -> dict[str, Any]:
    same = (getattr(settings, "cookie_samesite", "lax") or "lax").lower()
    if same not in {"lax", "strict", "none"}:
        same = "lax"
    secure = session_cookie_secure()
    if same == "none" and not secure:
        # Browsers reject SameSite=None without Secure
        same = "lax"
    return {
        "key": getattr(settings, "session_cookie_name", "securaiq_session") or "securaiq_session",
        "httponly": bool(getattr(settings, "cookie_httponly", True)),
        "secure": secure,
        "samesite": same,
        "max_age": _session_ttl_days() * 86400,
        "path": "/",
    }


def hash_password(password: str) -> str:
    """Prefer Argon2id when argon2-cffi is installed; else PBKDF2-HMAC-SHA256."""
    try:
        from argon2 import PasswordHasher

        # time_cost/memory tuned for interactive login (not offline KDF max).
        return PasswordHasher(time_cost=3, memory_cost=65536, parallelism=2).hash(password)
    except ImportError:
        salt = secrets.token_hex(16)
        dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("utf-8"), 180_000)
        return f"pbkdf2${salt}${dk.hex()}"


def verify_password(password: str, stored: str) -> bool:
    stored = stored or ""
    if stored.startswith("$argon2"):
        try:
            from argon2 import PasswordHasher
            from argon2.exceptions import InvalidHash, VerifyMismatchError

            try:
                return bool(PasswordHasher().verify(stored, password))
            except VerifyMismatchError:
                return False
            except InvalidHash:
                return False
        except ImportError:
            return False
    try:
        algo, salt, hexdigest = stored.split("$", 2)
        if algo != "pbkdf2":
            return False
        dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("utf-8"), 180_000)
        return hmac.compare_digest(dk.hex(), hexdigest)
    except Exception:
        return False


def needs_rehash(stored: str) -> bool:
    """#255 — upgrade PBKDF2 (or missing argon2) hashes to Argon2id on next login."""
    stored = stored or ""
    if not stored.startswith("$argon2"):
        return True
    try:
        from argon2 import PasswordHasher
        from argon2.exceptions import InvalidHash

        return bool(PasswordHasher().check_needs_rehash(stored))
    except ImportError:
        return False
    except Exception:
        return False


def maybe_rehash_password(user_id: str, password: str, stored: str) -> bool:
    """If verify succeeded and hash is legacy, rewrite to Argon2id. Returns True if updated.

    When argon2-cffi is unavailable, rotates PBKDF2 salt anyway so login still
    refreshes legacy material (returns True). Prefer Argon2id in production.
    """
    if not needs_rehash(stored):
        return False
    try:
        new_hash = hash_password(password)
        # Avoid no-op rewrite of identical pbkdf2 string
        if new_hash == stored:
            return False
        c = get_conn()
        c.execute("UPDATE users SET password_hash = ? WHERE id = ?", (new_hash, user_id))
        c.commit()
        audit(
            "password_rehash",
            user_id,
            {
                "from": "legacy",
                "to": "argon2id" if new_hash.startswith("$argon2") else "pbkdf2",
            },
        )
        return True
    except Exception:
        return False


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def ensure_bootstrap_admin() -> str | None:
    """Create default admin if no users exist. Returns plaintext password once if created."""
    c = get_conn()
    row = c.execute("SELECT COUNT(*) AS n FROM users").fetchone()
    if row and int(row["n"]) > 0:
        return None
    password = settings.bootstrap_admin_password or secrets.token_urlsafe(12)
    uid = new_id()
    c.execute(
        "INSERT INTO users (id, username, password_hash, role, created_at) VALUES (?, ?, ?, ?, ?)",
        (uid, settings.bootstrap_admin_username, hash_password(password), "admin", now()),
    )
    c.commit()
    audit("bootstrap_admin", uid, {"username": settings.bootstrap_admin_username})
    print(
        f"SecuraIQ auth: created admin `{settings.bootstrap_admin_username}` "
        f"(set BOOTSTRAP_ADMIN_PASSWORD to choose; password was auto-generated if unset)."
    )
    if not settings.bootstrap_admin_password:
        print(f"SecuraIQ auth: one-time admin password → {password}")
        return password
    return None


def register_user(
    username: str, password: str, role: str = "user", *, email: str | None = None
) -> AuthUser:
    from app.tenancy import ensure_tenant_schema

    ensure_tenant_schema()  # no-op here — users.email is already added by app.db._migrate_users
    username = (username or "").strip().lower()
    if len(username) < 3 or len(password) < 8:
        raise ValueError("Username ≥3 chars and password ≥8 chars required")
    # users.email is NOT NULL DEFAULT '' (see app.db._migrate_users) — use '' as the
    # "no email" sentinel, not NULL, or this insert violates that constraint.
    email = (email or "").strip().lower()
    c = get_conn()
    uid = new_id()
    try:
        c.execute(
            "INSERT INTO users (id, username, password_hash, role, created_at, email) VALUES (?, ?, ?, ?, ?, ?)",
            (uid, username, hash_password(password), role, now(), email),
        )
        c.commit()
    except Exception as exc:
        raise ValueError("Username already taken") from exc
    audit("register", uid, {"username": username, "email_set": bool(email)})
    return AuthUser(id=uid, username=username, role=role)


def login(
    username: str,
    password: str,
    *,
    totp: str | None = None,
    recovery_code: str | None = None,
    ip: str = "",
) -> tuple[AuthUser, str] | dict[str, Any]:
    """Return (user, token) or {mfa_required, mfa_token} when MFA step-up needed."""
    from app.login_attempts import assert_not_locked, record_login_attempt
    from app.mfa import create_mfa_pending, verify_mfa_factor

    uname = (username or "").strip().lower()
    assert_not_locked(uname)

    c = get_conn()
    row = c.execute(
        "SELECT * FROM users WHERE username = ?",
        (uname,),
    ).fetchone()
    if not row or not verify_password(password, row["password_hash"]):
        record_login_attempt(uname, ip=ip, success=False, mfa_stage=0)
        audit("login_failed", row["id"] if row else f"unknown:{uname}", {"ip": ip})
        raise ValueError("Invalid username or password")

    # #255 opportunistic Argon2id rehash after successful password verify
    maybe_rehash_password(row["id"], password, row["password_hash"])

    mfa_on = bool(row["mfa_enabled"])
    if mfa_on:
        if not totp and not recovery_code:
            pending = create_mfa_pending(row["id"])
            return {"mfa_required": True, "mfa_token": pending, "recovery_codes_accepted": True}
        try:
            verify_mfa_factor(row["id"], totp=totp, recovery_code=recovery_code)
        except ValueError as exc:
            record_login_attempt(uname, ip=ip, success=False, mfa_stage=1)
            raise ValueError(str(exc)) from exc

    token = secrets.token_urlsafe(32)
    expires = now() + _session_ttl_days() * 86400
    c.execute(
        "INSERT INTO sessions (token, user_id, expires_at, created_at) VALUES (?, ?, ?, ?)",
        (hash_token(token), row["id"], expires, now()),
    )
    c.commit()
    record_login_attempt(uname, ip=ip, success=True, mfa_stage=1 if mfa_on else 0)
    audit("login", row["id"], {"username": row["username"], "ip": ip})
    return AuthUser(id=row["id"], username=row["username"], role=row["role"]), token


def login_via_saml_nameid(
    nameid: str,
    *,
    ip: str = "",
) -> tuple[AuthUser, str] | dict[str, Any]:
    """Issue a session for a verified SAML NameID (username or email match).

    Does **not** auto-create users. MFA-enabled accounts still require the
    existing MFA step-up (same shape as password login).
    """
    from app.login_attempts import assert_not_locked, record_login_attempt
    from app.mfa import create_mfa_pending

    nid = (nameid or "").strip().lower()
    if len(nid) < 3:
        raise ValueError("SAML NameID too short")
    assert_not_locked(nid)

    c = get_conn()
    row = c.execute(
        "SELECT * FROM users WHERE lower(username) = ? OR lower(email) = ?",
        (nid, nid),
    ).fetchone()
    if not row:
        record_login_attempt(nid, ip=ip, success=False, mfa_stage=0)
        audit("saml_login_failed", f"unknown:{nid}", {"ip": ip, "reason": "no_user"})
        raise ValueError("No local user matches SAML NameID — provision the account first")

    uname = row["username"]
    mfa_on = bool(row["mfa_enabled"])
    if mfa_on:
        pending = create_mfa_pending(row["id"])
        audit("saml_mfa_required", row["id"], {"ip": ip})
        return {"mfa_required": True, "mfa_token": pending, "recovery_codes_accepted": True}

    token = secrets.token_urlsafe(32)
    expires = now() + _session_ttl_days() * 86400
    c.execute(
        "INSERT INTO sessions (token, user_id, expires_at, created_at) VALUES (?, ?, ?, ?)",
        (hash_token(token), row["id"], expires, now()),
    )
    c.commit()
    record_login_attempt(uname, ip=ip, success=True, mfa_stage=0)
    audit("saml_login", row["id"], {"username": uname, "ip": ip, "nameid": nid})
    return AuthUser(id=row["id"], username=row["username"], role=row["role"]), token


def complete_mfa_login(
    mfa_token: str,
    totp: str | None = None,
    *,
    recovery_code: str | None = None,
    ip: str = "",
) -> tuple[AuthUser, str]:
    from app.login_attempts import assert_not_locked, record_login_attempt
    from app.mfa import consume_mfa_pending, verify_mfa_factor

    user_id = consume_mfa_pending(mfa_token)
    if not user_id:
        raise ValueError("MFA session expired — log in again")
    row = get_conn().execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    if not row:
        raise ValueError("User not found")
    uname = row["username"]
    assert_not_locked(uname)
    try:
        kind = verify_mfa_factor(user_id, totp=totp, recovery_code=recovery_code)
    except ValueError as exc:
        record_login_attempt(uname, ip=ip, success=False, mfa_stage=1)
        raise ValueError(str(exc)) from exc
    token = secrets.token_urlsafe(32)
    expires = now() + _session_ttl_days() * 86400
    c = get_conn()
    c.execute(
        "INSERT INTO sessions (token, user_id, expires_at, created_at) VALUES (?, ?, ?, ?)",
        (hash_token(token), row["id"], expires, now()),
    )
    c.commit()
    record_login_attempt(uname, ip=ip, success=True, mfa_stage=1)
    audit("login", row["id"], {"username": row["username"], "mfa": True, "mfa_kind": kind, "ip": ip})
    return AuthUser(id=row["id"], username=row["username"], role=row["role"]), token


def request_password_reset(username: str) -> dict[str, Any]:
    """Create a one-time reset token. Always returns ok (no user enumeration).

    Security-sensitive: if the account has an email on file and SMTP is
    configured, the token is emailed and NEVER included in the API response —
    proving mailbox ownership is the whole point of a reset flow. Only when
    delivery isn't possible (no email on file, or SMTP unconfigured — the
    zero-config local/lab default) does it fall back to returning the token
    directly, and that fallback is called out explicitly in the response so
    an operator standing this up for real users notices and fixes it.
    """
    from app.tenancy import ensure_tenant_schema

    ensure_tenant_schema()
    username = (username or "").strip().lower()
    c = get_conn()
    row = c.execute("SELECT id, email FROM users WHERE username = ?", (username,)).fetchone()
    out: dict[str, Any] = {
        "ok": True,
        "message": "If that account exists, a reset link was sent.",
    }
    if not row:
        audit("password_reset_request", None, {"username": username, "found": False})
        return out
    raw = secrets.token_urlsafe(32)
    ttl_h = max(1, int(getattr(settings, "password_reset_ttl_hours", 2) or 2))
    expires = now() + ttl_h * 3600
    c.execute(
        "INSERT INTO password_reset_tokens (token_hash, user_id, expires_at, created_at, used_at) VALUES (?, ?, ?, ?, NULL)",
        (hash_token(raw), row["id"], expires, now()),
    )
    c.commit()

    email = (row["email"] or "").strip() if row["email"] else ""
    emailed = False
    if email:
        try:
            from app.notifications import _smtp_configured, send_email

            if _smtp_configured():
                base = (getattr(settings, "public_base_url", "") or "").rstrip("/")
                link = f"{base}/reset-password?token={raw}" if base else None
                body = (
                    f"A password reset was requested for your SecuraIQ account.\n\n"
                    f"{'Reset link: ' + link if link else 'Reset token: ' + raw}\n\n"
                    f"This expires in {ttl_h} hour(s). If you didn't request this, ignore this email."
                )
                emailed = send_email(email, "SecuraIQ password reset", body)
        except Exception:
            emailed = False

    audit(
        "password_reset_request",
        row["id"],
        {"username": username, "found": True, "emailed": emailed},
    )
    if emailed:
        out["expires_in_hours"] = ttl_h
        return out

    # Fallback path — no email on file, or SMTP isn't configured. Flag this
    # loudly rather than silently handing out a working credential-reset
    # token to anyone who can call this endpoint.
    out["message"] = (
        "No email on file or SMTP not configured — reset token returned directly "
        "(local/lab fallback). Set a user email and configure SMTP before exposing "
        "this to untrusted users."
    )
    out["reset_token"] = raw
    out["expires_in_hours"] = ttl_h
    return out


def reset_password_with_token(token: str, new_password: str) -> None:
    from app.tenancy import ensure_tenant_schema

    ensure_tenant_schema()
    if len(new_password or "") < 8:
        raise ValueError("Password must be at least 8 characters")
    th = hash_token((token or "").strip())
    c = get_conn()
    row = c.execute(
        "SELECT * FROM password_reset_tokens WHERE token_hash = ?",
        (th,),
    ).fetchone()
    if not row or row["used_at"] is not None or float(row["expires_at"]) < now():
        raise ValueError("Invalid or expired reset token")
    c.execute(
        "UPDATE users SET password_hash = ? WHERE id = ?",
        (hash_password(new_password), row["user_id"]),
    )
    c.execute(
        "UPDATE password_reset_tokens SET used_at = ? WHERE token_hash = ?",
        (now(), th),
    )
    # Invalidate all sessions for that user
    c.execute("DELETE FROM sessions WHERE user_id = ?", (row["user_id"],))
    c.commit()
    audit("password_reset_complete", row["user_id"], {})


def logout(token: str | None) -> None:
    if not token:
        return
    c = get_conn()
    c.execute("DELETE FROM sessions WHERE token = ?", (hash_token(token),))
    c.commit()


def create_api_key(user_id: str, name: str = "default") -> tuple[str, dict[str, Any]]:
    raw = "sq_" + secrets.token_urlsafe(28)
    kid = new_id()
    c = get_conn()
    c.execute(
        "INSERT INTO api_keys (id, user_id, name, key_prefix, key_hash, created_at) VALUES (?, ?, ?, ?, ?, ?)",
        (kid, user_id, name or "default", raw[:10], hash_token(raw), now()),
    )
    c.commit()
    audit("api_key_create", user_id, {"name": name, "prefix": raw[:10]})
    return raw, {"id": kid, "name": name, "key_prefix": raw[:10]}


def list_api_keys(user_id: str) -> list[dict[str, Any]]:
    rows = get_conn().execute(
        "SELECT id, name, key_prefix, created_at FROM api_keys WHERE user_id = ? ORDER BY created_at DESC",
        (user_id,),
    ).fetchall()
    return [dict(r) for r in rows]


def revoke_api_key(user_id: str, key_id: str) -> bool:
    cur = get_conn().execute(
        "DELETE FROM api_keys WHERE id = ? AND user_id = ?", (key_id, user_id)
    )
    get_conn().commit()
    if cur.rowcount:
        audit("api_key_revoke", user_id, {"id": key_id})
        return True
    return False


def resolve_user(
    authorization: str | None,
    api_key_header: str | None = None,
    session_cookie: str | None = None,
) -> AuthUser | None:
    token = None
    if authorization and authorization.lower().startswith("bearer "):
        token = authorization[7:].strip()
    if not token and api_key_header:
        token = api_key_header.strip()
    if not token and session_cookie:
        token = session_cookie.strip()
    if not token:
        return None

    c = get_conn()
    th = hash_token(token)

    # Session token
    sess = c.execute(
        "SELECT u.id, u.username, u.role, s.expires_at FROM sessions s "
        "JOIN users u ON u.id = s.user_id WHERE s.token = ?",
        (th,),
    ).fetchone()
    if sess:
        if float(sess["expires_at"]) < now():
            c.execute("DELETE FROM sessions WHERE token = ?", (th,))
            c.commit()
            return None
        return AuthUser(id=sess["id"], username=sess["username"], role=sess["role"])

    # API key / service account
    key = c.execute(
        "SELECT u.id, u.username, u.role, k.id AS key_id FROM api_keys k "
        "JOIN users u ON u.id = k.user_id WHERE k.key_hash = ?",
        (th,),
    ).fetchone()
    if key:
        from app.db import table_columns

        cols = table_columns(c, "api_keys")
        if "revoked_at" in cols:
            revoked = c.execute(
                "SELECT revoked_at FROM api_keys WHERE id = ?", (key["key_id"],)
            ).fetchone()
            if revoked and revoked["revoked_at"]:
                return None
        if "last_used_at" in cols:
            c.execute("UPDATE api_keys SET last_used_at = ? WHERE id = ?", (now(), key["key_id"]))
            c.commit()
        return AuthUser(id=key["id"], username=key["username"], role=key["role"])
    return None


def list_users_public() -> list[dict[str, Any]]:
    c = get_conn()
    rows = c.execute("SELECT id, username, role, created_at FROM users ORDER BY created_at").fetchall()
    return [dict(r) for r in rows]
