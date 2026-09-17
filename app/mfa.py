"""TOTP MFA (RFC 6238) + hashed recovery codes — stdlib (+ optional Argon2 for passwords elsewhere)."""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import struct
import time
from typing import Any
from urllib.parse import quote

from app.config import settings
from app.db import audit, get_conn, new_id, now, table_columns

_RECOVERY_CODE_COUNT = 10
_MFA_FAIL_WINDOW_SEC = 900  # 15 minutes
_MFA_FAIL_MAX = 10


def _base32_secret(length: int = 20) -> str:
    raw = secrets.token_bytes(length)
    return base64.b32encode(raw).decode("ascii").strip("=").upper()


def _decode_secret(secret: str) -> bytes:
    s = (secret or "").strip().replace(" ", "").upper()
    pad = (-len(s)) % 8
    return base64.b32decode(s + ("=" * pad), casefold=True)


def totp_at(secret: bytes, *, counter: int, digits: int = 6) -> str:
    msg = struct.pack(">Q", counter)
    digest = hmac.new(secret, msg, hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    code = struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF
    return str(code % (10**digits)).zfill(digits)


def verify_totp(secret: str, code: str, *, window: int = 1) -> bool:
    if not secret or not code:
        return False
    code = code.strip().replace(" ", "")
    if not code.isdigit() or len(code) not in {6, 8}:
        return False
    try:
        key = _decode_secret(secret)
    except Exception:
        return False
    counter = int(time.time()) // 30
    for delta in range(-window, window + 1):
        if hmac.compare_digest(totp_at(key, counter=counter + delta, digits=len(code)), code):
            return True
    return False


def ensure_mfa_schema() -> None:
    c = get_conn()
    c.execute(
        """
        CREATE TABLE IF NOT EXISTS mfa_recovery_codes (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            code_hash TEXT NOT NULL,
            used_at REAL,
            created_at REAL NOT NULL
        )
        """
    )
    c.execute(
        """
        CREATE TABLE IF NOT EXISTS mfa_attempts (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            kind TEXT NOT NULL DEFAULT 'totp',
            success INTEGER NOT NULL DEFAULT 0,
            created_at REAL NOT NULL
        )
        """
    )
    c.execute(
        "CREATE INDEX IF NOT EXISTS idx_mfa_recovery_user ON mfa_recovery_codes(user_id, used_at)"
    )
    c.execute(
        "CREATE INDEX IF NOT EXISTS idx_mfa_attempts_user ON mfa_attempts(user_id, created_at)"
    )
    # Ensure core MFA pending table exists even if full db migrate hasn't run yet.
    c.execute(
        """
        CREATE TABLE IF NOT EXISTS mfa_pending (
            token TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            expires_at REAL NOT NULL,
            created_at REAL NOT NULL
        )
        """
    )
    cols = table_columns(c, "users")
    if cols and "mfa_secret" not in cols:
        c.execute("ALTER TABLE users ADD COLUMN mfa_secret TEXT NOT NULL DEFAULT ''")
    if cols and "mfa_enabled" not in cols:
        c.execute("ALTER TABLE users ADD COLUMN mfa_enabled INTEGER NOT NULL DEFAULT 0")
    c.commit()


def mfa_required_globally() -> bool:
    return bool(getattr(settings, "mfa_required", False))


def mfa_is_mandatory_for(*, role: str | None, user_id: str | None = None) -> bool:
    """Commercial gate: MFA_REQUIRED for all; MFA_REQUIRED_FOR_ADMIN for admins."""
    if not getattr(settings, "auth_enabled", True):
        return False
    if user_id == "local":
        return False
    if mfa_required_globally():
        return True
    if getattr(settings, "mfa_required_for_admin", False) and (role or "").lower() == "admin":
        return True
    return False


def mfa_status(user_id: str) -> dict[str, Any]:
    ensure_mfa_schema()
    row = get_conn().execute(
        "SELECT mfa_enabled, mfa_secret FROM users WHERE id = ?", (user_id,)
    ).fetchone()
    if not row:
        return {"enabled": False, "enrolled": False, "recovery_codes_remaining": 0}
    secret = row["mfa_secret"] or ""
    remaining = get_conn().execute(
        "SELECT COUNT(*) AS n FROM mfa_recovery_codes WHERE user_id = ? AND used_at IS NULL",
        (user_id,),
    ).fetchone()
    return {
        "enabled": bool(row["mfa_enabled"]),
        "enrolled": bool(secret),
        "recovery_codes_remaining": int((remaining["n"] if remaining else 0) or 0),
    }


def _hash_recovery_code(code: str) -> str:
    normalized = (code or "").strip().upper().replace(" ", "").replace("-", "")
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


def _format_recovery_code() -> str:
    # XXXX-XXXX-XXXX — easy to type; stored only as hash.
    raw = secrets.token_hex(6).upper()
    return f"{raw[0:4]}-{raw[4:8]}-{raw[8:12]}"


def generate_recovery_codes(user_id: str, *, count: int = _RECOVERY_CODE_COUNT) -> list[str]:
    """Replace unused recovery codes; returns plaintext codes ONCE."""
    ensure_mfa_schema()
    codes = [_format_recovery_code() for _ in range(max(1, min(count, 20)))]
    ts = now()
    c = get_conn()
    c.execute("DELETE FROM mfa_recovery_codes WHERE user_id = ? AND used_at IS NULL", (user_id,))
    for code in codes:
        c.execute(
            "INSERT INTO mfa_recovery_codes (id, user_id, code_hash, used_at, created_at) VALUES (?, ?, ?, NULL, ?)",
            (new_id(), user_id, _hash_recovery_code(code), ts),
        )
    c.commit()
    audit("mfa_recovery_codes_issued", user_id, {"count": len(codes)})
    return codes


def consume_recovery_code(user_id: str, code: str) -> bool:
    """Mark a matching unused recovery code as used. One-shot."""
    ensure_mfa_schema()
    code_hash = _hash_recovery_code(code)
    c = get_conn()
    row = c.execute(
        "SELECT id FROM mfa_recovery_codes WHERE user_id = ? AND code_hash = ? AND used_at IS NULL LIMIT 1",
        (user_id, code_hash),
    ).fetchone()
    if not row:
        return False
    c.execute(
        "UPDATE mfa_recovery_codes SET used_at = ? WHERE id = ?",
        (now(), row["id"]),
    )
    c.commit()
    audit("mfa_recovery_code_used", user_id, {})
    return True


def record_mfa_attempt(user_id: str, *, success: bool, kind: str = "totp") -> None:
    ensure_mfa_schema()
    c = get_conn()
    c.execute(
        "INSERT INTO mfa_attempts (id, user_id, kind, success, created_at) VALUES (?, ?, ?, ?, ?)",
        (new_id(), user_id, kind, 1 if success else 0, now()),
    )
    c.commit()
    # #228 — mirror MFA failures in Redis for multi-replica rate limits
    try:
        from app.redis_client import get_sync_redis, redis_enabled

        if not redis_enabled():
            return
        r = get_sync_redis(cached=True)
        if r is None:
            return
        key = f"securaiq:mfa_fail:{user_id}"
        if success:
            r.delete(key)
        else:
            n = int(r.incr(key))
            if n == 1:
                r.expire(key, int(_MFA_FAIL_WINDOW_SEC))
    except Exception:
        pass


def mfa_rate_limited(user_id: str) -> bool:
    """True when too many recent MFA failures for this user."""
    ensure_mfa_schema()
    redis_n: int | None = None
    try:
        from app.redis_client import get_sync_redis, redis_enabled

        if redis_enabled():
            r = get_sync_redis(cached=True)
            if r is not None:
                raw = r.get(f"securaiq:mfa_fail:{user_id}")
                redis_n = int(raw) if raw is not None else 0
    except Exception:
        redis_n = None
    since = now() - _MFA_FAIL_WINDOW_SEC
    row = get_conn().execute(
        "SELECT COUNT(*) AS n FROM mfa_attempts WHERE user_id = ? AND success = 0 AND created_at >= ?",
        (user_id, since),
    ).fetchone()
    db_n = int((row["n"] if row else 0) or 0)
    n = max(db_n, redis_n) if redis_n is not None else db_n
    return n >= _MFA_FAIL_MAX


def assert_mfa_not_rate_limited(user_id: str) -> None:
    if mfa_rate_limited(user_id):
        raise ValueError("Too many MFA attempts — try again in 15 minutes")


def verify_mfa_factor(user_id: str, *, totp: str | None = None, recovery_code: str | None = None) -> str:
    """Verify TOTP or recovery code. Returns kind used: totp|recovery. Raises ValueError."""
    ensure_mfa_schema()
    assert_mfa_not_rate_limited(user_id)
    row = get_conn().execute(
        "SELECT mfa_secret, mfa_enabled FROM users WHERE id = ?", (user_id,)
    ).fetchone()
    if not row or not row["mfa_enabled"]:
        raise ValueError("MFA is not enabled for this account")

    if recovery_code and (recovery_code or "").strip():
        if consume_recovery_code(user_id, recovery_code):
            record_mfa_attempt(user_id, success=True, kind="recovery")
            return "recovery"
        record_mfa_attempt(user_id, success=False, kind="recovery")
        audit("mfa_failed", user_id, {"kind": "recovery"})
        raise ValueError("Invalid recovery code")

    if totp and verify_totp(row["mfa_secret"] or "", totp):
        record_mfa_attempt(user_id, success=True, kind="totp")
        return "totp"

    record_mfa_attempt(user_id, success=False, kind="totp")
    audit("mfa_failed", user_id, {"kind": "totp"})
    raise ValueError("Invalid authenticator code")


def mfa_enroll_start(user_id: str, *, issuer: str = "SecuraIQ", username: str = "") -> dict[str, Any]:
    ensure_mfa_schema()
    secret = _base32_secret()
    c = get_conn()
    c.execute(
        "UPDATE users SET mfa_secret = ?, mfa_enabled = 0 WHERE id = ?",
        (secret, user_id),
    )
    c.commit()
    label = quote(f"{issuer}:{username or user_id}")
    uri = f"otpauth://totp/{label}?secret={secret}&issuer={quote(issuer)}&algorithm=SHA1&digits=6&period=30"
    audit("mfa_enroll_start", user_id, {})
    return {"secret": secret, "otpauth_uri": uri, "issuer": issuer}


def mfa_enroll_confirm(user_id: str, code: str) -> dict[str, Any]:
    ensure_mfa_schema()
    row = get_conn().execute("SELECT mfa_secret FROM users WHERE id = ?", (user_id,)).fetchone()
    if not row or not row["mfa_secret"]:
        raise ValueError("Start MFA enrollment first")
    if not verify_totp(row["mfa_secret"], code):
        raise ValueError("Invalid authenticator code")
    c = get_conn()
    c.execute("UPDATE users SET mfa_enabled = 1 WHERE id = ?", (user_id,))
    c.commit()
    recovery_codes = generate_recovery_codes(user_id)
    audit("mfa_enroll_confirm", user_id, {})
    return {
        "ok": True,
        "mfa_enabled": True,
        "recovery_codes": recovery_codes,
        "recovery_codes_note": (
            "Store these recovery codes offline. Each code works once. "
            "They are shown only now and cannot be retrieved later."
        ),
    }


def mfa_regenerate_recovery_codes(user_id: str, *, totp: str) -> dict[str, Any]:
    ensure_mfa_schema()
    verify_mfa_factor(user_id, totp=totp)
    codes = generate_recovery_codes(user_id)
    return {
        "ok": True,
        "recovery_codes": codes,
        "recovery_codes_note": (
            "Previous unused recovery codes were revoked. Store these offline — shown once."
        ),
    }


def mfa_disable(user_id: str, code: str, *, role: str | None = None) -> bool:
    ensure_mfa_schema()
    if mfa_is_mandatory_for(role=role, user_id=user_id):
        raise ValueError("MFA is mandatory for this account and cannot be disabled")
    row = get_conn().execute(
        "SELECT mfa_secret, mfa_enabled FROM users WHERE id = ?", (user_id,)
    ).fetchone()
    if not row or not row["mfa_enabled"]:
        return True
    if not verify_totp(row["mfa_secret"] or "", code):
        raise ValueError("Invalid authenticator code")
    c = get_conn()
    c.execute(
        "UPDATE users SET mfa_enabled = 0, mfa_secret = '' WHERE id = ?",
        (user_id,),
    )
    c.execute("DELETE FROM mfa_recovery_codes WHERE user_id = ?", (user_id,))
    c.commit()
    audit("mfa_disable", user_id, {})
    return True


def create_mfa_pending(user_id: str) -> str:
    ensure_mfa_schema()
    token = secrets.token_urlsafe(24)
    expires = now() + 300
    c = get_conn()
    # Portable upsert: delete then insert (SQLite OR REPLACE / PG ON CONFLICT diverge).
    c.execute("DELETE FROM mfa_pending WHERE token = ?", (token,))
    c.execute("DELETE FROM mfa_pending WHERE user_id = ?", (user_id,))
    c.execute(
        "INSERT INTO mfa_pending (token, user_id, expires_at, created_at) VALUES (?, ?, ?, ?)",
        (token, user_id, expires, now()),
    )
    c.commit()
    return token


def consume_mfa_pending(token: str) -> str | None:
    ensure_mfa_schema()
    th = (token or "").strip()
    if not th:
        return None
    c = get_conn()
    row = c.execute("SELECT user_id, expires_at FROM mfa_pending WHERE token = ?", (th,)).fetchone()
    if not row:
        return None
    c.execute("DELETE FROM mfa_pending WHERE token = ?", (th,))
    c.commit()
    if float(row["expires_at"]) < now():
        return None
    return row["user_id"]
