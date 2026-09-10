"""Agent command signing, event IDs, and replay protection.

Floor for Agent Platform v1 — not full mTLS/certificate lifecycle yet.

HMAC seals remain the default command delivery path. Opt-in Ed25519 (or both)
via ``AGENT_COMMAND_SIGNING_ALG`` / ``agent_command_signing_alg`` (REALTIME Task J).
Production direction: Ed25519 + mTLS; HMAC keeps labs working without keys.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import os
import secrets
import threading
import time
from typing import Any

from app.db import get_conn, new_id, now

_log = logging.getLogger(__name__)

_NONCE_LOCK = threading.Lock()
_NONCE_TTL_SEC = 900
_MEMORY_NONCES: dict[str, float] = {}


def ensure_security_schema() -> None:
    c = get_conn()
    c.execute(
        """
        CREATE TABLE IF NOT EXISTS securaiq_agent_nonces (
            nonce TEXT PRIMARY KEY,
            agent_id TEXT NOT NULL DEFAULT '',
            created_at REAL NOT NULL,
            expires_at REAL NOT NULL
        )
        """
    )
    c.execute(
        "CREATE INDEX IF NOT EXISTS idx_agent_nonces_exp ON securaiq_agent_nonces(expires_at)"
    )
    c.commit()


def _signing_secret() -> bytes:
    """Derive HMAC key from SECURAIQ_AGENT_SIGNING_KEY or AUTH secret material."""
    raw = (os.environ.get("SECURAIQ_AGENT_SIGNING_KEY") or "").strip()
    if not raw:
        try:
            from app.config import settings

            raw = str(getattr(settings, "agent_signing_key", "") or "")
        except Exception:
            raw = ""
    if not raw:
        raw = "securaiq-dev-agent-signing-key-change-me"
    return hashlib.sha256(raw.encode("utf-8")).digest()


def new_event_id() -> str:
    return new_id()


def new_nonce() -> str:
    return secrets.token_urlsafe(16)


def _command_seal_ttl_sec() -> int:
    """Seal expiry window — aligns with AGENT_COMMAND_TTL_SEC when configured."""
    try:
        from app.config import settings

        ttl = int(getattr(settings, "agent_command_ttl_sec", None) or 86400)
    except Exception:
        ttl = int((os.environ.get("AGENT_COMMAND_TTL_SEC") or "86400").strip() or "86400")
    return max(60, ttl)


def canonical_command_payload(
    *,
    command_id: str,
    agent_id: str,
    kind: str,
    payload: dict[str, Any],
    nonce: str,
    event_id: str,
    issued_at: float | int | None = None,
    expires_at: float | int | None = None,
) -> bytes:
    """Canonical bytes for HMAC/Ed25519 seals.

    ``issued_at`` / ``expires_at`` are included when provided so agents can
    reject expired seals without trusting DB-side TTL alone. Legacy seals
    omit these fields and remain verifiable.
    """
    body: dict[str, Any] = {
        "command_id": command_id,
        "agent_id": agent_id,
        "kind": kind,
        "payload": payload or {},
        "nonce": nonce,
        "event_id": event_id,
    }
    if issued_at is not None:
        body["issued_at"] = float(issued_at)
    if expires_at is not None:
        body["expires_at"] = float(expires_at)
    return json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")


def sign_command(
    *,
    command_id: str,
    agent_id: str,
    kind: str,
    payload: dict[str, Any],
    nonce: str,
    event_id: str,
    issued_at: float | int | None = None,
    expires_at: float | int | None = None,
) -> str:
    msg = canonical_command_payload(
        command_id=command_id,
        agent_id=agent_id,
        kind=kind,
        payload=payload,
        nonce=nonce,
        event_id=event_id,
        issued_at=issued_at,
        expires_at=expires_at,
    )
    return hmac.new(_signing_secret(), msg, hashlib.sha256).hexdigest()


def verify_command_signature(
    *,
    command_id: str,
    agent_id: str,
    kind: str,
    payload: dict[str, Any],
    nonce: str,
    event_id: str,
    signature: str,
    issued_at: float | int | None = None,
    expires_at: float | int | None = None,
) -> bool:
    expected = sign_command(
        command_id=command_id,
        agent_id=agent_id,
        kind=kind,
        payload=payload,
        nonce=nonce,
        event_id=event_id,
        issued_at=issued_at,
        expires_at=expires_at,
    )
    return hmac.compare_digest(expected, (signature or "").strip())


def remember_nonce(nonce: str, *, agent_id: str = "", ttl_sec: int = _NONCE_TTL_SEC) -> bool:
    """Return True if nonce is fresh; False if replayed."""
    n = (nonce or "").strip()
    if not n:
        return False
    ensure_security_schema()
    ts = now()
    exp = ts + max(60, ttl_sec)
    with _NONCE_LOCK:
        # prune memory
        dead = [k for k, v in _MEMORY_NONCES.items() if v < ts]
        for k in dead:
            _MEMORY_NONCES.pop(k, None)
        if n in _MEMORY_NONCES:
            return False
        _MEMORY_NONCES[n] = exp
    c = get_conn()
    try:
        c.execute("DELETE FROM securaiq_agent_nonces WHERE expires_at < ?", (ts,))
        row = c.execute("SELECT nonce FROM securaiq_agent_nonces WHERE nonce = ?", (n,)).fetchone()
        if row:
            c.commit()
            return False
        c.execute(
            "INSERT INTO securaiq_agent_nonces (nonce, agent_id, created_at, expires_at) VALUES (?, ?, ?, ?)",
            (n, agent_id or "", ts, exp),
        )
        c.commit()
        return True
    except Exception:
        try:
            c.rollback()
        except Exception:
            pass
        return False


def _require_command_signature() -> bool:
    """RT-17: production opt-in; lab default is False."""
    try:
        from app.config import settings

        if bool(getattr(settings, "agent_require_command_signature", False)):
            return True
    except Exception:
        pass
    raw = (os.environ.get("AGENT_REQUIRE_COMMAND_SIGNATURE") or "").strip().lower()
    return raw in ("1", "true", "yes", "on")


def seal_command_for_delivery(command_row: dict[str, Any], payload: dict[str, Any]) -> dict[str, Any]:
    """Attach event_id, nonce, and signature(s) for gateway/check-in delivery.

    Algorithm controlled by ``agent_command_signing_alg`` (hmac | ed25519 | both).
    HMAC remains the default. When alg requests Ed25519 but no private key is
    configured, falls back to HMAC and logs a warning — unless
    ``agent_require_command_signature`` is True, in which case a valid seal for
    the configured algorithm is mandatory (raises on failure) and the command
    is stamped with ``require_verify: true``.
    """
    cid = str(command_row.get("id") or "")
    aid = str(command_row.get("agent_id") or "")
    kind = str(command_row.get("kind") or "")
    event_id = str(command_row.get("event_id") or "") or new_event_id()
    nonce = str(command_row.get("nonce") or "") or new_nonce()
    body = payload or {}
    require = _require_command_signature()
    issued_at = float(now())
    expires_at = issued_at + float(_command_seal_ttl_sec())
    out: dict[str, Any] = {
        "id": cid,
        "agent_id": aid,
        "kind": kind,
        "payload": body,
        "event_id": event_id,
        "nonce": nonce,
        "issued_at": issued_at,
        "expires_at": expires_at,
        "seq": float(command_row.get("created_at") or 0),
    }
    seal_kwargs = dict(
        command_id=cid,
        agent_id=aid,
        kind=kind,
        payload=body,
        nonce=nonce,
        event_id=event_id,
        issued_at=issued_at,
        expires_at=expires_at,
    )

    alg = _command_signing_alg()
    used_hmac = False
    used_ed = False

    if alg in ("hmac", "both"):
        out["signature"] = sign_command(**seal_kwargs)
        used_hmac = True

    if alg in ("ed25519", "both"):
        try:
            out["signature_ed25519"] = ed25519_sign_command(**seal_kwargs)
            pub = _ed25519_public_material()
            if pub:
                out["signing_public_key"] = pub
            used_ed = True
        except Exception as exc:
            if require and alg == "ed25519":
                raise ValueError(
                    "RT-17: Ed25519 seal required but unavailable — set "
                    "SECURAIQ_AGENT_ED25519_PRIVATE_KEY / agent_ed25519_private_key"
                ) from exc
            if require and alg == "both":
                raise ValueError(
                    "RT-17: both HMAC+Ed25519 required but Ed25519 seal failed — "
                    "configure Ed25519 keys or set AGENT_COMMAND_SIGNING_ALG=hmac"
                ) from exc
            _log.warning(
                "Ed25519 seal unavailable (%s); falling back to HMAC — "
                "set SECURAIQ_AGENT_ED25519_PRIVATE_KEY or agent_ed25519_private_key "
                "when AGENT_COMMAND_SIGNING_ALG=ed25519|both",
                exc,
            )
            if not used_hmac:
                out["signature"] = sign_command(**seal_kwargs)
                used_hmac = True

    if used_hmac and used_ed:
        out["signature_alg"] = "both"
    elif used_ed:
        out["signature_alg"] = "ed25519"
    else:
        out["signature_alg"] = "hmac"
        if "signature" not in out:
            out["signature"] = sign_command(**seal_kwargs)

    if require:
        out["require_verify"] = True
        # Self-check: never hand out a seal that fails verification.
        if not verify_sealed_command(out):
            raise ValueError("RT-17: seal_command_for_delivery produced an unverifiable seal")

    return out


def _seal_time_ok(cmd: dict[str, Any], *, skew_sec: float = 30.0) -> bool:
    """Reject expired seals (and seals issued too far in the future)."""
    ts = float(now())
    raw_exp = cmd.get("expires_at")
    raw_iss = cmd.get("issued_at")
    try:
        if raw_exp is not None and ts > float(raw_exp) + skew_sec:
            return False
        if raw_iss is not None and float(raw_iss) > ts + max(30.0, skew_sec * 10):
            return False
    except (TypeError, ValueError):
        return False
    return True


def verify_sealed_command(cmd: dict[str, Any]) -> bool:
    """Verify a sealed command dict per its ``signature_alg`` (hmac | ed25519 | both)."""
    if not isinstance(cmd, dict):
        return False
    cid = str(cmd.get("id") or "")
    aid = str(cmd.get("agent_id") or "")
    kind = str(cmd.get("kind") or "")
    payload = cmd.get("payload") if isinstance(cmd.get("payload"), dict) else {}
    nonce = str(cmd.get("nonce") or "")
    event_id = str(cmd.get("event_id") or "")
    if not (cid and nonce and event_id):
        return False
    if not _seal_time_ok(cmd):
        return False

    issued_at = cmd.get("issued_at")
    expires_at = cmd.get("expires_at")
    try:
        issued_f = float(issued_at) if issued_at is not None else None
        expires_f = float(expires_at) if expires_at is not None else None
    except (TypeError, ValueError):
        return False

    alg = str(cmd.get("signature_alg") or "hmac").strip().lower()
    if alg not in ("hmac", "ed25519", "both"):
        alg = "hmac"

    if alg in ("hmac", "both"):
        sig = str(cmd.get("signature") or "")
        if not verify_command_signature(
            command_id=cid,
            agent_id=aid,
            kind=kind,
            payload=payload,
            nonce=nonce,
            event_id=event_id,
            signature=sig,
            issued_at=issued_f,
            expires_at=expires_f,
        ):
            return False

    if alg in ("ed25519", "both"):
        sig_ed = str(cmd.get("signature_ed25519") or "")
        if not sig_ed:
            return False
        msg = canonical_command_payload(
            command_id=cid,
            agent_id=aid,
            kind=kind,
            payload=payload,
            nonce=nonce,
            event_id=event_id,
            issued_at=issued_f,
            expires_at=expires_f,
        )
        pub = str(cmd.get("signing_public_key") or "") or None
        if not ed25519_verify(msg, sig_ed, public_key=pub):
            return False

    return True


# ---------------------------------------------------------------------------
# Ed25519 foundations (optional) — production should move from HMAC to
# Ed25519 + mTLS; HMAC remains the default seal until operators opt in.
# ---------------------------------------------------------------------------


def _command_signing_alg() -> str:
    raw = ""
    try:
        from app.config import settings

        raw = str(getattr(settings, "agent_command_signing_alg", "") or "").strip()
    except Exception:
        raw = ""
    if not raw:
        raw = (os.environ.get("AGENT_COMMAND_SIGNING_ALG") or "hmac").strip()
    alg = raw.lower()
    if alg not in ("hmac", "ed25519", "both"):
        return "hmac"
    return alg


def _ed25519_public_material() -> str:
    """Public key string for embedding in sealed commands (agent can verify without extra config)."""
    raw = (os.environ.get("SECURAIQ_AGENT_ED25519_PUBLIC_KEY") or "").strip()
    if not raw:
        try:
            from app.config import settings

            raw = str(getattr(settings, "agent_ed25519_public_key", "") or "").strip()
        except Exception:
            raw = ""
    return raw


def _b64url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _b64url_decode(text: str) -> bytes:
    t = (text or "").strip()
    pad = "=" * (-len(t) % 4)
    return base64.urlsafe_b64decode(t + pad)


def generate_ed25519_keypair() -> dict[str, str]:
    """Generate a new Ed25519 keypair. Returns PEM + raw base64url forms."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    private = Ed25519PrivateKey.generate()
    public = private.public_key()
    priv_pem = private.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("ascii")
    pub_pem = public.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("ascii")
    priv_raw = private.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub_raw = public.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return {
        "private_pem": priv_pem,
        "public_pem": pub_pem,
        "private_b64": _b64url_encode(priv_raw),
        "public_b64": _b64url_encode(pub_raw),
    }


def _load_ed25519_private(material: str | None = None):
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    raw = (material or "").strip()
    if not raw:
        raw = (os.environ.get("SECURAIQ_AGENT_ED25519_PRIVATE_KEY") or "").strip()
    if not raw:
        try:
            from app.config import settings

            raw = str(getattr(settings, "agent_ed25519_private_key", "") or "").strip()
        except Exception:
            raw = ""
    if not raw:
        raise ValueError("No Ed25519 private key configured")
    if "BEGIN" in raw:
        return serialization.load_pem_private_key(raw.encode("utf-8"), password=None)
    return Ed25519PrivateKey.from_private_bytes(_b64url_decode(raw))


def _load_ed25519_public(material: str | None = None):
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    raw = (material or "").strip()
    if not raw:
        raw = (os.environ.get("SECURAIQ_AGENT_ED25519_PUBLIC_KEY") or "").strip()
    if not raw:
        try:
            from app.config import settings

            raw = str(getattr(settings, "agent_ed25519_public_key", "") or "").strip()
        except Exception:
            raw = ""
    if not raw:
        raise ValueError("No Ed25519 public key configured")
    if "BEGIN" in raw:
        return serialization.load_pem_public_key(raw.encode("utf-8"))
    return Ed25519PublicKey.from_public_bytes(_b64url_decode(raw))


def ed25519_sign(message: bytes | str, *, private_key: str | None = None) -> str:
    """Sign message bytes; returns base64url signature. Uses configured key if unset."""
    if isinstance(message, str):
        message = message.encode("utf-8")
    key = _load_ed25519_private(private_key)
    return _b64url_encode(key.sign(message))


def ed25519_verify(
    message: bytes | str,
    signature: str,
    *,
    public_key: str | None = None,
) -> bool:
    """Verify base64url Ed25519 signature. Returns False on any failure."""
    from cryptography.exceptions import InvalidSignature

    if isinstance(message, str):
        message = message.encode("utf-8")
    try:
        key = _load_ed25519_public(public_key)
        key.verify(_b64url_decode(signature), message)
        return True
    except (InvalidSignature, ValueError, TypeError, Exception):
        return False


def ed25519_sign_command(
    *,
    command_id: str,
    agent_id: str,
    kind: str,
    payload: dict[str, Any],
    nonce: str,
    event_id: str,
    issued_at: float | int | None = None,
    expires_at: float | int | None = None,
    private_key: str | None = None,
) -> str:
    """Ed25519 seal over the same canonical payload as HMAC."""
    msg = canonical_command_payload(
        command_id=command_id,
        agent_id=agent_id,
        kind=kind,
        payload=payload,
        nonce=nonce,
        event_id=event_id,
        issued_at=issued_at,
        expires_at=expires_at,
    )
    return ed25519_sign(msg, private_key=private_key)
