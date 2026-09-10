"""Agent request authentication helpers — bearer + optional replay/HMAC.

The enrollment token is `agent_id.agent_key`. Only SHA-256(key) is compared
for identity. New enrollments also store an encrypted copy of the key so
the server can verify HMAC signatures without keeping plaintext in the row.

Replay: `X-SecuraIQ-Ts` + `X-SecuraIQ-Nonce` (and optional `X-SecuraIQ-Sig`).
When `AGENT_REQUIRE_REPLAY_PROTECTION` is true, missing/stale/reused nonces
are rejected. When false, signed headers are still checked if present so
the Windows/Linux agent can send them without breaking older clients.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
from typing import Any

from app.config import settings
from app.db import now


def parse_agent_bearer(value: str | None) -> tuple[str, str]:
    raw = (value or "").strip()
    if raw.lower().startswith("bearer "):
        raw = raw[7:].strip()
    if "." not in raw:
        return "", ""
    aid, _, key = raw.partition(".")
    return aid.strip(), key.strip()


def sign_payload(raw_key: str, ts: str, nonce: str, body: bytes) -> str:
    digest = hashlib.sha256(body or b"").hexdigest()
    msg = f"{ts}.{nonce}.{digest}".encode("utf-8")
    return hmac.new(raw_key.encode("utf-8"), msg, hashlib.sha256).hexdigest()


def _agent_mac_key(agent: dict[str, Any]) -> str | None:
    enc = (agent.get("key_enc") or "").strip()
    if not enc:
        return None
    try:
        from app.secrets_crypto import decrypt_value

        raw = decrypt_value(enc)
        return raw or None
    except Exception:
        return None


def _nonce_seen_compat(agent_id: str, nonce: str) -> bool:
    try:
        from app.agent_security import remember_nonce

        # remember_nonce returns True if FRESH
        return not remember_nonce(nonce, agent_id=agent_id)
    except Exception:
        return False


def verify_replay_and_signature(
    agent: dict[str, Any],
    *,
    ts_header: str | None,
    nonce: str | None,
    sig: str | None,
    body: bytes,
    require: bool | None = None,
) -> str | None:
    """Return an error string if the request should be rejected, else None."""
    enforce = settings.agent_require_replay_protection if require is None else require
    ts_raw = (ts_header or "").strip()
    nonce_s = (nonce or "").strip()
    sig_s = (sig or "").strip()

    if not ts_raw and not nonce_s and not sig_s:
        if enforce:
            return "Missing replay headers (X-SecuraIQ-Ts, X-SecuraIQ-Nonce)"
        return None

    if not ts_raw or not nonce_s:
        return "Incomplete replay headers"

    try:
        ts_val = float(ts_raw)
    except ValueError:
        return "Invalid timestamp"
    skew = abs(now() - ts_val)
    max_skew = max(30, int(settings.agent_replay_max_skew_sec or 300))
    if skew > max_skew:
        return "Timestamp outside allowed skew"

    aid = str(agent.get("id") or "")
    if not aid:
        return "Unknown agent"
    mac_key = _agent_mac_key(agent)
    if sig_s:
        if not mac_key:
            return "Agent missing HMAC material for request signature"
        expected = sign_payload(mac_key, ts_raw, nonce_s, body)
        if not secrets.compare_digest(expected, sig_s):
            return "Invalid request signature"
    if _nonce_seen_compat(aid, nonce_s):
        return "Replay nonce already used"
    return None
