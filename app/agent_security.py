"""Agent command signing, event IDs, and replay protection.

Floor for Agent Platform v1 — not full mTLS/certificate lifecycle yet.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import threading
import time
from typing import Any

from app.db import get_conn, new_id, now

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


def canonical_command_payload(
    *,
    command_id: str,
    agent_id: str,
    kind: str,
    payload: dict[str, Any],
    nonce: str,
    event_id: str,
) -> bytes:
    body = {
        "command_id": command_id,
        "agent_id": agent_id,
        "kind": kind,
        "payload": payload or {},
        "nonce": nonce,
        "event_id": event_id,
    }
    return json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")


def sign_command(
    *,
    command_id: str,
    agent_id: str,
    kind: str,
    payload: dict[str, Any],
    nonce: str,
    event_id: str,
) -> str:
    msg = canonical_command_payload(
        command_id=command_id,
        agent_id=agent_id,
        kind=kind,
        payload=payload,
        nonce=nonce,
        event_id=event_id,
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
) -> bool:
    expected = sign_command(
        command_id=command_id,
        agent_id=agent_id,
        kind=kind,
        payload=payload,
        nonce=nonce,
        event_id=event_id,
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


def seal_command_for_delivery(command_row: dict[str, Any], payload: dict[str, Any]) -> dict[str, Any]:
    """Attach event_id, nonce, signature for gateway/check-in delivery."""
    cid = str(command_row.get("id") or "")
    aid = str(command_row.get("agent_id") or "")
    kind = str(command_row.get("kind") or "")
    event_id = str(command_row.get("event_id") or "") or new_event_id()
    nonce = str(command_row.get("nonce") or "") or new_nonce()
    sig = sign_command(
        command_id=cid,
        agent_id=aid,
        kind=kind,
        payload=payload or {},
        nonce=nonce,
        event_id=event_id,
    )
    return {
        "id": cid,
        "kind": kind,
        "payload": payload or {},
        "event_id": event_id,
        "nonce": nonce,
        "signature": sig,
        "seq": float(command_row.get("created_at") or 0),
    }
