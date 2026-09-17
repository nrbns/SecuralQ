"""Outbound webhooks with HMAC signing + retry DLQ (#235)."""

from __future__ import annotations

import hashlib
import hmac
import json
import secrets
from typing import Any

import httpx

from app.db import audit, get_conn, new_id, now, row_to_dict, table_columns


def ensure_webhook_schema() -> None:
    c = get_conn()
    c.executescript(
        """
        CREATE TABLE IF NOT EXISTS webhooks (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            name TEXT NOT NULL,
            url TEXT NOT NULL,
            events TEXT NOT NULL DEFAULT '["*"]',
            enabled INTEGER NOT NULL DEFAULT 1,
            created_at REAL NOT NULL
        );
        CREATE TABLE IF NOT EXISTS webhook_dlq (
            id TEXT PRIMARY KEY,
            webhook_id TEXT NOT NULL,
            user_id TEXT NOT NULL,
            event TEXT NOT NULL,
            payload TEXT NOT NULL,
            error TEXT NOT NULL DEFAULT '',
            attempts INTEGER NOT NULL DEFAULT 0,
            created_at REAL NOT NULL,
            last_attempt_at REAL NOT NULL DEFAULT 0
        );
        """
    )
    cols = table_columns(c, "webhooks")
    if cols and "secret" not in cols:
        c.execute("ALTER TABLE webhooks ADD COLUMN secret TEXT NOT NULL DEFAULT ''")
    c.commit()


def _new_secret() -> str:
    return secrets.token_urlsafe(24)


def create_webhook(
    user_id: str,
    *,
    name: str,
    url: str,
    events: list[str] | None = None,
    secret: str | None = None,
) -> dict[str, Any]:
    ensure_webhook_schema()
    wid = new_id()
    sec = (secret or _new_secret()).strip()
    get_conn().execute(
        """
        INSERT INTO webhooks (id, user_id, name, url, events, enabled, created_at, secret)
        VALUES (?, ?, ?, ?, ?, 1, ?, ?)
        """,
        (wid, user_id, name.strip()[:120], url.strip()[:500], json.dumps(events or ["*"]), now(), sec),
    )
    get_conn().commit()
    audit("webhook_create", user_id, {"id": wid, "name": name})
    out = get_webhook(user_id, wid) or {}
    out["secret"] = sec  # shown once on create
    return out


def get_webhook(user_id: str, webhook_id: str) -> dict[str, Any] | None:
    ensure_webhook_schema()
    row = get_conn().execute(
        "SELECT * FROM webhooks WHERE id = ? AND user_id = ?", (webhook_id, user_id)
    ).fetchone()
    d = row_to_dict(row)
    if d and "secret" in d:
        d["secret_set"] = bool(d.get("secret"))
        d.pop("secret", None)  # never return secret on get/list
    return d


def list_webhooks(user_id: str) -> list[dict[str, Any]]:
    ensure_webhook_schema()
    rows = get_conn().execute(
        "SELECT * FROM webhooks WHERE user_id = ? ORDER BY created_at DESC", (user_id,)
    ).fetchall()
    out = []
    for r in rows:
        d = row_to_dict(r)
        if d:
            try:
                d["events"] = json.loads(d.get("events") or "[]")
            except json.JSONDecodeError:
                d["events"] = ["*"]
            d["secret_set"] = bool(d.pop("secret", None))
            out.append(d)
    return out


def delete_webhook(user_id: str, webhook_id: str) -> bool:
    ensure_webhook_schema()
    cur = get_conn().execute(
        "DELETE FROM webhooks WHERE id = ? AND user_id = ?", (webhook_id, user_id)
    )
    get_conn().commit()
    return bool(cur.rowcount)


def _sign(secret: str, body: bytes, ts: str) -> str:
    msg = f"{ts}.".encode("utf-8") + body
    return hmac.new(secret.encode("utf-8"), msg, hashlib.sha256).hexdigest()


def _enqueue_dlq(
    webhook_id: str,
    user_id: str,
    event: str,
    payload: dict[str, Any],
    error: str,
    attempts: int = 1,
) -> None:
    ensure_webhook_schema()
    get_conn().execute(
        """
        INSERT INTO webhook_dlq (id, webhook_id, user_id, event, payload, error, attempts, created_at, last_attempt_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            new_id(),
            webhook_id,
            user_id,
            event,
            json.dumps(payload)[:8000],
            error[:500],
            attempts,
            now(),
            now(),
        ),
    )
    get_conn().commit()


def list_dlq(user_id: str, *, limit: int = 50) -> list[dict[str, Any]]:
    ensure_webhook_schema()
    rows = get_conn().execute(
        "SELECT * FROM webhook_dlq WHERE user_id = ? ORDER BY created_at DESC LIMIT ?",
        (user_id, max(1, limit)),
    ).fetchall()
    return [row_to_dict(r) for r in rows if r]


async def dispatch_webhooks(user_id: str, event: str, payload: dict[str, Any]) -> dict[str, Any]:
    ensure_webhook_schema()
    # Need secrets — query raw rows
    rows = get_conn().execute(
        "SELECT * FROM webhooks WHERE user_id = ? AND enabled = 1", (user_id,)
    ).fetchall()
    sent = 0
    errors: list[str] = []
    body_obj = {"event": event, "payload": payload, "source": "securaiq"}
    body_bytes = json.dumps(body_obj, separators=(",", ":"), default=str).encode("utf-8")
    ts = str(int(now()))
    async with httpx.AsyncClient(timeout=8.0) as client:
        for r in rows:
            h = dict(r)
            try:
                evs = json.loads(h.get("events") or "[]")
            except json.JSONDecodeError:
                evs = ["*"]
            if "*" not in evs and event not in evs:
                continue
            headers = {
                "Content-Type": "application/json",
                "X-SecuraIQ-Event": event,
                "X-SecuraIQ-Timestamp": ts,
            }
            secret = (h.get("secret") or "").strip()
            if secret:
                headers["X-SecuraIQ-Signature"] = f"sha256={_sign(secret, body_bytes, ts)}"
            try:
                resp = await client.post(h["url"], content=body_bytes, headers=headers)
                if resp.status_code >= 400:
                    err = f"{h.get('name')}: HTTP {resp.status_code}"
                    errors.append(err)
                    _enqueue_dlq(h["id"], user_id, event, payload, err)
                else:
                    sent += 1
            except Exception as exc:  # noqa: BLE001
                err = f"{h.get('name')}: {exc}"
                errors.append(err)
                _enqueue_dlq(h["id"], user_id, event, payload, err)
    audit("webhook_dispatch", user_id, {"event": event, "sent": sent, "errors": len(errors)})
    return {"sent": sent, "errors": errors[:10], "signed": True}


async def retry_dlq_entry(user_id: str, dlq_id: str) -> dict[str, Any]:
    ensure_webhook_schema()
    row = get_conn().execute(
        "SELECT * FROM webhook_dlq WHERE id = ? AND user_id = ?", (dlq_id, user_id)
    ).fetchone()
    if not row:
        raise ValueError("DLQ entry not found")
    d = dict(row)
    try:
        payload = json.loads(d.get("payload") or "{}")
    except json.JSONDecodeError:
        payload = {}
    result = await dispatch_webhooks(user_id, d["event"], payload if isinstance(payload, dict) else {"raw": payload})
    get_conn().execute("DELETE FROM webhook_dlq WHERE id = ?", (dlq_id,))
    get_conn().commit()
    return {"ok": True, "retried": dlq_id, "dispatch": result}


def verify_signature(secret: str, body: bytes, timestamp: str, signature_header: str) -> bool:
    """Receiver-side helper for integrators / tests."""
    want = signature_header.strip()
    if want.startswith("sha256="):
        want = want[7:]
    got = _sign(secret, body, timestamp)
    return hmac.compare_digest(got, want)
