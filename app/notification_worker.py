"""Background notification delivery worker.

In-app notifications stay synchronous (inbox + SSE). Email / Slack / Teams
are queued into ``notification_outbox`` and drained by ``notification_delivery_tick``
so SMTP/webhook latency never blocks the calling request path.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from typing import Any

from app.config import settings
from app.db import audit, get_conn, new_id, now, row_to_dict

CHANNELS = ("email", "slack", "teams")


def ensure_outbox_schema() -> None:
    c = get_conn()
    c.executescript(
        """
        CREATE TABLE IF NOT EXISTS notification_outbox (
            id TEXT PRIMARY KEY,
            notification_id TEXT NOT NULL DEFAULT '',
            user_id TEXT NOT NULL,
            org_id TEXT,
            channel TEXT NOT NULL,
            payload_json TEXT NOT NULL DEFAULT '{}',
            status TEXT NOT NULL DEFAULT 'pending',
            attempts INTEGER NOT NULL DEFAULT 0,
            next_attempt_at REAL NOT NULL,
            last_error TEXT NOT NULL DEFAULT '',
            created_at REAL NOT NULL,
            sent_at REAL
        );
        CREATE INDEX IF NOT EXISTS idx_notif_outbox_pending
            ON notification_outbox(status, next_attempt_at);
        """
    )
    c.commit()


def enqueue_delivery(
    user_id: str,
    *,
    channel: str,
    notification_id: str = "",
    payload: dict[str, Any] | None = None,
    org_id: str | None = None,
) -> dict[str, Any]:
    ensure_outbox_schema()
    ch = (channel or "").strip().lower()
    if ch not in CHANNELS:
        raise ValueError(f"channel must be one of {CHANNELS}")
    from app.tenancy import primary_org_id

    rid = new_id()
    t = now()
    get_conn().execute(
        """
        INSERT INTO notification_outbox
        (id, notification_id, user_id, org_id, channel, payload_json, status,
         attempts, next_attempt_at, last_error, created_at, sent_at)
        VALUES (?, ?, ?, ?, ?, ?, 'pending', 0, ?, '', ?, NULL)
        """,
        (
            rid,
            notification_id or "",
            user_id,
            org_id or primary_org_id(user_id),
            ch,
            json.dumps(payload or {})[:8000],
            t,
            t,
        ),
    )
    get_conn().commit()
    return row_to_dict(
        get_conn().execute("SELECT * FROM notification_outbox WHERE id = ?", (rid,)).fetchone()
    )  # type: ignore[return-value]


def _send_slack(text: str) -> bool:
    url = (getattr(settings, "slack_webhook_url", None) or "").strip()
    if not url:
        return False
    return _post_json(url, {"text": text[:3000]})


def _send_teams(title: str, body: str) -> bool:
    url = (getattr(settings, "teams_webhook_url", None) or "").strip()
    if not url:
        return False
    card = {
        "@type": "MessageCard",
        "@context": "http://schema.org/extensions",
        "summary": title[:200],
        "themeColor": "0076D7",
        "title": title[:200],
        "text": body[:3000] or title[:200],
    }
    return _post_json(url, card)


def _post_json(url: str, body: dict[str, Any]) -> bool:
    try:
        data = json.dumps(body).encode("utf-8")
        req = urllib.request.Request(
            url,
            data=data,
            method="POST",
            headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            return 200 <= int(resp.status) < 300
    except (urllib.error.URLError, TimeoutError, OSError, ValueError):
        return False


def _deliver_one(row: dict[str, Any]) -> tuple[bool, str]:
    from app.notifications import _user_email, send_email

    try:
        payload = json.loads(row.get("payload_json") or "{}")
    except Exception:
        payload = {}
    title = str(payload.get("title") or "SecuraIQ")
    body = str(payload.get("body") or title)
    channel = row.get("channel")
    if channel == "email":
        to_addr = str(payload.get("to") or _user_email(row["user_id"]) or "")
        if not to_addr:
            return False, "no email on file"
        ok = send_email(to_addr, f"[SecuraIQ] {title}", body)
        if ok and row.get("notification_id"):
            get_conn().execute(
                "UPDATE notifications SET emailed = 1 WHERE id = ?",
                (row["notification_id"],),
            )
            get_conn().commit()
        return ok, "" if ok else "smtp send failed"
    if channel == "slack":
        ok = _send_slack(f"*{title}*\n{body}")
        return ok, "" if ok else "slack webhook failed or not configured"
    if channel == "teams":
        ok = _send_teams(title, body)
        return ok, "" if ok else "teams webhook failed or not configured"
    return False, f"unknown channel {channel}"


def process_outbox(*, limit: int = 40) -> dict[str, Any]:
    """Drain pending outbox rows. Safe to call from a job tick."""
    ensure_outbox_schema()
    if not getattr(settings, "notification_worker_enabled", True):
        return {"ok": True, "skipped": True, "note": "notification_worker_enabled=false"}
    t = now()
    rows = [
        row_to_dict(r)
        for r in get_conn()
        .execute(
            """
            SELECT * FROM notification_outbox
            WHERE status = 'pending' AND next_attempt_at <= ?
            ORDER BY created_at ASC
            LIMIT ?
            """,
            (t, max(1, min(limit, 200))),
        )
        .fetchall()
    ]
    sent = 0
    failed = 0
    for row in rows:
        ok, err = _deliver_one(row)
        attempts = int(row.get("attempts") or 0) + 1
        if ok:
            get_conn().execute(
                """
                UPDATE notification_outbox
                SET status = 'sent', attempts = ?, sent_at = ?, last_error = ''
                WHERE id = ?
                """,
                (attempts, now(), row["id"]),
            )
            get_conn().commit()
            sent += 1
            try:
                audit(
                    "notification_delivered",
                    row["user_id"],
                    {"id": row["id"], "channel": row["channel"]},
                )
            except Exception:
                pass
        else:
            if attempts >= 8:
                status = "dead"
                next_at = now()
            else:
                status = "pending"
                next_at = now() + min(3600, 15 * (2 ** (attempts - 1)))
            get_conn().execute(
                """
                UPDATE notification_outbox
                SET status = ?, attempts = ?, next_attempt_at = ?, last_error = ?
                WHERE id = ?
                """,
                (status, attempts, next_at, (err or "delivery failed")[:500], row["id"]),
            )
            get_conn().commit()
            failed += 1
    return {"ok": True, "processed": len(rows), "sent": sent, "failed": failed}


def outbox_stats(user_id: str = "", *, org_id: str | None = None) -> dict[str, Any]:
    ensure_outbox_schema()
    args: list[Any] = []
    if user_id:
        from app.tenancy import tenant_visibility_sql

        where, args = tenant_visibility_sql(user_id, org_id=org_id)
        q = f"SELECT status, COUNT(*) AS n FROM notification_outbox WHERE {where}"
    else:
        q = "SELECT status, COUNT(*) AS n FROM notification_outbox"
    q += " GROUP BY status"
    counts = {r["status"]: int(r["n"]) for r in get_conn().execute(q, args).fetchall()}
    return {"ok": True, "counts": counts}
