"""In-app + email notifications.

Was "not started" per docs/launch-readiness.md. This gives every other module
a single `notify(...)` call to raise a critical-vuln alert, remediation due
date, or incident update — in-app always, email opportunistically when SMTP
is configured and the user has an email on file.
"""

from __future__ import annotations

import smtplib
import ssl
from email.message import EmailMessage
from typing import Any

from app.config import settings
from app.db import audit, get_conn, new_id, now, row_to_dict

VALID_KINDS = {
    "info",
    "critical_vuln",
    "remediation_due",
    "incident",
    "gap_analysis",
    "mfa_required",
    "system",
}


def create_notification(
    user_id: str,
    kind: str,
    title: str,
    body: str = "",
    link: str = "",
    *,
    org_id: str | None = None,
) -> dict[str, Any]:
    """Create an inbox notification for a specific recipient.

    Notifications stay recipient-scoped (list/mark-read by user_id). org_id is
    stamped for audit/tenant context only — inboxes are not org-shared.
    """
    from app.tenancy import ensure_tenant_schema, primary_org_id

    ensure_tenant_schema()
    kind = kind if kind in VALID_KINDS else "info"
    oid = org_id or primary_org_id(user_id)
    nid = new_id()
    t = now()
    c = get_conn()
    c.execute(
        "INSERT INTO notifications (id, user_id, org_id, kind, title, body, link, read, emailed, created_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, 0, 0, ?)",
        (nid, user_id, oid, kind, title[:200], body[:2000], link[:500], t),
    )
    c.commit()
    return row_to_dict(
        c.execute("SELECT * FROM notifications WHERE id = ?", (nid,)).fetchone()
    )  # type: ignore[return-value]


def list_notifications(user_id: str, unread_only: bool = False, limit: int = 50) -> list[dict[str, Any]]:
    c = get_conn()
    q = "SELECT * FROM notifications WHERE user_id = ?"
    args: list[Any] = [user_id]
    if unread_only:
        q += " AND read = 0"
    q += " ORDER BY created_at DESC LIMIT ?"
    args.append(max(1, min(limit, 200)))
    return [dict(r) for r in c.execute(q, args).fetchall()]


def unread_count(user_id: str) -> int:
    row = get_conn().execute(
        "SELECT COUNT(*) AS n FROM notifications WHERE user_id = ? AND read = 0", (user_id,)
    ).fetchone()
    return int(row["n"]) if row else 0


def mark_read(user_id: str, notification_id: str) -> bool:
    cur = get_conn().execute(
        "UPDATE notifications SET read = 1 WHERE id = ? AND user_id = ?", (notification_id, user_id)
    )
    get_conn().commit()
    return bool(cur.rowcount)


def mark_all_read(user_id: str) -> int:
    cur = get_conn().execute("UPDATE notifications SET read = 1 WHERE user_id = ? AND read = 0", (user_id,))
    get_conn().commit()
    return cur.rowcount


def _user_email(user_id: str) -> str:
    row = get_conn().execute("SELECT email FROM users WHERE id = ?", (user_id,)).fetchone()
    return (row["email"] if row else "") or ""


def _smtp_configured() -> bool:
    return bool(settings.smtp_host and settings.smtp_from)


def send_email(to_addr: str, subject: str, body: str) -> bool:
    """Best-effort SMTP send. Returns False (never raises) on any failure so a
    notification failure never breaks the calling workflow."""
    if not (_smtp_configured() and to_addr):
        return False
    try:
        msg = EmailMessage()
        msg["Subject"] = subject
        msg["From"] = settings.smtp_from
        msg["To"] = to_addr
        msg.set_content(body)
        if settings.smtp_use_tls:
            context = ssl.create_default_context()
            with smtplib.SMTP(settings.smtp_host, settings.smtp_port, timeout=10) as server:
                server.starttls(context=context)
                if settings.smtp_username:
                    server.login(settings.smtp_username, settings.smtp_password)
                server.send_message(msg)
        else:
            with smtplib.SMTP(settings.smtp_host, settings.smtp_port, timeout=10) as server:
                if settings.smtp_username:
                    server.login(settings.smtp_username, settings.smtp_password)
                server.send_message(msg)
        return True
    except Exception:
        return False


def notify(
    user_id: str,
    kind: str,
    title: str,
    body: str = "",
    link: str = "",
    email: bool = False,
) -> dict[str, Any]:
    """Single entry point other modules should call:
        from app.notifications import notify
        notify(user_id, "critical_vuln", "New critical vuln imported", f"{title} on {asset}")
    """
    if not settings.notifications_enabled:
        return {}
    record = create_notification(user_id, kind, title, body, link)
    if email:
        to_addr = _user_email(user_id)
        if to_addr and send_email(to_addr, f"[SecuraIQ] {title}", body or title):
            get_conn().execute("UPDATE notifications SET emailed = 1 WHERE id = ?", (record["id"],))
            get_conn().commit()
            audit("notification_emailed", user_id, {"id": record["id"], "kind": kind})
    try:
        from app.realtime_bus import publish

        publish(
            type="notification",
            user_id=user_id,
            kind=kind,
            id=record.get("id"),
            title=title[:120],
        )
    except Exception:
        pass
    return record
