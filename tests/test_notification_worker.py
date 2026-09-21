"""Notification outbox worker — email/Slack/Teams off the request path."""

from __future__ import annotations

from tests._http_test_utils import configure_isolated_settings


def _uid(monkeypatch, tmp_path, name="notif_w"):
    configure_isolated_settings(monkeypatch, tmp_path)
    from app.auth import login, register_user
    from app.tenancy import ensure_tenant_schema

    ensure_tenant_schema()
    register_user(name, "password123", role="admin")
    u, _ = login(name, "password123")
    return u.id


def test_notify_queues_email_outbox(tmp_path, monkeypatch):
    uid = _uid(monkeypatch, tmp_path, "notif_q")
    from app.config import settings
    from app.notification_worker import outbox_stats, process_outbox
    from app.notifications import notify

    monkeypatch.setattr(settings, "notification_worker_enabled", True)
    monkeypatch.setattr(settings, "notifications_enabled", True)
    monkeypatch.setattr("app.notifications.send_email", lambda *a, **k: True)
    monkeypatch.setattr("app.notifications._user_email", lambda _u: "ops@example.com")

    rec = notify(uid, "system", "Patch window", "Apply tonight", email=True)
    assert rec.get("id")
    stats = outbox_stats(uid)
    assert int(stats["counts"].get("pending") or 0) >= 1

    out = process_outbox(limit=10)
    assert out["sent"] >= 1
    stats2 = outbox_stats(uid)
    assert int(stats2["counts"].get("sent") or 0) >= 1


def test_outbox_retries_then_dead(tmp_path, monkeypatch):
    uid = _uid(monkeypatch, tmp_path, "notif_dead")
    from app.config import settings
    from app.db import get_conn, now
    from app.notification_worker import enqueue_delivery, process_outbox

    monkeypatch.setattr(settings, "notification_worker_enabled", True)
    monkeypatch.setattr("app.notification_worker._send_slack", lambda *_a, **_k: False)
    monkeypatch.setattr(settings, "slack_webhook_url", "https://hooks.example/x")

    row = enqueue_delivery(
        uid,
        channel="slack",
        payload={"title": "Critical", "body": "find me"},
    )
    for _ in range(8):
        get_conn().execute(
            "UPDATE notification_outbox SET next_attempt_at = ? WHERE id = ?",
            (now() - 1, row["id"]),
        )
        get_conn().commit()
        process_outbox(limit=5)
    dead = get_conn().execute(
        "SELECT status, attempts FROM notification_outbox WHERE id = ?",
        (row["id"],),
    ).fetchone()
    assert dead["status"] == "dead"
    assert int(dead["attempts"]) >= 8
