"""Compliance Operations — tasks, schedules, evidence gate, tick."""

from __future__ import annotations

import time

from tests._http_test_utils import configure_isolated_settings


def test_task_evidence_gate_and_complete(tmp_path, monkeypatch):
    configure_isolated_settings(monkeypatch, tmp_path)
    from app.auth import login, register_user
    from app.compliance_ops import complete_task, create_task, submit_evidence
    from app.tenancy import ensure_tenant_schema

    ensure_tenant_schema()
    register_user("co_user", "password123", role="admin")
    user, _ = login("co_user", "password123")
    due = time.time() + 3 * 86400
    task = create_task(
        user.id,
        {
            "title": "Quarterly access review",
            "department": "IT",
            "due_at": due,
            "evidence_required": True,
            "task_kind": "manual",
        },
    )
    assert task["status"] == "upcoming"
    try:
        complete_task(user.id, task["id"])
        assert False, "should block without evidence"
    except ValueError as exc:
        assert "evidence" in str(exc).lower()
    submit_evidence(user.id, task["id"], note="Review spreadsheet attached")
    done = complete_task(user.id, task["id"])
    assert done["status"] == "completed"


def test_seed_materialize_and_my_work(tmp_path, monkeypatch):
    configure_isolated_settings(monkeypatch, tmp_path)
    from app.auth import login, register_user
    from app.compliance_ops import my_work_queue, seed_default_schedules
    from app.compliance_ops.schedules import materialize_due_from_schedules
    from app.tenancy import ensure_tenant_schema

    ensure_tenant_schema()
    register_user("co_seed", "password123", role="admin")
    user, _ = login("co_seed", "password123")
    seeded = seed_default_schedules(user.id)
    assert seeded["seeded"] >= 5
    # Force next_due into horizon
    from app.db import get_conn, now

    get_conn().execute(
        "UPDATE compliance_schedules SET next_due_at = ? WHERE user_id = ?",
        (now() + 2 * 86400, user.id),
    )
    get_conn().commit()
    mat = materialize_due_from_schedules(user.id, horizon_days=14)
    assert mat["count"] >= 1
    wq = my_work_queue(user.id)
    assert wq["ok"] is True
    assert wq["counts"]["open"] >= 1


def test_tick_overdue_escalates(tmp_path, monkeypatch):
    configure_isolated_settings(monkeypatch, tmp_path)
    from app.auth import login, register_user
    from app.compliance_ops import create_task, get_task
    from app.compliance_ops.automation import run_compliance_ops_tick
    from app.tenancy import ensure_tenant_schema

    ensure_tenant_schema()
    register_user("co_esc", "password123", role="admin")
    user, _ = login("co_esc", "password123")
    past = time.time() - 3 * 86400
    task = create_task(
        user.id,
        {
            "title": "Overdue vendor review",
            "department": "Legal",
            "due_at": past,
            "evidence_required": False,
            "manager_id": user.id,
        },
    )
    # First tick: overdue notify
    run_compliance_ops_tick(user.id, materialize=False)
    # Pretend already overdue-notified and last escalate old → escalate
    from app.db import get_conn, now

    get_conn().execute(
        "UPDATE compliance_tasks SET overdue_notified = 1, last_escalated_at = ? WHERE id = ?",
        (now() - 20 * 3600, task["id"]),
    )
    get_conn().commit()
    out = run_compliance_ops_tick(user.id, materialize=False)
    assert out["ok"] is True
    refreshed = get_task(user.id, task["id"])
    assert int(refreshed.get("escalation_level") or 0) >= 1


def test_compliance_ops_api(tmp_path, monkeypatch):
    configure_isolated_settings(monkeypatch, tmp_path)
    from fastapi.testclient import TestClient

    from app.auth import login, register_user
    from app.main import app
    from app.tenancy import ensure_tenant_schema

    ensure_tenant_schema()
    register_user("co_api", "password123", role="admin")
    user, token = login("co_api", "password123")
    client = TestClient(app)
    headers = {"Authorization": f"Bearer {token}"}
    r = client.post("/api/compliance-ops/seed", headers=headers)
    assert r.status_code == 200
    assert r.json().get("ok") is True
    r2 = client.get("/api/compliance-ops/summary", headers=headers)
    assert r2.status_code == 200
    r3 = client.get("/api/compliance-ops/calendar", headers=headers)
    assert r3.status_code == 200
    assert r3.json().get("ok") is True
