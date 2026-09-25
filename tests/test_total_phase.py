"""Prove world-class 1–5 + master-build 1–46 are lab-complete."""

from __future__ import annotations

from tests._http_test_utils import configure_isolated_settings


def test_total_phase_board_all_lab(tmp_path, monkeypatch):
    configure_isolated_settings(monkeypatch, tmp_path)
    from app.db import init_schema
    from app.tenancy import ensure_tenant_schema
    from app.total_phase_board import master_build_phases, total_phase_board

    init_schema()
    ensure_tenant_schema()
    board = total_phase_board()
    assert board["ok"] is True
    assert board["all_lab"] is True
    assert board["master_build_count"] == 46
    ids = [p["id"] for p in board["master_build"]]
    assert ids == list(range(1, 47))
    assert all(p["status"] == "lab" for p in board["master_build"])
    assert all(p["code_unblocked"] for p in board["master_build"])
    wc = board["world_class"]
    assert wc["all_lab"] is True
    assert {p["id"] for p in wc["phases"]} == {
        "phase1_trustworthy",
        "phase2_powerful",
        "phase3_operational",
        "phase4_enterprise",
        "phase5_differentiated",
    }
    rows = master_build_phases()
    assert rows[3]["name"] == "Realtime command system"
    assert rows[7]["name"] == "Patch management"
    assert rows[45]["name"] == "Chaos testing"


def test_campaign_rollback_queues_allowlisted_command(tmp_path, monkeypatch):
    configure_isolated_settings(monkeypatch, tmp_path)
    from app.agents import (
        SUPPORTED_COMMAND_KINDS,
        create_campaign,
        enroll_agent,
        request_campaign_rollback,
    )
    from app.auth import register_user
    from app.db import init_schema
    from app.tenancy import ensure_tenant_schema

    init_schema()
    ensure_tenant_schema()
    assert "rollback" in SUPPORTED_COMMAND_KINDS
    u = register_user("rollback_op", "password123")
    agent = enroll_agent(u.id, name="rollback-host")
    camp = create_campaign(
        u.id,
        name="lab-patch",
        manager="apt",
        package="curl",
        target_version="8.5.0",
        agent_ids=[agent["agent_id"]],
        requested_by=u.id,
    )
    out = request_campaign_rollback(u.id, camp["id"], requested_by=u.id)
    assert out["ok"] is True
    assert out["commands"]
    assert out["commands"][0]["agent_id"] == agent["agent_id"]
    assert out["commands"][0]["status"] == "pending_approval"


def test_total_phase_http(tmp_path, monkeypatch):
    configure_isolated_settings(monkeypatch, tmp_path, auth_enabled=False)
    from fastapi.testclient import TestClient

    from app.db import init_schema
    from app.main import app
    from app.tenancy import ensure_tenant_schema

    init_schema()
    ensure_tenant_schema()
    client = TestClient(app)
    r = client.get("/api/phases/total")
    assert r.status_code == 200
    body = r.json()
    assert body["all_lab"] is True
    assert body["master_build_count"] == 46
