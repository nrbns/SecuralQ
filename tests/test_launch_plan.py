"""Unified launch plan — every P0 lab-unblocked, ops/frozen honest."""

from __future__ import annotations

from tests._http_test_utils import configure_isolated_settings


def test_launch_plan_board_no_open(tmp_path, monkeypatch):
    configure_isolated_settings(monkeypatch, tmp_path)
    from app.db import init_schema
    from app.launch_plan import launch_p0_rows, launch_plan_board
    from app.tenancy import ensure_tenant_schema

    init_schema()
    ensure_tenant_schema()
    rows = launch_p0_rows()
    assert len(rows) == 50
    assert {r["id"] for r in rows} == {f"P0-{i:02d}" for i in range(1, 51)}
    assert not any(r["status"] == "open" for r in rows)
    board = launch_plan_board()
    assert board["open_count"] == 0
    assert board["all_lab_unblocked"] is True
    assert board["ok"] is True
    assert board["lab_count"] >= 40
    assert board["ops_count"] >= 1
    assert board["frozen_count"] == 2


def test_launch_helpers_and_http(tmp_path, monkeypatch):
    configure_isolated_settings(monkeypatch, tmp_path, auth_enabled=False)
    from fastapi.testclient import TestClient

    from app.agent_parity import agent_parity_status, inspect_checkin
    from app.db import init_schema
    from app.evidence_spine.export_package import build_export_package
    from app.incident_timeline import incident_timeline
    from app.main import app
    from app.ops import create_incident
    from app.restart_recovery import restart_recovery_status
    from app.tenancy import ensure_tenant_schema

    init_schema()
    ensure_tenant_schema()
    parity = agent_parity_status()
    assert parity["ok"] is True
    inspected = inspect_checkin({"firewall_status": {"collected": False, "reason": "unsupported"}})
    assert inspected["fields"]["firewall_status"]["collected"] is False
    rec = restart_recovery_status()
    assert rec["ok"] is True
    assert rec["jobs"]["requeue_on_boot"] is True
    pkg = build_export_package("local")
    assert pkg["ok"] is True
    assert pkg["package_hash"]
    inc = create_incident("local", title="Lab timeline", severity="high")
    tl = incident_timeline("local", inc["id"])
    assert tl and tl["ok"] is True
    assert tl["events"]
    client = TestClient(app)
    plan = client.get("/api/launch/plan")
    assert plan.status_code == 200
    assert plan.json()["open_count"] == 0
    assert client.get("/api/launch/agent-parity").status_code == 200
    assert client.get("/api/ops/restart-recovery").status_code == 200
    assert client.get("/api/ops/measured").status_code == 200
    assert client.get("/api/evidence-spine/export-package").status_code == 200
    assert client.get(f"/api/incidents/{inc['id']}/timeline").status_code == 200
    assert client.get("/api/services/graph").status_code == 200
    assert client.get("/api/onboarding/progress").status_code == 200
