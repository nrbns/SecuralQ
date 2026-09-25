"""Launch demonstration: one real firewall closed loop."""

from __future__ import annotations

from tests._http_test_utils import configure_isolated_settings


def test_launch_loop_firewall_story(tmp_path, monkeypatch):
    configure_isolated_settings(monkeypatch, tmp_path)
    from app.auth import register_user
    from app.db import init_schema
    from app.launch_loop import run_launch_loop
    from app.tenancy import ensure_tenant_schema

    init_schema()
    ensure_tenant_schema()
    u = register_user("launch_loop", "password123")
    out = run_launch_loop(u.id)
    assert out["ok"] is True
    assert out["missing"] == []
    assert out["fail_via_checkin"] is True
    assert out["decision_drawer"]["verify"]["status"] == "verified"
    assert out["decision_drawer"]["verify"]["never_fixed_from_execute_alone"] is True
    names = [s["name"] for s in out["steps"]]
    assert "1_firewall_off_host_control_fail" in names
    assert "11_command_verification_verified" in names
    assert "12_realtime_timeline_chain" in names
    assert out["audit"]["ok"] is True


def test_launch_loop_http(tmp_path, monkeypatch):
    configure_isolated_settings(monkeypatch, tmp_path, auth_enabled=False)
    from fastapi.testclient import TestClient

    from app.db import init_schema
    from app.main import app
    from app.tenancy import ensure_tenant_schema

    init_schema()
    ensure_tenant_schema()
    client = TestClient(app)
    r = client.post("/api/launch/loop")
    assert r.status_code == 200
    body = r.json()
    assert body["ok"] is True
    assert body["product"].startswith("Continuous Security")
