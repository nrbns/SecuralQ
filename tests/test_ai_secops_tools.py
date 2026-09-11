"""Phase 8 SecOps tools — allowlist, tenancy, propose-only, no shell."""

from __future__ import annotations

from tests._http_test_utils import configure_isolated_settings


def _setup(monkeypatch, tmp_path, username="secops_tester"):
    configure_isolated_settings(monkeypatch, tmp_path)
    from app.auth import login, register_user
    from app.tenancy import ensure_tenant_schema

    ensure_tenant_schema()
    register_user(username, "password123", role="admin")
    u, _token = login(username, "password123")
    return u.id


def test_unknown_tool_denied():
    from app.secops.tools import call_tool

    r = call_tool("os_shell", "u1", args={"cmd": "whoami"})
    assert r["ok"] is False
    assert r["error"] == "tool_not_allowed"


def test_propose_remediation_does_not_mutate(tmp_path, monkeypatch):
    from app.enterprise import list_remediations
    from app.secops.tools import call_tool

    uid = _setup(monkeypatch, tmp_path)
    before = list_remediations(uid)
    r = call_tool(
        "propose_remediation",
        uid,
        args={"title": "Enable firewall", "recommendation": "approve enable_firewall"},
    )
    assert r["ok"] is True
    assert r["data"]["mutated"] is False
    assert r["data"]["proposed"] is True
    assert list_remediations(uid) == before


def test_secops_investigation_runs_allowlisted_tools(tmp_path, monkeypatch):
    from app.agents import checkin, enroll_agent
    from app.enterprise import create_vulnerability, update_asset
    from app.secops import run_secops_investigation

    uid = _setup(monkeypatch, tmp_path, username="secops_inv")
    enrolled = enroll_agent(uid, name="secops-host")
    ci = checkin(
        enrolled["agent_id"],
        {
            "hostname": "secops-host",
            "os": "linux",
            "firewall_status": {"collected": True, "enabled": False, "backend": "ufw"},
            "file_integrity": [
                {"path": "/etc/passwd", "status": "modified", "hash": "aa"},
            ],
        },
    )
    asset_id = ci["asset_id"]
    update_asset(uid, asset_id, {"criticality": "high"})
    create_vulnerability(
        uid,
        {
            "asset_id": asset_id,
            "asset_name": "secops-host",
            "title": "OpenSSH outdated",
            "severity": "high",
            "cvss": 7.5,
            "status": "open",
        },
    )
    pack = run_secops_investigation(uid, asset_id=asset_id, limit=3)
    assert pack["mode"] == "secops_tools"
    assert pack["summary"]["tools_ok"] >= 1
    assert all(t["tool"] != "os_shell" for t in pack["tool_trace"])
    assert pack["assets"]
    assert pack["proposed_remediations"]
    assert pack["proposed_remediations"][0]["mutated"] is False


def test_verify_host_remediation_observed(tmp_path, monkeypatch):
    from app.agents import checkin, enroll_agent
    from app.secops.verification import verify_host_remediation

    uid = _setup(monkeypatch, tmp_path, username="secops_verify")
    enrolled = enroll_agent(uid, name="verify-host")
    checkin(
        enrolled["agent_id"],
        {
            "hostname": "verify-host",
            "os": "linux",
            "firewall_status": {"collected": True, "enabled": True, "backend": "ufw"},
        },
    )
    out = verify_host_remediation(
        uid, agent_id=enrolled["agent_id"], test_name="host_firewall"
    )
    assert out["ok"] is True
    assert out["verified"] is True
    assert out["status"] == "pass"


def test_http_investigate_secops_mode(tmp_path, monkeypatch):
    configure_isolated_settings(monkeypatch, tmp_path)
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    from app.auth import login, register_user
    from app.enterprise_api import router
    from app.tenancy import ensure_tenant_schema

    ensure_tenant_schema()
    register_user("secops_http", "password123", role="admin")
    _u, token = login("secops_http", "password123")
    app = FastAPI()
    app.include_router(router)
    client = TestClient(app)
    res = client.post(
        "/api/ai/investigate",
        headers={"Authorization": f"Bearer {token}"},
        json={"limit": 3, "mode": "secops_tools"},
    )
    assert res.status_code == 200, res.text
    body = res.json()
    assert body.get("mode") == "secops_tools"
    assert "allowed_tools" in body

    tools = client.get("/api/ai/secops/tools", headers={"Authorization": f"Bearer {token}"})
    assert tools.status_code == 200
    assert "get_asset" in tools.json()["tools"]
