"""P0 production-build: login lockout, enroll tokens, revoke disconnect."""

from __future__ import annotations

import pytest

from tests._http_test_utils import configure_isolated_settings


def _reload(monkeypatch, data_dir):
    return configure_isolated_settings(monkeypatch, data_dir)


def test_login_lockout_after_failures(tmp_path, monkeypatch):
    _reload(monkeypatch, tmp_path)
    from app.auth import login, register_user
    from app.config import settings
    from app.login_attempts import failed_count, is_locked

    monkeypatch.setattr(settings, "login_lockout_max_failures", 3)
    monkeypatch.setattr(settings, "login_lockout_window_sec", 900)
    register_user("lockme", "password123")

    for _ in range(3):
        with pytest.raises(ValueError, match="Invalid username or password"):
            login("lockme", "wrong-password", ip="1.2.3.4")

    assert failed_count("lockme") >= 3
    locked, detail = is_locked("lockme")
    assert locked
    assert detail["limit"] == 3

    with pytest.raises(ValueError, match="Too many failed"):
        login("lockme", "password123", ip="1.2.3.4")


def test_enroll_token_flow(tmp_path, monkeypatch):
    _reload(monkeypatch, tmp_path)
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    from app.auth import login, register_user
    from app.agents_api import router
    from app.tenancy import ensure_tenant_schema

    ensure_tenant_schema()
    register_user("enroll_admin", "password123", role="admin")
    _u, token = login("enroll_admin", "password123")

    app = FastAPI()
    app.include_router(router)
    client = TestClient(app)
    headers = {"Authorization": f"Bearer {token}"}

    res = client.post(
        "/api/agents/enroll-tokens",
        json={"ttl_sec": 600, "max_uses": 1, "name_hint": "lab-host"},
        headers=headers,
    )
    assert res.status_code == 200, res.text
    enr = res.json()["enrollment_token"]
    assert enr.startswith("enr_")

    res = client.post(
        "/api/agents/enroll-by-token",
        json={"token": enr, "hostname": "win-01", "platform": "windows"},
    )
    assert res.status_code == 200, res.text
    body = res.json()
    assert body["agent_id"]
    assert "." in body["agent_token"]

    # Single-use: second attempt fails
    res = client.post(
        "/api/agents/enroll-by-token",
        json={"token": enr, "hostname": "win-02", "platform": "windows"},
    )
    assert res.status_code == 400


def test_revoke_calls_force_disconnect(tmp_path, monkeypatch):
    _reload(monkeypatch, tmp_path)
    from app.agents import enroll_agent, revoke_agent
    from app.auth import register_user

    calls: list[str] = []

    def _fake_disconnect(agent_id, code=4001, reason="revoked"):
        calls.append(agent_id)

    monkeypatch.setattr("app.agent_gateway.force_disconnect_agent", _fake_disconnect)
    u = register_user("revoker", "password123", role="admin")
    enrolled = enroll_agent(u.id, name="to-revoke")
    assert revoke_agent(u.id, enrolled["agent_id"])
    assert calls == [enrolled["agent_id"]]


def test_entitlements_check_endpoint(tmp_path, monkeypatch):
    _reload(monkeypatch, tmp_path)
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    from app.auth import login, register_user
    from app.license_api import entitlements_router, router
    from app.license_service import issue_license
    from app.agent_security import generate_ed25519_keypair
    from app.config import settings
    from app.tenancy import ensure_tenant_schema

    kp = generate_ed25519_keypair()
    monkeypatch.setattr(settings, "license_ed25519_private_key", kp["private_b64"])
    monkeypatch.setattr(settings, "license_ed25519_public_key", kp["public_b64"])

    ensure_tenant_schema()
    register_user("feat_user", "password123", role="admin")
    _u, token = login("feat_user", "password123")
    issue_license(_u.id, plan="pro")

    app = FastAPI()
    app.include_router(router)
    app.include_router(entitlements_router)
    client = TestClient(app)
    res = client.get(
        "/api/entitlements/check?feature=ai",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert res.status_code == 200
    assert res.json()["allowed"] is True
    assert res.json()["feature"] == "ai"
