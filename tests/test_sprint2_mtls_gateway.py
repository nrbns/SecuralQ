"""Sprint 2 finish: gateway mTLS parity + cert HTTP API + production fingerprint gate."""

from __future__ import annotations

from tests._http_test_utils import configure_isolated_settings


def test_production_ready_requires_fingerprint_match(tmp_path, monkeypatch):
    configure_isolated_settings(monkeypatch, tmp_path)
    from app.config import settings
    from app.production_profile import production_profile_status

    for flag in (
        "agent_mtls_enabled",
        "agent_mtls_proxy_verify",
        "agent_require_command_signature",
        "agent_require_replay_protection",
    ):
        monkeypatch.setattr(settings, flag, True, raising=False)
    monkeypatch.setattr(settings, "agent_mtls_require_fingerprint_match", False, raising=False)
    assert production_profile_status()["production_ready_agent_security"] is False

    monkeypatch.setattr(settings, "agent_mtls_require_fingerprint_match", True, raising=False)
    assert production_profile_status()["production_ready_agent_security"] is True


def test_gateway_wait_enforces_proxy_mtls(tmp_path, monkeypatch):
    configure_isolated_settings(monkeypatch, tmp_path)
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    from app.agents import enroll_agent
    from app.agent_gateway import router as gw_router
    from app.config import settings
    from app.tenancy import ensure_tenant_schema

    ensure_tenant_schema()
    monkeypatch.setattr(settings, "agent_gateway_enabled", True, raising=False)
    monkeypatch.setattr(settings, "agent_mtls_proxy_verify", True, raising=False)
    monkeypatch.setattr(settings, "agent_mtls_require_fingerprint_match", False, raising=False)

    out = enroll_agent("local", name="gw-mtls")
    token = f"{out['agent_id']}.{out['agent_key']}"
    app = FastAPI()
    app.include_router(gw_router)
    client = TestClient(app)

    denied = client.post(
        "/api/agents/gateway/wait",
        json={"timeout_sec": 1, "limit": 1},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert denied.status_code == 401
    assert "certificate" in str(denied.json().get("detail") or "").lower()

    ok = client.post(
        "/api/agents/gateway/wait",
        json={"timeout_sec": 1, "limit": 1},
        headers={
            "Authorization": f"Bearer {token}",
            "X-SSL-Client-Verify": "SUCCESS",
            "X-SSL-Client-Fingerprint": "aabbccddeeff00112233445566778899aabbccdd",
        },
    )
    assert ok.status_code == 200
    assert "commands" in ok.json()


def test_certificate_http_issue_rotate_revoke(tmp_path, monkeypatch):
    configure_isolated_settings(monkeypatch, tmp_path)
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    from app.agents import enroll_agent
    from app.agents_api import router
    from app.auth import login, register_user
    from app.config import settings
    from app.tenancy import ensure_tenant_schema

    ensure_tenant_schema()
    monkeypatch.setattr(settings, "agent_mtls_enabled", True, raising=False)

    register_user("cert_api_admin", "password123", role="admin")
    user, tok = login("cert_api_admin", "password123")
    uid = user["id"] if isinstance(user, dict) else user.id
    agent = enroll_agent(uid, name="cert-http")
    aid = agent["agent_id"]

    app = FastAPI()
    app.include_router(router)
    client = TestClient(app)
    headers = {"Authorization": f"Bearer {tok}"}

    issued = client.post(f"/api/agents/{aid}/certificate/issue", headers=headers)
    assert issued.status_code == 200, issued.text
    body = issued.json()
    fp1 = (body.get("mtls") or {}).get("fingerprint") or body.get("fingerprint")
    assert fp1

    summary = client.get(f"/api/agents/{aid}/certificate", headers=headers)
    assert summary.status_code == 200

    rotated = client.post(f"/api/agents/{aid}/certificate/rotate", headers=headers)
    assert rotated.status_code == 200, rotated.text

    revoked = client.post(f"/api/agents/{aid}/certificate/revoke", headers=headers)
    assert revoked.status_code == 200, revoked.text
