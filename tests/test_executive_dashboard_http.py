"""HTTP-layer test for GET /api/risk/executive-dashboard (app/risk_api.py)."""

from __future__ import annotations

from tests._http_test_utils import configure_isolated_settings


def _client_and_token(tmp_path, monkeypatch, username="exec_dash_http_tester"):
    configure_isolated_settings(monkeypatch, tmp_path)
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    from app.auth import login, register_user
    from app.risk_api import router as risk_router
    from app.tenancy import ensure_tenant_schema

    ensure_tenant_schema()
    register_user(username, "password123", role="admin")
    u, token = login(username, "password123")

    test_app = FastAPI()
    test_app.include_router(risk_router)
    client = TestClient(test_app)
    return client, token, u.id


def _auth(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


def test_executive_dashboard_requires_auth(tmp_path, monkeypatch):
    client, _token, _uid = _client_and_token(tmp_path, monkeypatch)
    res = client.get("/api/risk/executive-dashboard")
    assert res.status_code == 401


def test_executive_dashboard_returns_all_sections(tmp_path, monkeypatch):
    client, token, _uid = _client_and_token(tmp_path, monkeypatch)
    res = client.get("/api/risk/executive-dashboard", headers=_auth(token))
    assert res.status_code == 200, res.text
    body = res.json()
    for key in (
        "security_exposure", "critical_findings", "patch_compliance",
        "mean_remediation_time", "verified_remediation", "active_campaigns",
        "top_remaining_risks",
    ):
        assert key in body


def test_executive_dashboard_scoped_to_owning_user(tmp_path, monkeypatch):
    client_a, token_a, uid_a = _client_and_token(tmp_path, monkeypatch, username="exec_dash_owner_a")
    from app.auth import login, register_user
    from app.enterprise import create_asset, create_vulnerability

    register_user("exec_dash_owner_b", "password123", role="admin")
    _u_b, token_b = login("exec_dash_owner_b", "password123")

    a = create_asset(uid_a, "WEB-01", asset_type="web")
    create_vulnerability(
        uid_a,
        {"asset_id": a["id"], "asset_name": "WEB-01", "title": "Apache RCE", "cve": "CVE-2024-9999", "severity": "critical", "cvss": 9.8, "status": "open"},
    )

    res_a = client_a.get("/api/risk/executive-dashboard", headers=_auth(token_a))
    res_b = client_a.get("/api/risk/executive-dashboard", headers=_auth(token_b))
    assert res_a.json()["critical_findings"]["critical"] == 1
    assert res_b.json()["critical_findings"]["critical"] == 0
