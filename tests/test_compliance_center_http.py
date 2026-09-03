"""HTTP-layer tests for GET /api/compliance/overview and
GET /api/compliance/audit-center (app/gap_api.py)."""

from __future__ import annotations

from tests._http_test_utils import configure_isolated_settings


def _client_and_token(tmp_path, monkeypatch, username="compliance_http_tester"):
    configure_isolated_settings(monkeypatch, tmp_path)
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    from app.auth import login, register_user
    from app.gap_api import router as gap_router
    from app.tenancy import ensure_tenant_schema

    ensure_tenant_schema()
    register_user(username, "password123", role="admin")
    u, token = login(username, "password123")

    test_app = FastAPI()
    test_app.include_router(gap_router)
    client = TestClient(test_app)
    return client, token, u.id


def _auth(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


def test_compliance_overview_requires_auth(tmp_path, monkeypatch):
    client, _token, _uid = _client_and_token(tmp_path, monkeypatch)
    res = client.get("/api/compliance/overview")
    assert res.status_code == 401


def test_audit_center_requires_auth(tmp_path, monkeypatch):
    client, _token, _uid = _client_and_token(tmp_path, monkeypatch)
    res = client.get("/api/compliance/audit-center")
    assert res.status_code == 401


def test_compliance_overview_over_http(tmp_path, monkeypatch):
    client, token, uid = _client_and_token(tmp_path, monkeypatch)
    from app.gap_analysis import run_gap_analysis

    run_gap_analysis(framework_id="cis_controls", evidence="", user_id=uid, title="t")
    res = client.get("/api/compliance/overview", headers=_auth(token))
    assert res.status_code == 200, res.text
    body = res.json()
    assert body["frameworks_assessed"] == 1
    assert body["overall_compliance_percent"] is not None


def test_audit_center_over_http(tmp_path, monkeypatch):
    client, token, uid = _client_and_token(tmp_path, monkeypatch)
    from app.gap_analysis import run_gap_analysis

    run_gap_analysis(framework_id="cis_controls", evidence="", user_id=uid, title="t")
    res = client.get("/api/compliance/audit-center", headers=_auth(token))
    assert res.status_code == 200, res.text
    body = res.json()
    assert body["assessments_included"] == 1
    assert body["totals"]["controls_total"] > 0


def test_compliance_overview_scoped_to_owning_user(tmp_path, monkeypatch):
    from app.auth import login, register_user
    from app.gap_analysis import run_gap_analysis

    client_a, token_a, uid_a = _client_and_token(tmp_path, monkeypatch, username="compliance_owner_a")
    register_user("compliance_owner_b", "password123", role="admin")
    _u_b, token_b = login("compliance_owner_b", "password123")

    run_gap_analysis(framework_id="cis_controls", evidence="", user_id=uid_a, title="t")

    res_a = client_a.get("/api/compliance/overview", headers=_auth(token_a))
    res_b = client_a.get("/api/compliance/overview", headers=_auth(token_b))
    assert res_a.json()["frameworks_assessed"] == 1
    assert res_b.json()["frameworks_assessed"] == 0
