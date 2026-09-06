"""HTTP-layer tests for /api/canonical-controls (app/canonical_controls_api.py)."""

from __future__ import annotations

from tests._http_test_utils import configure_isolated_settings


def _client_and_token(tmp_path, monkeypatch, username="canon_http_tester"):
    configure_isolated_settings(monkeypatch, tmp_path)
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    from app.auth import login, register_user
    from app.canonical_controls_api import router as canon_router
    from app.tenancy import ensure_tenant_schema

    ensure_tenant_schema()
    register_user(username, "password123", role="admin")
    u, token = login(username, "password123")

    test_app = FastAPI()
    test_app.include_router(canon_router)
    client = TestClient(test_app)
    return client, token, u.id


def _auth(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


def test_list_requires_auth(tmp_path, monkeypatch):
    client, _token, _uid = _client_and_token(tmp_path, monkeypatch)
    res = client.get("/api/canonical-controls")
    assert res.status_code == 401


def test_list_canonical_controls(tmp_path, monkeypatch):
    client, token, _uid = _client_and_token(tmp_path, monkeypatch)
    res = client.get("/api/canonical-controls", headers=_auth(token))
    assert res.status_code == 200
    ids = {c["id"] for c in res.json()["canonical_controls"]}
    assert "mfa" in ids
    assert len(ids) >= 20


def test_get_one_canonical_control(tmp_path, monkeypatch):
    client, token, _uid = _client_and_token(tmp_path, monkeypatch)
    res = client.get("/api/canonical-controls/mfa", headers=_auth(token))
    assert res.status_code == 200
    assert res.json()["name"] == "Multi-Factor Authentication"

    missing = client.get("/api/canonical-controls/does-not-exist", headers=_auth(token))
    assert missing.status_code == 404


def test_for_control_reverse_lookup(tmp_path, monkeypatch):
    client, token, _uid = _client_and_token(tmp_path, monkeypatch)
    res = client.get(
        "/api/canonical-controls/for-control?framework_id=cmmc_l2&control_id=IA.L2-3.5.3",
        headers=_auth(token),
    )
    assert res.status_code == 200
    ids = {c["id"] for c in res.json()["canonical_controls"]}
    assert "mfa" in ids


def test_status_all_and_single(tmp_path, monkeypatch):
    from app.gap_analysis import run_gap_analysis

    client, token, uid = _client_and_token(tmp_path, monkeypatch)
    run_gap_analysis(framework_id="cmmc_l2", evidence="", user_id=uid, title="t")

    all_res = client.get("/api/canonical-controls/status", headers=_auth(token))
    assert all_res.status_code == 200
    assert len(all_res.json()["statuses"]) >= 20

    one_res = client.get("/api/canonical-controls/mfa/status", headers=_auth(token))
    assert one_res.status_code == 200
    body = one_res.json()
    assert body["frameworks"]["cmmc_l2"]["has_assessment"] is True

    missing_res = client.get("/api/canonical-controls/does-not-exist/status", headers=_auth(token))
    assert missing_res.status_code == 404
