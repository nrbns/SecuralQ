"""HTTP-layer tests for GET /api/gap/live-tests/{framework_id} (app/gap_api.py)
-- Live Control Testing, computed from real product data with no pasted
evidence text required.
"""

from __future__ import annotations

from tests._http_test_utils import configure_isolated_settings


def _client_and_token(tmp_path, monkeypatch, username="live_test_http_tester"):
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


def test_live_tests_requires_auth(tmp_path, monkeypatch):
    client, _token, _uid = _client_and_token(tmp_path, monkeypatch)
    res = client.get("/api/gap/live-tests/cis_controls")
    assert res.status_code == 401


def test_live_tests_unknown_framework_404(tmp_path, monkeypatch):
    client, token, _uid = _client_and_token(tmp_path, monkeypatch)
    res = client.get("/api/gap/live-tests/not-a-real-framework", headers=_auth(token))
    assert res.status_code == 404


def test_live_tests_returns_mapped_controls_only(tmp_path, monkeypatch):
    client, token, _uid = _client_and_token(tmp_path, monkeypatch)
    res = client.get("/api/gap/live-tests/cis_controls", headers=_auth(token))
    assert res.status_code == 200, res.text
    body = res.json()
    assert body["framework_id"] == "cis_controls"
    assert "CIS-1" in body["tested_control_ids"]
    assert "CIS-3" not in body["tested_control_ids"]
    assert set(body["results"].keys()) == set(body["tested_control_ids"])


def test_live_tests_reflect_real_data_over_http(tmp_path, monkeypatch):
    client, token, uid = _client_and_token(tmp_path, monkeypatch)

    res_before = client.get("/api/gap/live-tests/cis_controls", headers=_auth(token))
    assert res_before.json()["results"]["CIS-1"][0]["status"] == "fail"

    from app.enterprise import create_asset

    create_asset(uid, "HTTP-TEST-01", asset_type="web")

    res_after = client.get("/api/gap/live-tests/cis_controls", headers=_auth(token))
    assert res_after.json()["results"]["CIS-1"][0]["status"] == "partial"


def test_live_tests_scoped_to_owning_user(tmp_path, monkeypatch):
    client_a, token_a, uid_a = _client_and_token(tmp_path, monkeypatch, username="live_test_owner_a")
    from app.auth import login, register_user
    from app.enterprise import create_asset

    register_user("live_test_owner_b", "password123", role="admin")
    _u_b, token_b = login("live_test_owner_b", "password123")

    create_asset(uid_a, "OWNER-A-ASSET", asset_type="web")

    res_a = client_a.get("/api/gap/live-tests/cis_controls", headers=_auth(token_a))
    res_b = client_a.get("/api/gap/live-tests/cis_controls", headers=_auth(token_b))
    assert res_a.json()["results"]["CIS-1"][0]["detail"]["total_assets"] == 1
    assert res_b.json()["results"]["CIS-1"][0]["detail"]["total_assets"] == 0
