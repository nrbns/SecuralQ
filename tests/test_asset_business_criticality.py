"""HTTP-layer tests for the business_criticality field on assets — the Risk
Engine hardening addition that distinguishes "how critical is this piece of
infrastructure" (criticality) from "how critical is the business function/
data it serves" (business_criticality). Optional, blank by default, exposed
through the real POST/PATCH /api/assets routes (app/enterprise_api.py).
"""

from __future__ import annotations

from tests._http_test_utils import configure_isolated_settings


def _reload_db(monkeypatch, data_dir):
    return configure_isolated_settings(monkeypatch, data_dir)


def _client_and_token(tmp_path, monkeypatch, username="biz_crit_tester"):
    _reload_db(monkeypatch, tmp_path)
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    from app.auth import login, register_user
    from app.enterprise_api import router as enterprise_router
    from app.tenancy import ensure_tenant_schema

    ensure_tenant_schema()
    register_user(username, "password123", role="admin")
    u, token = login(username, "password123")

    test_app = FastAPI()
    test_app.include_router(enterprise_router)
    client = TestClient(test_app)
    return client, token, u.id


def _auth(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


def test_asset_defaults_to_blank_business_criticality(tmp_path, monkeypatch):
    client, token, _uid = _client_and_token(tmp_path, monkeypatch)
    res = client.post("/api/assets", json={"name": "plain-host"}, headers=_auth(token))
    assert res.status_code == 200, res.text
    assert res.json()["business_criticality"] == ""


def test_asset_create_accepts_business_criticality(tmp_path, monkeypatch):
    client, token, _uid = _client_and_token(tmp_path, monkeypatch)
    res = client.post(
        "/api/assets",
        json={"name": "db-host", "criticality": "low", "business_criticality": "critical"},
        headers=_auth(token),
    )
    assert res.status_code == 200, res.text
    body = res.json()
    assert body["criticality"] == "low"
    assert body["business_criticality"] == "critical"


def test_asset_update_sets_business_criticality(tmp_path, monkeypatch):
    client, token, _uid = _client_and_token(tmp_path, monkeypatch)
    created = client.post("/api/assets", json={"name": "later-host"}, headers=_auth(token)).json()
    asset_id = created["id"]
    assert created["business_criticality"] == ""

    res = client.patch(
        f"/api/assets/{asset_id}",
        json={"business_criticality": "high"},
        headers=_auth(token),
    )
    assert res.status_code == 200, res.text
    assert res.json()["business_criticality"] == "high"

    # confirm it actually persisted, not just echoed back
    listing = client.get("/api/assets", headers=_auth(token)).json()
    assets = listing["assets"] if isinstance(listing, dict) and "assets" in listing else listing
    row = next(a for a in assets if a["id"] == asset_id)
    assert row["business_criticality"] == "high"
