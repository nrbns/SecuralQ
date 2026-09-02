"""HTTP-layer tests for GET /api/risk/priority (app/risk_api.py) — the
"what to fix first" ranking built on app.services.risk_priority.

Pattern follows tests/test_delete_routes_http.py: a real FastAPI TestClient
wrapping just the router(s) under test, register_user()/login() for a real
bearer token, threading through the real user.id (not the username) since
create_asset()/create_vulnerability() key rows by user.id.
"""

from __future__ import annotations

from tests._http_test_utils import configure_isolated_settings


def _reload_db(monkeypatch, data_dir):
    return configure_isolated_settings(monkeypatch, data_dir)


def _client_and_token(tmp_path, monkeypatch, username="risk_tester"):
    """Returns (client, bearer_token, real_user_id)."""
    _reload_db(monkeypatch, tmp_path)
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


def test_priority_list_requires_auth(tmp_path, monkeypatch):
    client, _token, _uid = _client_and_token(tmp_path, monkeypatch)
    res = client.get("/api/risk/priority")
    assert res.status_code == 401


def test_priority_list_empty_when_no_open_findings(tmp_path, monkeypatch):
    client, token, _uid = _client_and_token(tmp_path, monkeypatch)
    res = client.get("/api/risk/priority", headers=_auth(token))
    assert res.status_code == 200, res.text
    body = res.json()
    assert body["total_open"] == 0
    assert body["items"] == []


def test_priority_list_ranks_critical_asset_above_low_criticality(tmp_path, monkeypatch):
    client, token, uid = _client_and_token(tmp_path, monkeypatch)
    from app.enterprise import create_asset, create_vulnerability

    crit_asset = create_asset(uid, "prod-db", asset_type="server", criticality="critical")
    low_asset = create_asset(uid, "test-vm", asset_type="server", criticality="low")

    v_high = create_vulnerability(
        uid,
        {
            "asset_id": crit_asset["id"],
            "asset_name": "prod-db",
            "title": "Outdated OpenSSL",
            "severity": "high",
            "cvss": 7.5,
            "status": "open",
        },
    )
    v_low = create_vulnerability(
        uid,
        {
            "asset_id": low_asset["id"],
            "asset_name": "test-vm",
            "title": "Outdated OpenSSL",
            "severity": "high",
            "cvss": 7.5,
            "status": "open",
        },
    )

    res = client.get("/api/risk/priority", headers=_auth(token))
    assert res.status_code == 200, res.text
    body = res.json()
    assert body["total_open"] == 2
    items = body["items"]
    assert len(items) == 2
    ids_in_order = [i["vuln_id"] for i in items]
    assert ids_in_order.index(v_high["id"]) < ids_in_order.index(v_low["id"])
    # every item carries the same explainable shape compute_risk_score produces
    for item in items:
        assert "score" in item and "band" in item and "factors" in item
        assert isinstance(item["reasons"], list) and item["reasons"]


def test_priority_list_excludes_resolved_findings(tmp_path, monkeypatch):
    client, token, uid = _client_and_token(tmp_path, monkeypatch)
    from app.enterprise import create_asset, create_vulnerability

    asset = create_asset(uid, "host-1")
    create_vulnerability(
        uid,
        {"asset_id": asset["id"], "asset_name": "host-1", "title": "Fixed already", "severity": "high", "status": "resolved"},
    )
    open_v = create_vulnerability(
        uid,
        {"asset_id": asset["id"], "asset_name": "host-1", "title": "Still open", "severity": "medium", "status": "open"},
    )

    res = client.get("/api/risk/priority", headers=_auth(token))
    body = res.json()
    assert body["total_open"] == 1
    assert body["items"][0]["vuln_id"] == open_v["id"]


def test_priority_list_respects_limit(tmp_path, monkeypatch):
    client, token, uid = _client_and_token(tmp_path, monkeypatch)
    from app.enterprise import create_asset, create_vulnerability

    asset = create_asset(uid, "host-many")
    for i in range(5):
        create_vulnerability(
            uid,
            {"asset_id": asset["id"], "asset_name": "host-many", "title": f"Finding {i}", "severity": "medium", "status": "open"},
        )

    res = client.get("/api/risk/priority?limit=2", headers=_auth(token))
    body = res.json()
    assert body["total_open"] == 5
    assert len(body["items"]) == 2


def test_priority_list_scoped_to_owning_user(tmp_path, monkeypatch):
    client, token_a, uid_a = _client_and_token(tmp_path, monkeypatch, username="risk_owner_a")
    from app.auth import login, register_user
    from app.enterprise import create_asset, create_vulnerability

    register_user("risk_owner_b", "password123", role="admin")
    _u_b, token_b = login("risk_owner_b", "password123")

    asset = create_asset(uid_a, "a-only-host")
    create_vulnerability(
        uid_a,
        {"asset_id": asset["id"], "asset_name": "a-only-host", "title": "A's finding", "severity": "high", "status": "open"},
    )

    res_a = client.get("/api/risk/priority", headers=_auth(token_a))
    assert res_a.json()["total_open"] == 1

    res_b = client.get("/api/risk/priority", headers=_auth(token_b))
    assert res_b.json()["total_open"] == 0
