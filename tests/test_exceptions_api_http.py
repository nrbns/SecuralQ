"""HTTP-layer tests for /api/exceptions (app/exceptions_api.py)."""

from __future__ import annotations

from tests._http_test_utils import configure_isolated_settings


def _client_and_token(tmp_path, monkeypatch, username="exc_http_tester"):
    configure_isolated_settings(monkeypatch, tmp_path)
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    from app.auth import login, register_user
    from app.exceptions_api import router as exceptions_router
    from app.tenancy import ensure_tenant_schema

    ensure_tenant_schema()
    register_user(username, "password123", role="admin")
    u, token = login(username, "password123")

    test_app = FastAPI()
    test_app.include_router(exceptions_router)
    client = TestClient(test_app)
    return client, token, u.id


def _auth(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


def _payload(now_val, **overrides):
    base = {
        "title": "Legacy VPN lacks MFA",
        "reason": "Vendor appliance pending Q3 upgrade",
        "risk_accepted": "Medium residual risk of credential stuffing",
        "owner": "ciso@example.com",
        "expiry": now_val + 30 * 86400,
    }
    base.update(overrides)
    return base


def test_list_requires_auth(tmp_path, monkeypatch):
    client, _token, _uid = _client_and_token(tmp_path, monkeypatch)
    res = client.get("/api/exceptions")
    assert res.status_code == 401


def test_create_and_get_exception(tmp_path, monkeypatch):
    from app.db import now

    client, token, _uid = _client_and_token(tmp_path, monkeypatch)
    res = client.post("/api/exceptions", json=_payload(now()), headers=_auth(token))
    assert res.status_code == 200, res.text
    body = res.json()
    assert body["status"] == "pending_approval"

    got = client.get(f"/api/exceptions/{body['id']}", headers=_auth(token))
    assert got.status_code == 200
    assert got.json()["title"] == "Legacy VPN lacks MFA"


def test_create_rejects_missing_expiry(tmp_path, monkeypatch):
    client, token, _uid = _client_and_token(tmp_path, monkeypatch)
    payload = {
        "title": "No expiry",
        "reason": "x",
        "risk_accepted": "y",
        "owner": "z",
    }
    res = client.post("/api/exceptions", json=payload, headers=_auth(token))
    assert res.status_code == 422  # pydantic: expiry is a required field


def test_create_rejects_past_expiry(tmp_path, monkeypatch):
    from app.db import now

    client, token, _uid = _client_and_token(tmp_path, monkeypatch)
    res = client.post("/api/exceptions", json=_payload(now(), expiry=now() - 3600), headers=_auth(token))
    assert res.status_code == 400
    assert "future" in res.json()["detail"]


def test_approve_reject_revoke_flow(tmp_path, monkeypatch):
    from app.db import now

    client, token, _uid = _client_and_token(tmp_path, monkeypatch)
    created = client.post("/api/exceptions", json=_payload(now()), headers=_auth(token)).json()
    eid = created["id"]

    approved = client.post(f"/api/exceptions/{eid}/approve", headers=_auth(token))
    assert approved.status_code == 200
    assert approved.json()["status"] == "approved"
    assert approved.json()["is_active_coverage"] is True

    revoked = client.post(f"/api/exceptions/{eid}/revoke", headers=_auth(token))
    assert revoked.status_code == 200
    assert revoked.json()["status"] == "revoked"


def test_list_and_summary(tmp_path, monkeypatch):
    from app.db import now

    client, token, _uid = _client_and_token(tmp_path, monkeypatch)
    client.post("/api/exceptions", json=_payload(now(), title="A"), headers=_auth(token))
    client.post("/api/exceptions", json=_payload(now(), title="B"), headers=_auth(token))

    listed = client.get("/api/exceptions", headers=_auth(token))
    assert listed.status_code == 200
    assert len(listed.json()["exceptions"]) == 2

    summary = client.get("/api/exceptions/summary", headers=_auth(token))
    assert summary.status_code == 200
    assert summary.json()["total"] == 2


def test_delete_exception(tmp_path, monkeypatch):
    from app.db import now

    client, token, _uid = _client_and_token(tmp_path, monkeypatch)
    created = client.post("/api/exceptions", json=_payload(now()), headers=_auth(token)).json()
    res = client.delete(f"/api/exceptions/{created['id']}", headers=_auth(token))
    assert res.status_code == 200
    res2 = client.get(f"/api/exceptions/{created['id']}", headers=_auth(token))
    assert res2.status_code == 404


def test_exceptions_scoped_to_owning_user(tmp_path, monkeypatch):
    from app.auth import login, register_user
    from app.db import now

    client_a, token_a, _uid_a = _client_and_token(tmp_path, monkeypatch, username="exc_owner_a")
    register_user("exc_owner_b", "password123", role="admin")
    _u_b, token_b = login("exc_owner_b", "password123")

    client_a.post("/api/exceptions", json=_payload(now()), headers=_auth(token_a))

    res_a = client_a.get("/api/exceptions", headers=_auth(token_a))
    res_b = client_a.get("/api/exceptions", headers=_auth(token_b))
    assert len(res_a.json()["exceptions"]) == 1
    assert len(res_b.json()["exceptions"]) == 0
