"""HTTP-layer tests for Remediation Plans — POST/GET/DELETE
/api/risk/remediation-plans* (app/risk_api.py)."""

from __future__ import annotations

from tests._http_test_utils import configure_isolated_settings


def _client_and_token(tmp_path, monkeypatch, username="remediation_http_tester"):
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


def _seed_open_group(uid, *, cve="CVE-2024-1111"):
    from app.enterprise import create_asset, create_vulnerability

    a = create_asset(uid, "WEB-01", asset_type="web")
    create_vulnerability(
        uid,
        {"asset_id": a["id"], "asset_name": "WEB-01", "title": "Apache RCE", "cve": cve, "severity": "critical", "cvss": 9.8, "status": "open"},
    )
    return f"cve:{cve}"


def test_create_plan_requires_auth(tmp_path, monkeypatch):
    client, token, uid = _client_and_token(tmp_path, monkeypatch)
    group_key = _seed_open_group(uid)
    res = client.post("/api/risk/remediation-plans", json={"group_key": group_key})
    assert res.status_code == 401


def test_create_plan_success_and_get(tmp_path, monkeypatch):
    client, token, uid = _client_and_token(tmp_path, monkeypatch)
    group_key = _seed_open_group(uid)

    res = client.post("/api/risk/remediation-plans", json={"group_key": group_key}, headers=_auth(token))
    assert res.status_code == 200, res.text
    plan = res.json()
    assert plan["status"] == "draft"
    assert plan["group_key"] == group_key

    got = client.get(f"/api/risk/remediation-plans/{plan['id']}", headers=_auth(token))
    assert got.status_code == 200
    assert got.json()["id"] == plan["id"]


def test_create_plan_rejects_unknown_group(tmp_path, monkeypatch):
    client, token, _uid = _client_and_token(tmp_path, monkeypatch)
    res = client.post("/api/risk/remediation-plans", json={"group_key": "cve:CVE-0000-0000"}, headers=_auth(token))
    assert res.status_code == 400


def test_list_plans(tmp_path, monkeypatch):
    client, token, uid = _client_and_token(tmp_path, monkeypatch)
    key_a = _seed_open_group(uid, cve="CVE-2024-1001")
    key_b = _seed_open_group(uid, cve="CVE-2024-1002")
    client.post("/api/risk/remediation-plans", json={"group_key": key_a}, headers=_auth(token))
    client.post("/api/risk/remediation-plans", json={"group_key": key_b}, headers=_auth(token))

    res = client.get("/api/risk/remediation-plans", headers=_auth(token))
    assert res.status_code == 200
    assert len(res.json()["plans"]) == 2


def test_approve_reject_and_delete_plan(tmp_path, monkeypatch):
    client, token, uid = _client_and_token(tmp_path, monkeypatch)
    group_key = _seed_open_group(uid)
    plan = client.post("/api/risk/remediation-plans", json={"group_key": group_key}, headers=_auth(token)).json()

    approved = client.post(f"/api/risk/remediation-plans/{plan['id']}/approve", headers=_auth(token))
    assert approved.status_code == 200
    assert approved.json()["status"] == "approved"

    # can't reject-then-approve-again in this test; instead exercise reject on a fresh plan
    group_key2 = _seed_open_group(uid, cve="CVE-2024-2002")
    plan2 = client.post("/api/risk/remediation-plans", json={"group_key": group_key2}, headers=_auth(token)).json()
    rejected = client.post(f"/api/risk/remediation-plans/{plan2['id']}/reject", headers=_auth(token))
    assert rejected.status_code == 200
    assert rejected.json()["status"] == "rejected"

    deleted = client.delete(f"/api/risk/remediation-plans/{plan['id']}", headers=_auth(token))
    assert deleted.status_code == 200
    missing = client.get(f"/api/risk/remediation-plans/{plan['id']}", headers=_auth(token))
    assert missing.status_code == 404


def test_link_campaign_flow(tmp_path, monkeypatch):
    from app.agents import create_campaign, enroll_agent

    client, token, uid = _client_and_token(tmp_path, monkeypatch)
    group_key = _seed_open_group(uid)
    plan = client.post("/api/risk/remediation-plans", json={"group_key": group_key}, headers=_auth(token)).json()
    client.post(f"/api/risk/remediation-plans/{plan['id']}/approve", headers=_auth(token))

    agent = enroll_agent(uid, name="http-test-agent")
    campaign = create_campaign(uid, name="http test campaign", manager="apt", package="apache2", agent_ids=[agent["agent_id"]])

    res = client.post(
        f"/api/risk/remediation-plans/{plan['id']}/link-campaign",
        json={"campaign_id": campaign["id"]},
        headers=_auth(token),
    )
    assert res.status_code == 200, res.text
    assert res.json()["status"] == "executing"
    assert res.json()["campaign_id"] == campaign["id"]


def test_link_campaign_rejects_unknown_campaign(tmp_path, monkeypatch):
    client, token, uid = _client_and_token(tmp_path, monkeypatch)
    group_key = _seed_open_group(uid)
    plan = client.post("/api/risk/remediation-plans", json={"group_key": group_key}, headers=_auth(token)).json()
    client.post(f"/api/risk/remediation-plans/{plan['id']}/approve", headers=_auth(token))

    res = client.post(
        f"/api/risk/remediation-plans/{plan['id']}/link-campaign",
        json={"campaign_id": "does-not-exist"},
        headers=_auth(token),
    )
    assert res.status_code == 400


def test_remeasure_plan(tmp_path, monkeypatch):
    client, token, uid = _client_and_token(tmp_path, monkeypatch)
    group_key = _seed_open_group(uid)
    plan = client.post("/api/risk/remediation-plans", json={"group_key": group_key}, headers=_auth(token)).json()
    client.post(f"/api/risk/remediation-plans/{plan['id']}/approve", headers=_auth(token))

    res = client.post(f"/api/risk/remediation-plans/{plan['id']}/remeasure", headers=_auth(token))
    assert res.status_code == 200, res.text
    assert res.json()["status"] == "measured"
    assert res.json()["risk_after"] is not None


def test_plan_scoped_to_owning_user(tmp_path, monkeypatch):
    client_a, token_a, uid_a = _client_and_token(tmp_path, monkeypatch, username="remediation_http_owner_a")
    from app.auth import login, register_user

    register_user("remediation_http_owner_b", "password123", role="admin")
    _u_b, token_b = login("remediation_http_owner_b", "password123")

    group_key = _seed_open_group(uid_a)
    plan = client_a.post("/api/risk/remediation-plans", json={"group_key": group_key}, headers=_auth(token_a)).json()

    res = client_a.get(f"/api/risk/remediation-plans/{plan['id']}", headers=_auth(token_b))
    assert res.status_code == 404
