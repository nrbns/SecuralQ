"""HTTP-layer tests for /api/cmmc/affirmations (app/cmmc_affirmation_api.py)."""

from __future__ import annotations

from tests._http_test_utils import configure_isolated_settings


def _client_and_token(tmp_path, monkeypatch, username="cmmc_affirm_http_tester"):
    configure_isolated_settings(monkeypatch, tmp_path)
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    from app.auth import login, register_user
    from app.cmmc_affirmation_api import router as affirm_router
    from app.tenancy import ensure_tenant_schema

    ensure_tenant_schema()
    register_user(username, "password123", role="admin")
    u, token = login(username, "password123")

    test_app = FastAPI()
    test_app.include_router(affirm_router)
    client = TestClient(test_app)
    return client, token, u.id


def _auth(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


def test_list_requires_auth(tmp_path, monkeypatch):
    client, _token, _uid = _client_and_token(tmp_path, monkeypatch)
    res = client.get("/api/cmmc/affirmations")
    assert res.status_code == 401


def test_create_and_get_affirmation(tmp_path, monkeypatch):
    from app.db import now

    client, token, _uid = _client_and_token(tmp_path, monkeypatch)
    payload = {
        "level": "Level 2",
        "assessment_date": now() - 1000,
        "affirming_official": "Jane CISO",
        "score": 92,
    }
    res = client.post("/api/cmmc/affirmations", json=payload, headers=_auth(token))
    assert res.status_code == 200
    body = res.json()
    assert body["score"] == 92
    assert body["level"] == "Level 2"

    got = client.get(f"/api/cmmc/affirmations/{body['id']}", headers=_auth(token))
    assert got.status_code == 200
    assert got.json()["affirming_official"] == "Jane CISO"


def test_create_rejects_invalid_score(tmp_path, monkeypatch):
    from app.db import now

    client, token, _uid = _client_and_token(tmp_path, monkeypatch)
    payload = {
        "level": "Level 2",
        "assessment_date": now(),
        "affirming_official": "Jane CISO",
        "score": 9999,
    }
    res = client.post("/api/cmmc/affirmations", json=payload, headers=_auth(token))
    assert res.status_code == 400


def test_latest_and_list(tmp_path, monkeypatch):
    from app.db import now

    client, token, _uid = _client_and_token(tmp_path, monkeypatch)
    client.post(
        "/api/cmmc/affirmations",
        json={"level": "Level 2", "assessment_date": now() - 500000, "affirming_official": "A", "score": 40},
        headers=_auth(token),
    )
    client.post(
        "/api/cmmc/affirmations",
        json={"level": "Level 2", "assessment_date": now() - 100, "affirming_official": "B", "score": 70},
        headers=_auth(token),
    )

    latest = client.get("/api/cmmc/affirmations/latest", headers=_auth(token))
    assert latest.status_code == 200
    assert latest.json()["affirmation"]["affirming_official"] == "B"

    listed = client.get("/api/cmmc/affirmations", headers=_auth(token))
    assert len(listed.json()["affirmations"]) == 2


def test_delete_affirmation(tmp_path, monkeypatch):
    from app.db import now

    client, token, _uid = _client_and_token(tmp_path, monkeypatch)
    created = client.post(
        "/api/cmmc/affirmations",
        json={"level": "Level 1", "assessment_date": now(), "affirming_official": "Jane CISO"},
        headers=_auth(token),
    ).json()

    res = client.delete(f"/api/cmmc/affirmations/{created['id']}", headers=_auth(token))
    assert res.status_code == 200
    missing = client.get(f"/api/cmmc/affirmations/{created['id']}", headers=_auth(token))
    assert missing.status_code == 404
