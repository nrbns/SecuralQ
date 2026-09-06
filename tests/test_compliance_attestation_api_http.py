"""HTTP-layer tests for /api/compliance/attestations (app/compliance_attestation_api.py)."""

from __future__ import annotations

from tests._http_test_utils import configure_isolated_settings


def _client_and_token(tmp_path, monkeypatch, username="attest_http_tester"):
    configure_isolated_settings(monkeypatch, tmp_path)
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    from app.auth import login, register_user
    from app.compliance_attestation_api import router as attest_router
    from app.tenancy import ensure_tenant_schema

    ensure_tenant_schema()
    register_user(username, "password123", role="admin")
    u, token = login(username, "password123")

    test_app = FastAPI()
    test_app.include_router(attest_router)
    client = TestClient(test_app)
    return client, token, u.id


def _auth(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


def test_list_requires_auth(tmp_path, monkeypatch):
    client, _token, _uid = _client_and_token(tmp_path, monkeypatch)
    res = client.get("/api/compliance/attestations")
    assert res.status_code == 401


def test_profile_endpoint(tmp_path, monkeypatch):
    client, token, _uid = _client_and_token(tmp_path, monkeypatch)
    res = client.get("/api/compliance/attestations/profile/pci_dss", headers=_auth(token))
    assert res.status_code == 200
    body = res.json()
    assert body["attestation_label"] == "SAQ / Attestation of Compliance (AOC)"


def test_create_and_get_attestation(tmp_path, monkeypatch):
    from app.db import now

    client, token, _uid = _client_and_token(tmp_path, monkeypatch)
    payload = {
        "framework_id": "iso27001",
        "assessment_date": now() - 1000,
        "attesting_official": "Jane CISO",
    }
    res = client.post("/api/compliance/attestations", json=payload, headers=_auth(token))
    assert res.status_code == 200
    body = res.json()
    assert body["framework_id"] == "iso27001"

    got = client.get(f"/api/compliance/attestations/{body['id']}", headers=_auth(token))
    assert got.status_code == 200
    assert got.json()["attesting_official"] == "Jane CISO"


def test_create_rejects_missing_official(tmp_path, monkeypatch):
    from app.db import now

    client, token, _uid = _client_and_token(tmp_path, monkeypatch)
    payload = {"framework_id": "hipaa", "assessment_date": now(), "attesting_official": "   "}
    res = client.post("/api/compliance/attestations", json=payload, headers=_auth(token))
    assert res.status_code == 400


def test_latest_and_list(tmp_path, monkeypatch):
    from app.db import now

    client, token, _uid = _client_and_token(tmp_path, monkeypatch)
    client.post(
        "/api/compliance/attestations",
        json={"framework_id": "gdpr", "assessment_date": now() - 500000, "attesting_official": "A"},
        headers=_auth(token),
    )
    client.post(
        "/api/compliance/attestations",
        json={"framework_id": "gdpr", "assessment_date": now() - 100, "attesting_official": "B"},
        headers=_auth(token),
    )

    latest = client.get("/api/compliance/attestations/latest?framework_id=gdpr", headers=_auth(token))
    assert latest.status_code == 200
    assert latest.json()["attestation"]["attesting_official"] == "B"

    listed = client.get("/api/compliance/attestations?framework_id=gdpr", headers=_auth(token))
    assert len(listed.json()["attestations"]) == 2


def test_delete_attestation(tmp_path, monkeypatch):
    from app.db import now

    client, token, _uid = _client_and_token(tmp_path, monkeypatch)
    created = client.post(
        "/api/compliance/attestations",
        json={"framework_id": "nis2", "assessment_date": now(), "attesting_official": "Jane"},
        headers=_auth(token),
    ).json()

    res = client.delete(f"/api/compliance/attestations/{created['id']}", headers=_auth(token))
    assert res.status_code == 200
    missing = client.get(f"/api/compliance/attestations/{created['id']}", headers=_auth(token))
    assert missing.status_code == 404
