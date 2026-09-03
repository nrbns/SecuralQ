"""HTTP-layer tests for GET/POST /api/evidence (app/evidence_api.py)."""

from __future__ import annotations

from tests._http_test_utils import configure_isolated_settings


def _client_and_token(tmp_path, monkeypatch, username="evidence_http_tester"):
    configure_isolated_settings(monkeypatch, tmp_path)
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    from app.auth import login, register_user
    from app.evidence_api import router as evidence_router
    from app.tenancy import ensure_tenant_schema

    ensure_tenant_schema()
    register_user(username, "password123", role="admin")
    u, token = login(username, "password123")

    test_app = FastAPI()
    test_app.include_router(evidence_router)
    client = TestClient(test_app)
    return client, token, u.id


def _auth(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


def test_list_evidence_requires_auth(tmp_path, monkeypatch):
    client, _token, _uid = _client_and_token(tmp_path, monkeypatch)
    res = client.get("/api/evidence")
    assert res.status_code == 401


def test_list_evidence_empty_then_populated(tmp_path, monkeypatch):
    client, token, uid = _client_and_token(tmp_path, monkeypatch)
    res = client.get("/api/evidence", headers=_auth(token))
    assert res.status_code == 200
    assert res.json()["evidence"] == []

    from app.services.evidence import record_evidence

    record_evidence(uid, entity_type="threat", entity_id="t1", source="observed", summary="signal")

    res2 = client.get("/api/evidence", headers=_auth(token))
    assert len(res2.json()["evidence"]) == 1


def test_get_evidence_for_entity(tmp_path, monkeypatch):
    client, token, uid = _client_and_token(tmp_path, monkeypatch)
    from app.services.evidence import record_evidence

    record_evidence(uid, entity_type="threat", entity_id="t1", source="observed", summary="signal A")
    record_evidence(uid, entity_type="threat", entity_id="t2", source="observed", summary="signal B")

    res = client.get("/api/evidence/threat/t1", headers=_auth(token))
    assert res.status_code == 200
    body = res.json()["evidence"]
    assert len(body) == 1
    assert body[0]["entity_id"] == "t1"


def test_confirm_evidence_via_http(tmp_path, monkeypatch):
    client, token, uid = _client_and_token(tmp_path, monkeypatch)
    from app.services.evidence import record_evidence

    ev = record_evidence(uid, entity_type="threat", entity_id="t1", source="observed", summary="signal")
    assert ev["verified"] is False

    res = client.post(f"/api/evidence/{ev['id']}/confirm", headers=_auth(token))
    assert res.status_code == 200, res.text
    assert res.json()["verified"] is True


def test_confirm_evidence_requires_auth(tmp_path, monkeypatch):
    client, token, uid = _client_and_token(tmp_path, monkeypatch)
    from app.services.evidence import record_evidence

    ev = record_evidence(uid, entity_type="threat", entity_id="t1", source="observed", summary="signal")
    res = client.post(f"/api/evidence/{ev['id']}/confirm")
    assert res.status_code == 401


def test_confirm_evidence_unknown_id_404(tmp_path, monkeypatch):
    client, token, _uid = _client_and_token(tmp_path, monkeypatch)
    res = client.post("/api/evidence/does-not-exist/confirm", headers=_auth(token))
    assert res.status_code == 404


def test_evidence_scoped_to_owning_user_via_http(tmp_path, monkeypatch):
    client_a, token_a, uid_a = _client_and_token(tmp_path, monkeypatch, username="evidence_http_owner_a")
    from app.auth import login, register_user
    from app.services.evidence import record_evidence

    register_user("evidence_http_owner_b", "password123", role="admin")
    _u_b, token_b = login("evidence_http_owner_b", "password123")

    record_evidence(uid_a, entity_type="threat", entity_id="shared", source="observed", summary="a's evidence")

    res_a = client_a.get("/api/evidence/threat/shared", headers=_auth(token_a))
    res_b = client_a.get("/api/evidence/threat/shared", headers=_auth(token_b))
    assert len(res_a.json()["evidence"]) == 1
    assert len(res_b.json()["evidence"]) == 0


def test_list_evidence_filters_by_query_params(tmp_path, monkeypatch):
    client, token, uid = _client_and_token(tmp_path, monkeypatch)
    from app.services.evidence import record_evidence

    record_evidence(uid, entity_type="asset_dependency", entity_id="d1", source="declared", summary="declared")
    record_evidence(uid, entity_type="threat", entity_id="t1", source="observed", summary="observed")

    res = client.get("/api/evidence", params={"source": "declared"}, headers=_auth(token))
    body = res.json()["evidence"]
    assert len(body) == 1
    assert body[0]["source"] == "declared"

    res2 = client.get("/api/evidence", params={"entity_type": "threat"}, headers=_auth(token))
    body2 = res2.json()["evidence"]
    assert len(body2) == 1
    assert body2[0]["entity_type"] == "threat"
