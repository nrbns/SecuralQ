"""HTTP-layer tests for asset dependency declarations —
POST/GET /api/assets/{asset_id}/dependencies and
DELETE /api/asset-dependencies/{dependency_id} (app/enterprise_api.py).

This is the only honest source of attack-path connects_to edges (see
app/services/attack_graph.py) — a user declaring "this asset talks to that
asset" since there's no network flow capture in this product.
"""

from __future__ import annotations

from tests._http_test_utils import configure_isolated_settings


def _client_and_token(tmp_path, monkeypatch, username="dep_tester"):
    configure_isolated_settings(monkeypatch, tmp_path)
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


def test_declare_dependency_requires_auth(tmp_path, monkeypatch):
    client, token, _uid = _client_and_token(tmp_path, monkeypatch)
    a = client.post("/api/assets", json={"name": "web"}, headers=_auth(token)).json()
    b = client.post("/api/assets", json={"name": "db"}, headers=_auth(token)).json()
    res = client.post(f"/api/assets/{a['id']}/dependencies", json={"target_asset_id": b["id"]})
    assert res.status_code == 401


def test_declare_dependency_success(tmp_path, monkeypatch):
    client, token, _uid = _client_and_token(tmp_path, monkeypatch)
    a = client.post("/api/assets", json={"name": "web"}, headers=_auth(token)).json()
    b = client.post("/api/assets", json={"name": "db"}, headers=_auth(token)).json()

    res = client.post(
        f"/api/assets/{a['id']}/dependencies",
        json={"target_asset_id": b["id"], "notes": "app tier to db tier"},
        headers=_auth(token),
    )
    assert res.status_code == 200, res.text
    body = res.json()
    assert body["source_asset_id"] == a["id"]
    assert body["target_asset_id"] == b["id"]
    assert body["relationship"] == "connects_to"
    assert body["source"] == "declared"
    assert body["confidence"] == 1.0
    assert body["notes"] == "app tier to db tier"


def test_confirm_inferred_dependency_marks_source_confirmed(tmp_path, monkeypatch):
    """The confirm-connection flow: a security team member confirms a
    previously-inferred connects_to edge. It reuses this same create route
    with confirmed_from_inference=True rather than a separate endpoint, and
    the resulting row must read source='confirmed' (not 'declared') so the
    evidence trail still shows it originated as an inference."""
    client, token, _uid = _client_and_token(tmp_path, monkeypatch)
    a = client.post("/api/assets", json={"name": "web"}, headers=_auth(token)).json()
    b = client.post("/api/assets", json={"name": "db"}, headers=_auth(token)).json()

    res = client.post(
        f"/api/assets/{a['id']}/dependencies",
        json={"target_asset_id": b["id"], "confirmed_from_inference": True},
        headers=_auth(token),
    )
    assert res.status_code == 200, res.text
    body = res.json()
    assert body["source"] == "confirmed"
    assert body["confidence"] == 1.0


def test_declare_dependency_rejects_unknown_source_or_target(tmp_path, monkeypatch):
    client, token, _uid = _client_and_token(tmp_path, monkeypatch)
    a = client.post("/api/assets", json={"name": "web"}, headers=_auth(token)).json()

    res_bad_target = client.post(
        f"/api/assets/{a['id']}/dependencies", json={"target_asset_id": "does-not-exist"}, headers=_auth(token)
    )
    assert res_bad_target.status_code == 404

    res_bad_source = client.post(
        "/api/assets/does-not-exist/dependencies", json={"target_asset_id": a["id"]}, headers=_auth(token)
    )
    assert res_bad_source.status_code == 404


def test_declare_dependency_rejects_self_reference(tmp_path, monkeypatch):
    client, token, _uid = _client_and_token(tmp_path, monkeypatch)
    a = client.post("/api/assets", json={"name": "web"}, headers=_auth(token)).json()

    res = client.post(f"/api/assets/{a['id']}/dependencies", json={"target_asset_id": a["id"]}, headers=_auth(token))
    assert res.status_code == 400


def test_list_dependencies_for_asset(tmp_path, monkeypatch):
    client, token, _uid = _client_and_token(tmp_path, monkeypatch)
    a = client.post("/api/assets", json={"name": "web"}, headers=_auth(token)).json()
    b = client.post("/api/assets", json={"name": "db"}, headers=_auth(token)).json()
    c = client.post("/api/assets", json={"name": "cache"}, headers=_auth(token)).json()

    client.post(f"/api/assets/{a['id']}/dependencies", json={"target_asset_id": b["id"]}, headers=_auth(token))
    client.post(f"/api/assets/{c['id']}/dependencies", json={"target_asset_id": a["id"]}, headers=_auth(token))

    res = client.get(f"/api/assets/{a['id']}/dependencies", headers=_auth(token))
    assert res.status_code == 200, res.text
    deps = res.json()["dependencies"]
    # both directions should show up for asset a (it's the source of one, the target of another)
    assert len(deps) == 2


def test_delete_dependency(tmp_path, monkeypatch):
    client, token, _uid = _client_and_token(tmp_path, monkeypatch)
    a = client.post("/api/assets", json={"name": "web"}, headers=_auth(token)).json()
    b = client.post("/api/assets", json={"name": "db"}, headers=_auth(token)).json()
    created = client.post(f"/api/assets/{a['id']}/dependencies", json={"target_asset_id": b["id"]}, headers=_auth(token)).json()

    res = client.delete(f"/api/asset-dependencies/{created['id']}", headers=_auth(token))
    assert res.status_code == 200, res.text

    listing = client.get(f"/api/assets/{a['id']}/dependencies", headers=_auth(token)).json()
    assert listing["dependencies"] == []

    res_again = client.delete(f"/api/asset-dependencies/{created['id']}", headers=_auth(token))
    assert res_again.status_code == 404


def test_dependency_scoped_to_owning_user(tmp_path, monkeypatch):
    client, token_a, _uid_a = _client_and_token(tmp_path, monkeypatch, username="dep_owner_a")
    from app.auth import login, register_user

    register_user("dep_owner_b", "password123", role="admin")
    _u_b, token_b = login("dep_owner_b", "password123")

    a = client.post("/api/assets", json={"name": "a-web"}, headers=_auth(token_a)).json()
    b = client.post("/api/assets", json={"name": "a-db"}, headers=_auth(token_a)).json()
    created = client.post(f"/api/assets/{a['id']}/dependencies", json={"target_asset_id": b["id"]}, headers=_auth(token_a)).json()

    # user B cannot see or delete user A's dependency
    res_delete = client.delete(f"/api/asset-dependencies/{created['id']}", headers=_auth(token_b))
    assert res_delete.status_code == 404
