"""HTTP-layer tests for GET /api/assets/cmmc-enclave-boundary
(app.cmmc_scoping.enclave_boundary_report via app/enterprise_api.py).

The "Secure Enclave" model in CMMC scoping guidance says CUI Assets/SPAs
must sit behind a boundary with no unmediated connection to the regular
business network. This endpoint doesn't draw that boundary as a static
picture -- it recomputes it every call from two pieces of data this
product already collects (cmmc_asset_category, asset_dependencies) and
flags any declared/inferred dependency that crosses it.
"""

from __future__ import annotations

from tests._http_test_utils import configure_isolated_settings


def _client_and_token(tmp_path, monkeypatch, username="enclave_tester"):
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


def test_enclave_boundary_requires_auth(tmp_path, monkeypatch):
    client, _token, _uid = _client_and_token(tmp_path, monkeypatch)
    res = client.get("/api/assets/cmmc-enclave-boundary")
    assert res.status_code == 401


def test_enclave_boundary_empty_when_no_assets(tmp_path, monkeypatch):
    client, token, _uid = _client_and_token(tmp_path, monkeypatch)
    res = client.get("/api/assets/cmmc-enclave-boundary", headers=_auth(token))
    assert res.status_code == 200, res.text
    body = res.json()
    assert body["enclave_asset_count"] == 0
    assert body["regular_business_asset_count"] == 0
    assert body["boundary_violations"] == []
    assert body["boundary_intact"] is True


def test_enclave_boundary_intact_with_no_crossing_dependency(tmp_path, monkeypatch):
    """A CUI asset and a regular-business asset that simply coexist, with
    no declared connection between them, is not a violation."""
    client, token, _uid = _client_and_token(tmp_path, monkeypatch)

    enclave = client.post(
        "/api/assets",
        json={"name": "cui-workstation", "cmmc_asset_category": "cui_asset"},
        headers=_auth(token),
    ).json()
    client.post(
        "/api/assets",
        json={"name": "regular-laptop", "cmmc_asset_category": "out_of_scope"},
        headers=_auth(token),
    )

    res = client.get("/api/assets/cmmc-enclave-boundary", headers=_auth(token))
    body = res.json()
    assert body["enclave_asset_count"] == 1
    assert body["regular_business_asset_count"] == 1
    assert body["boundary_violations"] == []
    assert body["boundary_intact"] is True
    assert enclave["id"]  # sanity: the enclave asset really was created


def test_enclave_boundary_flags_declared_crossing_dependency(tmp_path, monkeypatch):
    """The real finding: a declared connects_to edge between a CUI asset
    and an out-of-scope asset must be flagged as a boundary violation."""
    client, token, _uid = _client_and_token(tmp_path, monkeypatch)

    cui = client.post(
        "/api/assets",
        json={"name": "cui-file-server", "cmmc_asset_category": "cui_asset"},
        headers=_auth(token),
    ).json()
    regular = client.post(
        "/api/assets",
        json={"name": "unmanaged-laptop", "cmmc_asset_category": ""},
        headers=_auth(token),
    ).json()
    client.post(
        f"/api/assets/{cui['id']}/dependencies",
        json={"target_asset_id": regular["id"]},
        headers=_auth(token),
    )

    res = client.get("/api/assets/cmmc-enclave-boundary", headers=_auth(token))
    body = res.json()
    assert body["boundary_intact"] is False
    assert len(body["boundary_violations"]) == 1
    v = body["boundary_violations"][0]
    assert {v["enclave_asset_id"], v["regular_asset_id"]} == {cui["id"], regular["id"]}
    assert v["enclave_asset_name"] == "cui-file-server"
    assert v["regular_asset_name"] == "unmanaged-laptop"


def test_enclave_boundary_spa_to_regular_also_flagged(tmp_path, monkeypatch):
    """SPA (Security Protection Asset) is also a full-assessment category --
    a connection from an SPA into the regular network must be flagged too,
    not just cui_asset."""
    client, token, _uid = _client_and_token(tmp_path, monkeypatch)

    spa = client.post(
        "/api/assets", json={"name": "mfa-gateway", "cmmc_asset_category": "spa"}, headers=_auth(token)
    ).json()
    regular = client.post(
        "/api/assets", json={"name": "guest-wifi-ap", "cmmc_asset_category": "out_of_scope"}, headers=_auth(token)
    ).json()
    client.post(
        f"/api/assets/{regular['id']}/dependencies",
        json={"target_asset_id": spa["id"]},
        headers=_auth(token),
    )

    res = client.get("/api/assets/cmmc-enclave-boundary", headers=_auth(token))
    body = res.json()
    assert body["boundary_intact"] is False
    assert len(body["boundary_violations"]) == 1


def test_enclave_boundary_crma_connection_is_not_a_violation(tmp_path, monkeypatch):
    """CRMA (Contractor Risk Managed Asset) is CMMC's own answer for
    limited, policy-managed contact with the boundary -- a connection
    touching a crma-classified asset must NOT be flagged, unlike
    out_of_scope/unclassified."""
    client, token, _uid = _client_and_token(tmp_path, monkeypatch)

    cui = client.post(
        "/api/assets", json={"name": "cui-db", "cmmc_asset_category": "cui_asset"}, headers=_auth(token)
    ).json()
    crma = client.post(
        "/api/assets", json={"name": "risk-managed-laptop", "cmmc_asset_category": "crma"}, headers=_auth(token)
    ).json()
    client.post(
        f"/api/assets/{cui['id']}/dependencies",
        json={"target_asset_id": crma["id"]},
        headers=_auth(token),
    )

    res = client.get("/api/assets/cmmc-enclave-boundary", headers=_auth(token))
    body = res.json()
    assert body["boundary_violations"] == []
    assert body["boundary_intact"] is True


def test_enclave_boundary_scoped_to_owning_user(tmp_path, monkeypatch):
    client, token_a, _uid_a = _client_and_token(tmp_path, monkeypatch, username="enclave_owner_a")
    from app.auth import login, register_user

    register_user("enclave_owner_b", "password123", role="admin")
    _u_b, token_b = login("enclave_owner_b", "password123")

    client.post(
        "/api/assets", json={"name": "a-cui-box", "cmmc_asset_category": "cui_asset"}, headers=_auth(token_a)
    )

    res_a = client.get("/api/assets/cmmc-enclave-boundary", headers=_auth(token_a))
    assert res_a.json()["enclave_asset_count"] == 1

    res_b = client.get("/api/assets/cmmc-enclave-boundary", headers=_auth(token_b))
    assert res_b.json()["enclave_asset_count"] == 0
