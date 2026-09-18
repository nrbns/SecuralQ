"""HTTP-layer tests for DELETE /api/scans/{scan_id} (app/scans_api.py).

Manual delete for live scans — the "Recent web scans" / "Scan reports" tables
previously only let you delete an *archived* report (DELETE
/api/archive/scans/{id}); a scan still in the live `scans` table had no
delete path at all. Pattern follows tests/test_delete_routes_http.py.
"""

from __future__ import annotations

from pathlib import Path

from tests._http_test_utils import configure_isolated_settings


def _client_and_token(tmp_path, monkeypatch, username="scan_del_tester"):
    """Returns (client, bearer_token, real_user_id)."""
    configure_isolated_settings(monkeypatch, tmp_path)
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    from app.auth import login, register_user
    from app.scans_api import router as scans_router
    from app.tenancy import ensure_tenant_schema

    ensure_tenant_schema()
    register_user(username, "password123", role="admin")
    u, token = login(username, "password123")

    test_app = FastAPI()
    test_app.include_router(scans_router)
    client = TestClient(test_app)
    return client, token, u.id


def _register_and_login(username: str):
    from app.auth import login, register_user

    register_user(username, "password123", role="admin")
    u, token = login(username, "password123")
    return token, u.id


def _auth(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


def _make_scan(user_id: str, *, target: str = "https://example.com"):
    from app.scan_engine.models import create_scan

    return create_scan(
        user_id=user_id,
        target=target,
        scanner="zap",
        profile="web",
        authorized=True,
    )


def test_delete_scan_requires_auth(tmp_path, monkeypatch):
    client, _token, _uid = _client_and_token(tmp_path, monkeypatch)
    res = client.delete("/api/scans/does-not-exist")
    assert res.status_code == 401


def test_delete_scan_404_for_unknown(tmp_path, monkeypatch):
    client, token, _uid = _client_and_token(tmp_path, monkeypatch)
    res = client.delete("/api/scans/does-not-exist", headers=_auth(token))
    assert res.status_code == 404


def test_delete_scan_removes_row_and_evidence_dir(tmp_path, monkeypatch):
    client, token, uid = _client_and_token(tmp_path, monkeypatch)
    scan = _make_scan(uid)
    scan_id = scan["id"]
    ev_dir = Path(scan["evidence_dir"])
    ev_dir.mkdir(parents=True, exist_ok=True)
    (ev_dir / "marker.txt").write_text("evidence", encoding="utf-8")

    # visible before delete
    get_res = client.get(f"/api/scans/{scan_id}", headers=_auth(token))
    assert get_res.status_code == 200

    del_res = client.delete(f"/api/scans/{scan_id}", headers=_auth(token))
    assert del_res.status_code == 200, del_res.text
    assert del_res.json()["ok"] is True

    # gone from the DB — real removal, not a status flag
    get_res2 = client.get(f"/api/scans/{scan_id}", headers=_auth(token))
    assert get_res2.status_code == 404

    # evidence directory actually removed from disk
    assert not ev_dir.exists()

    # deleting again is a real 404, not a silent no-op success
    del_res2 = client.delete(f"/api/scans/{scan_id}", headers=_auth(token))
    assert del_res2.status_code == 404


def test_delete_scan_scoped_to_owning_user(tmp_path, monkeypatch):
    client, token_a, uid_a = _client_and_token(tmp_path, monkeypatch, username="scan_owner_a")
    token_b, _uid_b = _register_and_login("scan_owner_b")
    scan = _make_scan(uid_a)
    scan_id = scan["id"]

    res = client.delete(f"/api/scans/{scan_id}", headers=_auth(token_b))
    assert res.status_code == 404

    # still there for the real owner
    res2 = client.get(f"/api/scans/{scan_id}", headers=_auth(token_a))
    assert res2.status_code == 200
