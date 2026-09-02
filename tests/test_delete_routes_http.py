"""HTTP-layer tests for the delete routes added this hardening pass:

  DELETE /api/vulnerabilities/{vuln_id}   (app/enterprise_api.py)
  DELETE /api/gap/remediations/{rem_id}   (app/enterprise_api.py)
  DELETE /api/gap/assessments/{assessment_id}  (app/gap_api.py, cascades
      to its remediation tasks)

Earlier coverage exercised the underlying app.enterprise / app.gap_analysis
functions directly. These tests go through the real FastAPI routes with
TestClient (pattern from tests/test_builtin_scanner.py) to verify auth
enforcement, status codes, and — for the assessment route — the actual
cascade-delete behavior over HTTP.

Note: register_user()/login() generate a random opaque user id distinct
from the username, so every helper below threads through the *real*
user.id (returned by `_client_and_token`) rather than the login username —
using the username as user_id would silently create/query rows for a user
that doesn't exist, which is exactly what the first draft of this file did
and why every "still there for the owner" assertion 404'd.
"""

from __future__ import annotations

from tests._http_test_utils import configure_isolated_settings


def _reload_db(monkeypatch, data_dir):
    return configure_isolated_settings(monkeypatch, data_dir)


def _client_and_token(tmp_path, monkeypatch, username="del_tester"):
    """Returns (client, bearer_token, real_user_id)."""
    _reload_db(monkeypatch, tmp_path)
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    from app.auth import login, register_user
    from app.enterprise_api import router as enterprise_router
    from app.gap_api import router as gap_router
    from app.tenancy import ensure_tenant_schema

    ensure_tenant_schema()
    register_user(username, "password123", role="admin")
    u, token = login(username, "password123")

    test_app = FastAPI()
    test_app.include_router(enterprise_router)
    test_app.include_router(gap_router)
    client = TestClient(test_app)
    return client, token, u.id


def _register_and_login(username: str):
    from app.auth import login, register_user

    register_user(username, "password123", role="admin")
    u, token = login(username, "password123")
    return token, u.id


def _auth(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


# --- DELETE /api/vulnerabilities/{id} ---------------------------------------


def test_delete_vulnerability_requires_auth(tmp_path, monkeypatch):
    client, _token, _uid = _client_and_token(tmp_path, monkeypatch)
    res = client.delete("/api/vulnerabilities/does-not-exist")
    assert res.status_code == 401


def test_delete_vulnerability_404_for_unknown(tmp_path, monkeypatch):
    client, token, _uid = _client_and_token(tmp_path, monkeypatch)
    res = client.delete("/api/vulnerabilities/does-not-exist", headers=_auth(token))
    assert res.status_code == 404


def _vuln_ids(client, token) -> set:
    res = client.get("/api/vulnerabilities", headers=_auth(token))
    assert res.status_code == 200, res.text
    return {v["id"] for v in res.json()["vulnerabilities"]}


def test_delete_vulnerability_removes_real_finding(tmp_path, monkeypatch):
    client, token, uid = _client_and_token(tmp_path, monkeypatch)
    from app.enterprise import create_vulnerability

    row = create_vulnerability(
        uid,
        {"title": "SQLi in login form", "severity": "high", "source": "test"},
    )
    vid = row["id"]

    # visible before delete, via the real list route
    assert vid in _vuln_ids(client, token)

    del_res = client.delete(f"/api/vulnerabilities/{vid}", headers=_auth(token))
    assert del_res.status_code == 200, del_res.text
    assert del_res.json()["ok"] is True

    # gone after delete — genuine removal, not silently "still there"
    assert vid not in _vuln_ids(client, token)

    # deleting again is a real 404
    del_res2 = client.delete(f"/api/vulnerabilities/{vid}", headers=_auth(token))
    assert del_res2.status_code == 404


def test_delete_vulnerability_scoped_to_owning_user(tmp_path, monkeypatch):
    client, token_a, uid_a = _client_and_token(tmp_path, monkeypatch, username="vuln_owner_a")
    token_b, _uid_b = _register_and_login("vuln_owner_b")
    from app.enterprise import create_vulnerability

    row = create_vulnerability(uid_a, {"title": "Owner A's finding", "severity": "medium"})
    vid = row["id"]

    res = client.delete(f"/api/vulnerabilities/{vid}", headers=_auth(token_b))
    assert res.status_code == 404

    # still there for the real owner
    assert vid in _vuln_ids(client, token_a)


# --- DELETE /api/gap/remediations/{id} --------------------------------------


def test_delete_remediation_requires_auth(tmp_path, monkeypatch):
    client, _token, _uid = _client_and_token(tmp_path, monkeypatch)
    res = client.delete("/api/gap/remediations/does-not-exist")
    assert res.status_code == 401


def test_delete_remediation_404_for_unknown(tmp_path, monkeypatch):
    client, token, _uid = _client_and_token(tmp_path, monkeypatch)
    res = client.delete("/api/gap/remediations/does-not-exist", headers=_auth(token))
    assert res.status_code == 404


def test_delete_remediation_removes_real_task(tmp_path, monkeypatch):
    client, token, uid = _client_and_token(tmp_path, monkeypatch)
    from app.enterprise import create_remediation, list_remediations

    row = create_remediation(uid, control_id="AC-2", title="Rotate service account keys")
    rid = row["id"]
    assert any(r["id"] == rid for r in list_remediations(uid))

    del_res = client.delete(f"/api/gap/remediations/{rid}", headers=_auth(token))
    assert del_res.status_code == 200, del_res.text
    assert del_res.json()["ok"] is True

    assert not any(r["id"] == rid for r in list_remediations(uid))

    del_res2 = client.delete(f"/api/gap/remediations/{rid}", headers=_auth(token))
    assert del_res2.status_code == 404


def test_delete_remediation_scoped_to_owning_user(tmp_path, monkeypatch):
    client, token_a, uid_a = _client_and_token(tmp_path, monkeypatch, username="rem_owner_a")
    token_b, _uid_b = _register_and_login("rem_owner_b")
    from app.enterprise import create_remediation, list_remediations

    row = create_remediation(uid_a, control_id="AC-3", title="Owner A's task")
    rid = row["id"]

    res = client.delete(f"/api/gap/remediations/{rid}", headers=_auth(token_b))
    assert res.status_code == 404

    assert any(r["id"] == rid for r in list_remediations(uid_a))


# --- DELETE /api/gap/assessments/{id} (cascade) -----------------------------


def test_delete_assessment_requires_auth(tmp_path, monkeypatch):
    client, _token, _uid = _client_and_token(tmp_path, monkeypatch)
    res = client.delete("/api/gap/assessments/does-not-exist")
    assert res.status_code == 401


def test_delete_assessment_404_for_unknown(tmp_path, monkeypatch):
    client, token, _uid = _client_and_token(tmp_path, monkeypatch)
    res = client.delete("/api/gap/assessments/does-not-exist", headers=_auth(token))
    assert res.status_code == 404


def test_delete_assessment_cascades_to_remediations(tmp_path, monkeypatch):
    client, token, uid = _client_and_token(tmp_path, monkeypatch)
    from app.gap_analysis import run_gap_analysis
    from app.enterprise import list_remediations

    result = run_gap_analysis(
        framework_id="soc2",
        evidence="We use MFA for all admin access. No centralized logging in place.",
        title="SOC2 self-assessment",
        user_id=uid,
    )
    assessment_id = result["id"]

    # get_assessment endpoint sees it
    get_res = client.get(f"/api/gap/assessments/{assessment_id}", headers=_auth(token))
    assert get_res.status_code == 200

    rem_before = [r for r in list_remediations(uid) if r.get("assessment_id") == assessment_id]
    assert len(rem_before) > 0, "run_gap_analysis should auto-create remediation tasks for gaps"

    del_res = client.delete(f"/api/gap/assessments/{assessment_id}", headers=_auth(token))
    assert del_res.status_code == 200, del_res.text
    assert del_res.json()["ok"] is True

    # assessment itself is gone
    get_res2 = client.get(f"/api/gap/assessments/{assessment_id}", headers=_auth(token))
    assert get_res2.status_code == 404

    # cascade actually removed the linked remediation tasks, not just the
    # assessment row
    rem_after = [r for r in list_remediations(uid) if r.get("assessment_id") == assessment_id]
    assert rem_after == []

    del_res2 = client.delete(f"/api/gap/assessments/{assessment_id}", headers=_auth(token))
    assert del_res2.status_code == 404


def test_delete_assessment_scoped_to_owning_user(tmp_path, monkeypatch):
    client, token_a, uid_a = _client_and_token(tmp_path, monkeypatch, username="assess_owner_a")
    token_b, _uid_b = _register_and_login("assess_owner_b")
    from app.gap_analysis import run_gap_analysis

    result = run_gap_analysis(
        framework_id="soc2",
        evidence="Baseline evidence.",
        title="Owner A's assessment",
        user_id=uid_a,
    )
    assessment_id = result["id"]

    res = client.delete(f"/api/gap/assessments/{assessment_id}", headers=_auth(token_b))
    assert res.status_code == 404

    res2 = client.get(f"/api/gap/assessments/{assessment_id}", headers=_auth(token_a))
    assert res2.status_code == 200
