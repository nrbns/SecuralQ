"""HTTP-layer tests for the SSP / POA&M / SPRS-preview routes added to
app/gap_api.py (backed by app.services.cmmc_documents)."""

from __future__ import annotations

from tests._http_test_utils import configure_isolated_settings


def _client_and_token(tmp_path, monkeypatch, username="cmmc_doc_http_tester"):
    configure_isolated_settings(monkeypatch, tmp_path)
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    from app.auth import login, register_user
    from app.gap_api import router as gap_router
    from app.tenancy import ensure_tenant_schema

    ensure_tenant_schema()
    register_user(username, "password123", role="admin")
    u, token = login(username, "password123")

    test_app = FastAPI()
    test_app.include_router(gap_router)
    client = TestClient(test_app)
    return client, token, u.id


def _auth(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


def test_ssp_requires_auth(tmp_path, monkeypatch):
    client, _token, _uid = _client_and_token(tmp_path, monkeypatch)
    res = client.get("/api/gap/assessments/whatever/ssp")
    assert res.status_code == 401


def test_poam_requires_auth(tmp_path, monkeypatch):
    client, _token, _uid = _client_and_token(tmp_path, monkeypatch)
    res = client.get("/api/gap/assessments/whatever/poam")
    assert res.status_code == 401


def test_ssp_404_for_unknown_assessment(tmp_path, monkeypatch):
    client, token, _uid = _client_and_token(tmp_path, monkeypatch)
    res = client.get("/api/gap/assessments/does-not-exist/ssp", headers=_auth(token))
    assert res.status_code == 404


def test_ssp_and_poam_over_http(tmp_path, monkeypatch):
    from app.gap_analysis import run_gap_analysis

    client, token, uid = _client_and_token(tmp_path, monkeypatch)
    assessment = run_gap_analysis(framework_id="cmmc_l2", evidence="", user_id=uid, title="http-test")

    ssp = client.get(f"/api/gap/assessments/{assessment['id']}/ssp", headers=_auth(token))
    assert ssp.status_code == 200
    assert "text/markdown" in ssp.headers["content-type"]
    assert "System Security Plan" in ssp.text

    poam = client.get(f"/api/gap/assessments/{assessment['id']}/poam", headers=_auth(token))
    assert poam.status_code == 200
    assert "Plan of Action" in poam.text


def test_sprs_preview_over_http_for_cmmc(tmp_path, monkeypatch):
    from app.gap_analysis import run_gap_analysis

    client, token, uid = _client_and_token(tmp_path, monkeypatch)
    assessment = run_gap_analysis(framework_id="cmmc_l2", evidence="", user_id=uid, title="t")

    res = client.get(f"/api/gap/assessments/{assessment['id']}/sprs-preview", headers=_auth(token))
    assert res.status_code == 200
    body = res.json()
    assert body["preview"]["max_score"] == 313


def test_sprs_preview_null_for_non_cmmc_framework(tmp_path, monkeypatch):
    from app.gap_analysis import run_gap_analysis

    client, token, uid = _client_and_token(tmp_path, monkeypatch)
    assessment = run_gap_analysis(framework_id="cis_controls", evidence="", user_id=uid, title="t")

    res = client.get(f"/api/gap/assessments/{assessment['id']}/sprs-preview", headers=_auth(token))
    assert res.status_code == 200
    assert res.json()["preview"] is None
