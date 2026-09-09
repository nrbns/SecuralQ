"""Live SSP (Sprint 6, docs/control-config-engine.md) — real-data snapshot,
recomputed every call, never a cached/manually-edited document."""

from __future__ import annotations

from tests._http_test_utils import configure_isolated_settings


def _setup(monkeypatch, tmp_path, username="ssp_tester"):
    configure_isolated_settings(monkeypatch, tmp_path)
    from app.auth import register_user

    user = register_user(username, "Sup3rSecret!", role="admin")
    return user.id


def test_live_ssp_snapshot_empty_environment(tmp_path, monkeypatch):
    uid = _setup(monkeypatch, tmp_path)
    from app.services.live_ssp import live_ssp_snapshot

    snap = live_ssp_snapshot(uid, "cmmc_l2")
    assert snap["framework_id"] == "cmmc_l2"
    assert snap["controls_total"] == 110
    assert len(snap["controls"]) == 110
    assert snap["environment"]["total_assets"] == 0
    # No assessment yet -> every control not_assessed, no invented status.
    assert snap["counts"]["not_assessed"] == 110
    for c in snap["controls"]:
        assert c["evidence_status"] == "not_assessed"
        assert c["live_status"] is None
    assert "disclaimer" in snap


def test_live_ssp_reflects_real_assets_and_evidence(tmp_path, monkeypatch):
    uid = _setup(monkeypatch, tmp_path)
    from app.enterprise import create_asset
    from app.gap_analysis import run_gap_analysis
    from app.services.live_ssp import live_ssp_snapshot

    create_asset(uid, "Domain Controller", asset_type="server", cmmc_asset_category="cui_asset")
    create_asset(uid, "MFA Gateway", asset_type="network", cmmc_asset_category="spa")

    run_gap_analysis(
        framework_id="cmmc_l2",
        evidence="access control least privilege authorized users multi-factor authentication",
        user_id=uid,
        title="live ssp test",
    )

    snap = live_ssp_snapshot(uid, "cmmc_l2")
    assert snap["environment"]["total_assets"] == 2
    scope_cats = {row["category"] for row in snap["environment"]["cmmc_scope"]}
    assert "cui_asset" in scope_cats and "spa" in scope_cats
    assert snap["assessment_id"] is not None
    # At least one control should now be scored from real evidence, not all not_assessed.
    assert snap["counts"]["not_assessed"] < 110


def test_live_ssp_control_detail_not_found(tmp_path, monkeypatch):
    uid = _setup(monkeypatch, tmp_path)
    from app.services.live_ssp import live_ssp_control_detail

    assert live_ssp_control_detail(uid, "cmmc_l2", "NOT.A.REAL-CONTROL") is None


def test_live_ssp_control_detail_real_control(tmp_path, monkeypatch):
    uid = _setup(monkeypatch, tmp_path)
    from app.services.live_ssp import live_ssp_control_detail

    detail = live_ssp_control_detail(uid, "cmmc_l2", "AC.L2-3.1.1")
    assert detail is not None
    assert detail["control_id"] == "AC.L2-3.1.1"
    assert detail["evidence_status"] == "not_assessed"
    assert detail["poam_eligible"] is False  # sprs_weight 5 control
    assert "disclaimer" in detail


def _client_and_token(tmp_path, monkeypatch, username="ssp_http_tester"):
    configure_isolated_settings(monkeypatch, tmp_path)
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    from app.auth import login, register_user
    from app.live_ssp_api import router as live_ssp_router
    from app.tenancy import ensure_tenant_schema

    ensure_tenant_schema()
    register_user(username, "password123", role="admin")
    _u, token = login(username, "password123")

    test_app = FastAPI()
    test_app.include_router(live_ssp_router)
    client = TestClient(test_app)
    return client, token


def _auth(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


def test_live_ssp_http_requires_auth(tmp_path, monkeypatch):
    client, _token = _client_and_token(tmp_path, monkeypatch)
    res = client.get("/api/compliance/ssp/cmmc_l2/live")
    assert res.status_code in (401, 403)


def test_live_ssp_http_returns_snapshot(tmp_path, monkeypatch):
    client, token = _client_and_token(tmp_path, monkeypatch)
    res = client.get("/api/compliance/ssp/cmmc_l2/live", headers=_auth(token))
    assert res.status_code == 200
    body = res.json()
    assert body["framework_id"] == "cmmc_l2"
    assert body["controls_total"] == 110


def test_live_ssp_http_control_detail(tmp_path, monkeypatch):
    client, token = _client_and_token(tmp_path, monkeypatch)
    res = client.get("/api/compliance/ssp/cmmc_l2/live/AC.L2-3.1.1", headers=_auth(token))
    assert res.status_code == 200
    assert res.json()["control_id"] == "AC.L2-3.1.1"


def test_live_ssp_http_control_detail_not_found(tmp_path, monkeypatch):
    client, token = _client_and_token(tmp_path, monkeypatch)
    res = client.get(
        "/api/compliance/ssp/cmmc_l2/live/NOT.A.REAL-CONTROL", headers=_auth(token)
    )
    assert res.status_code == 404


def test_live_ssp_http_unknown_framework(tmp_path, monkeypatch):
    client, token = _client_and_token(tmp_path, monkeypatch)
    res = client.get(
        "/api/compliance/ssp/not_a_real_framework/live",
        headers=_auth(token),
    )
    assert res.status_code == 404
