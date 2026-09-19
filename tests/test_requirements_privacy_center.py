"""Requirements first-class + Privacy Center depth + Command Center WHY chain."""

from __future__ import annotations

from tests._http_test_utils import configure_isolated_settings


def test_requirements_grouped_by_domain():
    from app.controls.requirements import get_requirement, list_requirements, requirements_index

    idx = requirements_index()
    assert idx["ok"] is True
    assert any(f["framework_id"] == "cmmc_l2" for f in idx["frameworks"])

    rows = list_requirements("cmmc_l2")
    assert len(rows) >= 5
    access = next((r for r in rows if "access" in (r["title"] or "").lower()), None)
    assert access is not None
    assert access["control_count"] >= 1
    assert access["id"].startswith("cmmc_l2:")

    detail = get_requirement("cmmc_l2", access["id"])
    assert detail is not None
    assert detail["controls"]
    assert "requirement" in detail["chain"]


def test_requirements_api(tmp_path, monkeypatch):
    configure_isolated_settings(monkeypatch, tmp_path)
    from fastapi.testclient import TestClient

    from app.auth import login, register_user
    from app.main import app
    from app.tenancy import ensure_tenant_schema

    ensure_tenant_schema()
    register_user("req_api_user", "password123", role="admin")
    user, token = login("req_api_user", "password123")
    client = TestClient(app)
    headers = {"Authorization": f"Bearer {token}"}
    r = client.get("/api/controls/requirements", headers=headers)
    assert r.status_code == 200
    assert r.json().get("ok") is True
    r2 = client.get("/api/controls/requirements/dpdp_rules_2025", headers=headers)
    assert r2.status_code == 200
    body = r2.json()
    assert body.get("count", 0) >= 1
    rid = body["requirements"][0]["id"]
    r3 = client.get(f"/api/controls/requirements/dpdp_rules_2025/{rid}", headers=headers)
    assert r3.status_code == 200
    assert r3.json()["requirement"]["id"] == rid


def test_dpdp_overview_privacy_center_sections(tmp_path, monkeypatch):
    configure_isolated_settings(monkeypatch, tmp_path)
    from app.auth import login, register_user
    from app.data_governance import dpdp_overview, upsert_processing_activity
    from app.tenancy import ensure_tenant_schema

    ensure_tenant_schema()
    register_user("privacy_depth", "password123", role="admin")
    user, _ = login("privacy_depth", "password123")
    upsert_processing_activity(
        user.id,
        {"name": "Account signup", "purpose": "service delivery", "lawful_basis": "consent"},
    )
    ov = dpdp_overview(user.id)
    assert ov["ok"] is True
    assert "activities" in ov["data_map"]
    assert "principal_requests" in ov["data_map"]
    assert "retention_policies" in ov["data_map"]
    assert "privacy_center" in ov
    assert "data_inventory" in ov["privacy_center"]["sections"]
    assert any(a.get("name") == "Account signup" for a in ov["data_map"]["activities"])
