"""HTTP-layer tests for the framework-generic /report, /action-plan, and
/document-profile routes added to app/gap_api.py (backed by
app.services.compliance_documents)."""

from __future__ import annotations

from tests._http_test_utils import configure_isolated_settings


def _client_and_token(tmp_path, monkeypatch, username="compliance_doc_http_tester"):
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


def test_report_requires_auth(tmp_path, monkeypatch):
    client, _token, _uid = _client_and_token(tmp_path, monkeypatch)
    res = client.get("/api/gap/assessments/whatever/report")
    assert res.status_code == 401


def test_report_404_for_unknown_assessment(tmp_path, monkeypatch):
    client, token, _uid = _client_and_token(tmp_path, monkeypatch)
    res = client.get("/api/gap/assessments/does-not-exist/report", headers=_auth(token))
    assert res.status_code == 404


def test_document_profile_matches_framework(tmp_path, monkeypatch):
    from app.gap_analysis import run_gap_analysis

    client, token, uid = _client_and_token(tmp_path, monkeypatch)
    assessment = run_gap_analysis(framework_id="hipaa", evidence="", user_id=uid, title="t")

    res = client.get(f"/api/gap/assessments/{assessment['id']}/document-profile", headers=_auth(token))
    assert res.status_code == 200
    body = res.json()
    assert body["report_kind"] == "Security Risk Assessment (SRA) Report"
    assert body["plan_kind"] == "Corrective Action Plan"


def test_report_and_action_plan_over_http_for_iso27001(tmp_path, monkeypatch):
    from app.gap_analysis import run_gap_analysis

    client, token, uid = _client_and_token(tmp_path, monkeypatch)
    assessment = run_gap_analysis(framework_id="iso27001", evidence="", user_id=uid, title="http-test")

    report = client.get(f"/api/gap/assessments/{assessment['id']}/report", headers=_auth(token))
    assert report.status_code == 200
    assert "text/markdown" in report.headers["content-type"]
    assert "Statement of Applicability" in report.text

    plan = client.get(f"/api/gap/assessments/{assessment['id']}/action-plan", headers=_auth(token))
    assert plan.status_code == 200
    assert "Corrective Action Plan" in plan.text


def test_report_over_http_for_pci_dss(tmp_path, monkeypatch):
    from app.gap_analysis import run_gap_analysis

    client, token, uid = _client_and_token(tmp_path, monkeypatch)
    assessment = run_gap_analysis(framework_id="pci_dss", evidence="", user_id=uid, title="t")

    report = client.get(f"/api/gap/assessments/{assessment['id']}/report", headers=_auth(token))
    assert report.status_code == 200
    assert "PCI DSS Compliance Readiness Report" in report.text
