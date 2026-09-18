"""Tests for Microsoft Sentinel outbound SIEM forwarding
(app.connectors.azure_sentinel + GET/POST /api/logs/siem/*).

Real logic under test: is_configured() reflects exactly what's set (no
partial-credential false positive), and the HTTP routes report status
without ever claiming "connected" absent a real round trip. Live network
calls to login.microsoftonline.com / *.ingest.monitor.azure.com are not
exercised here (no real Azure tenant in CI) — that's what /siem/azure/test
is for, when an operator actually configures it.
"""

from __future__ import annotations

from tests._http_test_utils import configure_isolated_settings


def _client_and_token(tmp_path, monkeypatch, username="siem_tester"):
    configure_isolated_settings(monkeypatch, tmp_path)
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    from app.auth import login, register_user
    from app.log_management_api import router as log_router
    from app.tenancy import ensure_tenant_schema

    ensure_tenant_schema()
    register_user(username, "password123", role="admin")
    u, token = login(username, "password123")

    test_app = FastAPI()
    test_app.include_router(log_router)
    client = TestClient(test_app)
    return client, token, u.id


def _auth(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


def test_azure_sentinel_not_configured_by_default(monkeypatch):
    from app.connectors import azure_sentinel

    monkeypatch.setattr(azure_sentinel.settings, "siem_azure_dce_url", "", raising=False)
    monkeypatch.setattr(azure_sentinel.settings, "siem_azure_dcr_immutable_id", "", raising=False)
    monkeypatch.setattr(azure_sentinel.settings, "siem_azure_tenant_id", "", raising=False)
    monkeypatch.setattr(azure_sentinel.settings, "azure_tenant_id", "", raising=False)
    assert azure_sentinel.is_configured() is False


def test_azure_sentinel_requires_all_fields(monkeypatch):
    from app.connectors import azure_sentinel

    monkeypatch.setattr(azure_sentinel.settings, "siem_azure_dce_url", "https://x.ingest.monitor.azure.com", raising=False)
    monkeypatch.setattr(azure_sentinel.settings, "siem_azure_dcr_immutable_id", "", raising=False)
    monkeypatch.setattr(azure_sentinel.settings, "siem_azure_tenant_id", "tenant", raising=False)
    monkeypatch.setattr(azure_sentinel.settings, "siem_azure_client_id", "client", raising=False)
    monkeypatch.setattr(azure_sentinel.settings, "siem_azure_client_secret", "secret", raising=False)
    # Missing DCR immutable id -> still not configured
    assert azure_sentinel.is_configured() is False


def test_azure_sentinel_configured_when_complete(monkeypatch):
    from app.connectors import azure_sentinel

    monkeypatch.setattr(azure_sentinel.settings, "siem_azure_dce_url", "https://x.ingest.monitor.azure.com", raising=False)
    monkeypatch.setattr(azure_sentinel.settings, "siem_azure_dcr_immutable_id", "dcr-abc123", raising=False)
    monkeypatch.setattr(azure_sentinel.settings, "siem_azure_tenant_id", "tenant", raising=False)
    monkeypatch.setattr(azure_sentinel.settings, "siem_azure_client_id", "client", raising=False)
    monkeypatch.setattr(azure_sentinel.settings, "siem_azure_client_secret", "secret", raising=False)
    assert azure_sentinel.is_configured() is True


def test_azure_sentinel_falls_back_to_cloud_posture_azure_app(monkeypatch):
    """Tenant/client/secret fall back to the Azure Defender app registration
    fields when the SIEM-specific ones are left blank, so an operator using
    one Entra app for both doesn't have to type the same values twice."""
    from app.connectors import azure_sentinel

    monkeypatch.setattr(azure_sentinel.settings, "siem_azure_dce_url", "https://x.ingest.monitor.azure.com", raising=False)
    monkeypatch.setattr(azure_sentinel.settings, "siem_azure_dcr_immutable_id", "dcr-abc123", raising=False)
    monkeypatch.setattr(azure_sentinel.settings, "siem_azure_tenant_id", "", raising=False)
    monkeypatch.setattr(azure_sentinel.settings, "siem_azure_client_id", "", raising=False)
    monkeypatch.setattr(azure_sentinel.settings, "siem_azure_client_secret", "", raising=False)
    monkeypatch.setattr(azure_sentinel.settings, "azure_tenant_id", "shared-tenant", raising=False)
    monkeypatch.setattr(azure_sentinel.settings, "azure_client_id", "shared-client", raising=False)
    monkeypatch.setattr(azure_sentinel.settings, "azure_client_secret", "shared-secret", raising=False)
    assert azure_sentinel.is_configured() is True


def test_logs_siem_status_requires_auth(tmp_path, monkeypatch):
    client, _token, _uid = _client_and_token(tmp_path, monkeypatch)
    res = client.get("/api/logs/siem/status")
    assert res.status_code == 401


def test_logs_siem_status_reports_disabled_by_default(tmp_path, monkeypatch):
    client, token, _uid = _client_and_token(tmp_path, monkeypatch)
    res = client.get("/api/logs/siem/status", headers=_auth(token))
    assert res.status_code == 200, res.text
    body = res.json()
    assert body["azure_sentinel"]["enabled"] is False
    assert body["azure_sentinel"]["configured"] is False


def test_azure_test_route_reports_not_configured(tmp_path, monkeypatch):
    client, token, _uid = _client_and_token(tmp_path, monkeypatch)
    from app.connectors import azure_sentinel

    monkeypatch.setattr(azure_sentinel.settings, "siem_azure_dce_url", "", raising=False)
    monkeypatch.setattr(azure_sentinel.settings, "siem_azure_dcr_immutable_id", "", raising=False)
    res = client.post("/api/logs/siem/azure/test", headers=_auth(token))
    assert res.status_code == 200
    assert res.json()["ok"] is False
    assert res.json()["error"] == "not_configured"
