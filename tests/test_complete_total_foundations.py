"""Complete-total foundations: billing downloads, capacity/HA honesty, agent cert install."""

from __future__ import annotations

from pathlib import Path

from tests._http_test_utils import configure_isolated_settings


def test_billing_downloads_uses_effective_entitlements(tmp_path, monkeypatch):
    configure_isolated_settings(monkeypatch, tmp_path)
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    from app.auth import login, register_user
    from app.billing_api import router
    from app.tenancy import ensure_tenant_schema

    ensure_tenant_schema()
    register_user("dl_user", "password123", role="user")
    _u, tok = login("dl_user", "password123")

    app = FastAPI()
    app.include_router(router)
    client = TestClient(app)
    res = client.get("/api/billing/downloads", headers={"Authorization": f"Bearer {tok}"})
    assert res.status_code == 200, res.text
    body = res.json()
    assert body.get("ok") is True
    assert "packages" in body
    assert body.get("download_base") == "/api/agents/packages"
    assert body.get("plan")


def test_billing_portal_requires_stripe(tmp_path, monkeypatch):
    configure_isolated_settings(monkeypatch, tmp_path)
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    from app.auth import login, register_user
    from app.billing_api import router
    from app.config import settings
    from app.tenancy import ensure_tenant_schema

    ensure_tenant_schema()
    monkeypatch.setattr(settings, "stripe_secret_key", "", raising=False)
    register_user("portal_user", "password123", role="user")
    _u, tok = login("portal_user", "password123")

    app = FastAPI()
    app.include_router(router)
    client = TestClient(app)
    res = client.post(
        "/api/billing/portal",
        headers={"Authorization": f"Bearer {tok}", "Content-Type": "application/json"},
        json={"return_url": "http://localhost:8080/"},
    )
    assert res.status_code == 501


def test_list_built_packages_public_alias(tmp_path, monkeypatch):
    configure_isolated_settings(monkeypatch, tmp_path)
    from app.agents_api import _list_built_packages, list_built_packages

    assert list_built_packages() == _list_built_packages()


def test_python_agent_install_client_certificate(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    # Point agent home at tmp by running install with patched _agent_home
    import scripts.securaiq_agent as agent

    monkeypatch.setattr(agent, "_agent_home", lambda: str(tmp_path))
    cert = "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----"
    key = "-----BEGIN PRIVATE KEY-----\nMIIE\n-----END PRIVATE KEY-----"
    cpath, kpath = agent.install_client_certificate(cert, key)
    assert Path(cpath).is_file()
    assert Path(kpath).is_file()
    assert "BEGIN CERTIFICATE" in Path(cpath).read_text(encoding="utf-8")

    monkeypatch.setenv("SECURAIQ_MTLS_CERT_PEM", cert)
    monkeypatch.setenv("SECURAIQ_MTLS_KEY_PEM", key)
    # Second install after wipe
    Path(cpath).unlink()
    Path(kpath).unlink()
    out = agent.maybe_install_client_certificate_from_env()
    assert out is not None
    assert "SECURAIQ_MTLS_KEY_PEM" not in __import__("os").environ


def test_sentinel_failover_dry_run():
    from scripts.sentinel_failover_measure import dry_run

    assert dry_run() == 0


def test_capacity_lab_doc_and_harness_flags():
    root = Path(__file__).resolve().parents[1]
    assert (root / "docs/ops/CAPACITY-LAB.md").is_file()
    text = (root / "scripts/realtime_load_test.py").read_text(encoding="utf-8")
    assert "--to-5k" in text
    assert "CAPACITY-LAB.md" in text
    assert "not claim" in text.lower() or "do not market 5k" in text.lower()


def test_license_activated_in_event_schema():
    from app.event_schema import EVENT_TYPE_REGISTRY

    assert "license.activated" in EVENT_TYPE_REGISTRY
    assert "entitlement.changed" in EVENT_TYPE_REGISTRY
    assert "license.updated" in EVENT_TYPE_REGISTRY
