"""Packaging scaffolds, signed updates, /api/v1 alias, agent license validate."""

from __future__ import annotations

from pathlib import Path

from tests._http_test_utils import configure_isolated_settings


def _reload(monkeypatch, data_dir):
    return configure_isolated_settings(monkeypatch, data_dir)


def test_api_v1_alias_rewrites_path(tmp_path, monkeypatch):
    _reload(monkeypatch, tmp_path)
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from starlette.middleware.base import BaseHTTPMiddleware
    from starlette.requests import Request

    from app.api_v1 import ApiV1AliasMiddleware

    seen: dict[str, str] = {}

    class Capture(BaseHTTPMiddleware):
        async def dispatch(self, request: Request, call_next):
            seen["path"] = request.scope.get("path") or ""
            return await call_next(request)

    app = FastAPI()

    @app.get("/api/ping")
    async def ping():
        return {"ok": True}

    # Capture added first, ApiV1 last → ApiV1 runs first (Starlette reverse order)
    app.add_middleware(Capture)
    app.add_middleware(ApiV1AliasMiddleware)

    client = TestClient(app)
    res = client.get("/api/v1/ping")
    assert res.status_code == 200, res.text
    assert seen.get("path") == "/api/ping"


def test_upgrade_payload_has_signature_and_rollback_fields(tmp_path, monkeypatch):
    _reload(monkeypatch, tmp_path)
    from app.agent_security import generate_ed25519_keypair
    from app.agent_updates import publish_script_release, upgrade_payload_from_latest
    from app.config import settings

    kp = generate_ed25519_keypair()
    monkeypatch.setattr(settings, "agent_ed25519_private_key", kp["private_b64"])
    monkeypatch.setattr(settings, "agent_ed25519_public_key", kp["public_b64"])

    row = publish_script_release(version="9.9.9", notes="test", previous_sha256="abc")
    assert row.get("signature")
    payload = upgrade_payload_from_latest()
    assert payload["expected_sha256"]
    assert payload["signature"]
    assert payload["previous_sha256"] == "abc"
    assert payload.get("signing_public_key")
    assert payload.get("download_url")


def test_agent_license_validate_endpoint(tmp_path, monkeypatch):
    _reload(monkeypatch, tmp_path)
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    from app.agents import enroll_agent
    from app.agents_api import router
    from app.tenancy import ensure_tenant_schema

    ensure_tenant_schema()
    enrolled = enroll_agent("local", name="lic-agent")
    token = f"{enrolled['agent_id']}.{enrolled['agent_key']}"
    app = FastAPI()
    app.include_router(router)
    client = TestClient(app)
    res = client.post(
        "/api/agents/license/validate",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert res.status_code == 200, res.text
    body = res.json()
    assert "activation_cache" in body
    assert body["activation_cache"]["schema"] == "securaiq.activation_cache.v1"
    assert body.get("agent_id") == enrolled["agent_id"]


def test_packages_roadmap_msi_scaffold_hint(tmp_path, monkeypatch):
    _reload(monkeypatch, tmp_path)
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    from app.auth import login, register_user
    from app.agents_api import router
    from app.tenancy import ensure_tenant_schema

    ensure_tenant_schema()
    register_user("pkg2_admin", "password123", role="admin")
    _u, token = login("pkg2_admin", "password123")
    app = FastAPI()
    app.include_router(router)
    client = TestClient(app)
    res = client.get("/api/agents/packages", headers={"Authorization": f"Bearer {token}"})
    assert res.status_code == 200
    data = res.json()
    assert data["deploy"]["agent_license_validate_url"] == "/api/agents/license/validate"
    assert data["deploy"]["updates_latest_url"] == "/api/agents/updates/latest"
    win = data["roadmap_packages"]["windows"]
    assert any(x.get("kind") == "msi" and "build_msi" in str(x.get("build_hint", "")) for x in win)


def test_packaging_scripts_exist():
    root = Path(__file__).resolve().parents[1]
    for rel in (
        "scripts/packaging/wix/SecuraIQAgent.wxs",
        "scripts/packaging/build_msi.ps1",
        "scripts/packaging/build_deb.sh",
        "scripts/packaging/build_rpm.sh",
    ):
        assert (root / rel).is_file(), rel


def test_mtls_enroll_issues_cert_when_enabled(tmp_path, monkeypatch):
    _reload(monkeypatch, tmp_path)
    from app.agents import enroll_agent
    from app.config import settings

    monkeypatch.setattr(settings, "agent_mtls_enabled", True)
    monkeypatch.setattr(settings, "agent_mtls_cert_days", 30)
    out = enroll_agent("local", name="mtls-agent")
    assert out.get("mtls")
    assert "BEGIN CERTIFICATE" in (out["mtls"].get("certificate_pem") or "")
    assert "BEGIN PRIVATE KEY" in (out["mtls"].get("private_key_pem") or "")
    assert out["mtls"].get("fingerprint")
