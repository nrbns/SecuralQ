"""Commercial activation: validate, restricted mode, trial, activation cache."""

from __future__ import annotations

import time

from tests._http_test_utils import configure_isolated_settings


def _reload(monkeypatch, data_dir):
    return configure_isolated_settings(monkeypatch, data_dir)


def test_validate_and_restricted_mode(tmp_path, monkeypatch):
    _reload(monkeypatch, tmp_path)
    from app.agent_security import generate_ed25519_keypair
    from app.auth import register_user
    from app.config import settings
    from app.license_service import (
        effective_entitlements,
        issue_license,
        validate_license,
    )

    kp = generate_ed25519_keypair()
    monkeypatch.setattr(settings, "license_ed25519_private_key", kp["private_b64"])
    monkeypatch.setattr(settings, "license_ed25519_public_key", kp["public_b64"])
    monkeypatch.setattr(settings, "license_enforcement_enabled", True)

    u = register_user("lic_val", "password123")
    # Expired beyond grace → restricted (agents still allowed check-in; premium blocked)
    past = time.time() - (30 * 86400)
    issue_license(u.id, plan="pro", expires_at=past, grace_days=7)
    ent = effective_entitlements(u.id)
    assert ent["mode"] == "restricted"
    assert ent["allow_agent_checkin"] is True
    assert ent["allow_new_enrollment"] is False
    assert ent["allow_premium_writes"] is False
    assert "remediation" in (ent.get("features_blocked") or []) or "remediation" not in ent["features"]

    v = validate_license(u.id)
    assert v["valid"] is True  # agents not bricked
    assert v["activation_cache"]["schema"] == "securaiq.activation_cache.v1"
    assert v["activation_cache"].get("license_id")
    assert "signature" not in v["activation_cache"]  # signed blob stays server-side
    assert v["activation_cache"]["mode"] == "restricted"


def test_trial_and_validate_api(tmp_path, monkeypatch):
    _reload(monkeypatch, tmp_path)
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    from app.agent_security import generate_ed25519_keypair
    from app.auth import login, register_user
    from app.config import settings
    from app.license_api import router
    from app.tenancy import ensure_tenant_schema

    kp = generate_ed25519_keypair()
    monkeypatch.setattr(settings, "license_ed25519_private_key", kp["private_b64"])
    monkeypatch.setattr(settings, "license_ed25519_public_key", kp["public_b64"])

    ensure_tenant_schema()
    register_user("trial_admin", "password123", role="admin")
    _u, token = login("trial_admin", "password123")
    app = FastAPI()
    app.include_router(router)
    client = TestClient(app)
    headers = {"Authorization": f"Bearer {token}"}

    res = client.post("/api/licenses/trial", json={"plan": "pro", "days": 30}, headers=headers)
    assert res.status_code == 200, res.text
    body = res.json()
    assert body["license"]["plan"] == "pro"
    assert body["validation"]["mode"] in ("active", "warning", "critical")
    assert body["validation"]["days_remaining"] is not None
    assert body["validation"]["days_remaining"] <= 30

    res = client.post("/api/licenses/validate", headers=headers)
    assert res.status_code == 200
    assert res.json()["activation_cache"]["paths"]["linux_license_file"].startswith("/etc/securaiq")


def test_packages_deploy_metadata(tmp_path, monkeypatch):
    _reload(monkeypatch, tmp_path)
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    from app.auth import login, register_user
    from app.agents_api import router
    from app.tenancy import ensure_tenant_schema

    ensure_tenant_schema()
    register_user("pkg_admin", "password123", role="admin")
    _u, token = login("pkg_admin", "password123")
    app = FastAPI()
    app.include_router(router)
    client = TestClient(app)
    res = client.get("/api/agents/packages", headers={"Authorization": f"Bearer {token}"})
    assert res.status_code == 200
    data = res.json()
    assert "deploy" in data
    assert data["deploy"]["enroll_by_token_url"] == "/api/agents/enroll-by-token"
    assert "msi" in str(data.get("roadmap_packages", {})).lower()
