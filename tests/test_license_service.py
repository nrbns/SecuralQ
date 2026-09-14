"""Signed license service + enroll quota gate."""

from __future__ import annotations

import time

import pytest

from tests._http_test_utils import configure_isolated_settings


def _reload(monkeypatch, data_dir):
    return configure_isolated_settings(monkeypatch, data_dir)


def test_sign_and_verify_license_roundtrip(tmp_path, monkeypatch):
    _reload(monkeypatch, tmp_path)
    from app.agent_security import generate_ed25519_keypair
    from app.config import settings
    from app.license_service import (
        build_license_payload,
        issue_license,
        sign_license_payload,
        verify_signed_license,
    )

    kp = generate_ed25519_keypair()
    monkeypatch.setattr(settings, "license_ed25519_private_key", kp["private_b64"])
    monkeypatch.setattr(settings, "license_ed25519_public_key", kp["public_b64"])

    payload = build_license_payload(
        license_id="lic_test",
        organization_id="org_1",
        plan="pro",
        expires_at=time.time() + 86400,
    )
    signed = sign_license_payload(payload)
    ok, reason = verify_signed_license(signed)
    assert ok, reason
    assert signed["alg"] == "ed25519"
    assert signed["signature"]

    # Tamper max_agents
    tampered = dict(signed)
    tampered["payload"] = dict(payload)
    tampered["payload"]["max_agents"] = 999999
    ok2, reason2 = verify_signed_license(tampered)
    assert not ok2
    assert reason2 == "bad_signature"

    lic = issue_license("user_a", org_id="org_1", plan="pro")
    assert lic["id"].startswith("lic_")
    assert lic["plan"] == "pro"
    assert lic["max_agents"] == 100
    assert lic["signature"]
    ok3, _ = verify_signed_license(lic["signed"])
    assert ok3


def test_enroll_quota_soft_then_hard(tmp_path, monkeypatch):
    _reload(monkeypatch, tmp_path)
    from app.agent_security import generate_ed25519_keypair
    from app.agents import enroll_agent
    from app.config import settings
    from app.license_service import issue_license

    kp = generate_ed25519_keypair()
    monkeypatch.setattr(settings, "license_ed25519_private_key", kp["private_b64"])
    monkeypatch.setattr(settings, "license_ed25519_public_key", kp["public_b64"])
    monkeypatch.setattr(settings, "license_enforcement_enabled", False)

    issue_license("u1", plan="free", max_agents=2)
    enroll_agent("u1", name="a1")
    enroll_agent("u1", name="a2")
    # Soft: third still allowed when enforcement off
    enroll_agent("u1", name="a3")

    monkeypatch.setattr(settings, "license_enforcement_enabled", True)
    with pytest.raises(ValueError, match="agent_quota_exceeded"):
        enroll_agent("u1", name="a4")


def test_expired_grace_blocks_new_enroll_not_existing(tmp_path, monkeypatch):
    _reload(monkeypatch, tmp_path)
    from app.agent_security import generate_ed25519_keypair
    from app.agents import enroll_agent, list_agents
    from app.config import settings
    from app.license_service import evaluate_license_status, get_active_license, issue_license

    kp = generate_ed25519_keypair()
    monkeypatch.setattr(settings, "license_ed25519_private_key", kp["private_b64"])
    monkeypatch.setattr(settings, "license_ed25519_public_key", kp["public_b64"])
    monkeypatch.setattr(settings, "license_enforcement_enabled", True)

    past = time.time() - 3600
    issue_license("u2", plan="pro", max_agents=10, expires_at=past, grace_days=14)
    lic = get_active_license("u2")
    assert lic
    ok, reason = evaluate_license_status(lic)
    assert not ok
    assert reason == "expired_grace"

    # Existing agent created before expiry gate still listed; new enroll blocked
    monkeypatch.setattr(settings, "license_enforcement_enabled", False)
    enroll_agent("u2", name="existing")
    monkeypatch.setattr(settings, "license_enforcement_enabled", True)
    with pytest.raises(ValueError, match="license_expired_grace"):
        enroll_agent("u2", name="new")
    agents = list_agents("u2")
    assert any(a.get("name") == "existing" for a in agents)


def test_license_api_plans_and_issue(tmp_path, monkeypatch):
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
    register_user("lic_admin", "password123", role="admin")
    _u, token = login("lic_admin", "password123")

    app = FastAPI()
    app.include_router(router)
    client = TestClient(app)

    res = client.get("/api/licenses/plans")
    assert res.status_code == 200
    assert "pro" in res.json()["plans"]
    assert res.json()["plans"]["pro"]["max_agents"] == 100

    res = client.post(
        "/api/licenses/issue",
        json={"plan": "team"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert res.status_code == 200, res.text
    body = res.json()
    assert body["license"]["plan"] == "team"
    assert body["license"]["max_agents"] == 500
    assert body["entitlements"]["source"] == "signed_license"

    res = client.get(
        "/api/licenses/entitlements",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert res.status_code == 200
    assert res.json()["plan"] == "team"
    assert res.json()["enrollment_allowed"] is True
