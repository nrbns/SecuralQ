"""MFA recovery codes, mandatory policy, Argon2 passwords, Stripe→license."""

from __future__ import annotations

import time

import pytest

from tests._http_test_utils import configure_isolated_settings


def _reload(monkeypatch, data_dir):
    return configure_isolated_settings(monkeypatch, data_dir)


def _totp_now(secret: str) -> str:
    from app.mfa import _decode_secret, totp_at

    return totp_at(_decode_secret(secret), counter=int(time.time()) // 30)


def test_mfa_confirm_issues_hashed_recovery_and_login(tmp_path, monkeypatch):
    _reload(monkeypatch, tmp_path)
    from app.auth import login, register_user
    from app.mfa import mfa_enroll_confirm, mfa_enroll_start, mfa_status

    u = register_user("mfa_user", "password123")
    enroll = mfa_enroll_start(u.id, username=u.username)
    out = mfa_enroll_confirm(u.id, _totp_now(enroll["secret"]))
    assert out["mfa_enabled"] is True
    codes = out["recovery_codes"]
    assert len(codes) == 10
    assert mfa_status(u.id)["recovery_codes_remaining"] == 10

    # Password alone → MFA challenge
    step = login("mfa_user", "password123")
    assert isinstance(step, dict) and step.get("mfa_required")

    from app.auth import complete_mfa_login

    user, token = complete_mfa_login(step["mfa_token"], recovery_code=codes[0])
    assert user.username == "mfa_user"
    assert token
    assert mfa_status(u.id)["recovery_codes_remaining"] == 9

    # Used code cannot be reused
    step2 = login("mfa_user", "password123")
    with pytest.raises(ValueError, match="Invalid recovery"):
        complete_mfa_login(step2["mfa_token"], recovery_code=codes[0])


def test_mfa_mandatory_blocks_disable_and_api(tmp_path, monkeypatch):
    _reload(monkeypatch, tmp_path)
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    from app.auth import AuthUser, login, register_user
    from app.commercial_api import router
    from app.config import settings
    from app.mfa import mfa_disable
    from app.tenancy import ensure_tenant_schema

    monkeypatch.setattr(settings, "mfa_required", True)
    ensure_tenant_schema()
    register_user("need_mfa", "password123", role="user")
    user, token = login("need_mfa", "password123")
    assert isinstance(user, AuthUser)

    app = FastAPI()
    app.include_router(router)
    client = TestClient(app)
    headers = {"Authorization": f"Bearer {token}"}

    # Without MFA enrolled, protected API is blocked
    res = client.get("/api/chats", headers=headers)
    assert res.status_code == 403, res.text
    assert "MFA enrollment required" in res.json()["detail"]

    # Enroll is allowed (exempt path)
    res = client.post("/api/auth/mfa/enroll", headers=headers)
    assert res.status_code == 200
    secret = res.json()["secret"]
    res = client.post(
        "/api/auth/mfa/confirm",
        headers={**headers, "Content-Type": "application/json"},
        json={"code": _totp_now(secret)},
    )
    assert res.status_code == 200
    assert res.json()["recovery_codes"]

    res = client.get("/api/chats", headers=headers)
    assert res.status_code == 200, res.text

    with pytest.raises(ValueError, match="mandatory"):
        mfa_disable(user.id, _totp_now(secret), role="user")


def test_mfa_rate_limit(tmp_path, monkeypatch):
    _reload(monkeypatch, tmp_path)
    from app.auth import register_user
    from app.mfa import (
        _MFA_FAIL_MAX,
        mfa_enroll_confirm,
        mfa_enroll_start,
        mfa_rate_limited,
        record_mfa_attempt,
        verify_mfa_factor,
    )

    u = register_user("rate_mfa", "password123")
    enroll = mfa_enroll_start(u.id, username=u.username)
    mfa_enroll_confirm(u.id, _totp_now(enroll["secret"]))
    for _ in range(_MFA_FAIL_MAX):
        record_mfa_attempt(u.id, success=False, kind="totp")
    assert mfa_rate_limited(u.id)
    with pytest.raises(ValueError, match="Too many MFA"):
        verify_mfa_factor(u.id, totp="000000")


def test_password_hash_argon2_or_pbkdf2(tmp_path, monkeypatch):
    _reload(monkeypatch, tmp_path)
    from app.auth import hash_password, verify_password

    h = hash_password("super-secret-pass")
    assert verify_password("super-secret-pass", h)
    assert not verify_password("wrong", h)
    # Prefer argon2 when package present
    try:
        import argon2  # noqa: F401

        assert h.startswith("$argon2")
    except ImportError:
        assert h.startswith("pbkdf2$")


def test_stripe_checkout_completed_issues_license(tmp_path, monkeypatch):
    _reload(monkeypatch, tmp_path)
    from app.agent_security import generate_ed25519_keypair
    from app.auth import register_user
    from app.billing import get_user_plan
    from app.billing_stripe import apply_checkout_completed
    from app.config import settings
    from app.license_service import get_active_license

    kp = generate_ed25519_keypair()
    monkeypatch.setattr(settings, "license_ed25519_private_key", kp["private_b64"])
    monkeypatch.setattr(settings, "license_ed25519_public_key", kp["public_b64"])

    u = register_user("buyer@example.com", "password123", email="buyer@example.com")
    result = apply_checkout_completed(
        {
            "metadata": {"plan": "pro", "user_id": u.id},
            "customer_email": "buyer@example.com",
        }
    )
    assert result["ok"] is True
    assert get_user_plan(u.id) == "pro"
    lic = get_active_license(u.id)
    assert lic and lic["plan"] == "pro"
    assert lic["max_agents"] == 100
