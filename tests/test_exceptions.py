"""Tests for app.services.exceptions -- Compliance Exceptions. The one rule
under test throughout: no exception may exist without a real, bounded,
future expiry, and status changes (approve/reject/revoke) must be explicit,
auditable actions rather than generic field edits.
"""

from __future__ import annotations

import pytest

from tests._http_test_utils import configure_isolated_settings


def _setup(monkeypatch, tmp_path, username="exceptions_tester"):
    configure_isolated_settings(monkeypatch, tmp_path)
    from app.auth import login, register_user
    from app.tenancy import ensure_tenant_schema

    ensure_tenant_schema()
    register_user(username, "password123", role="admin")
    u, _token = login(username, "password123")
    return u.id


def _valid_kwargs(now_fn, **overrides):
    base = dict(
        title="Legacy VPN lacks MFA",
        reason="Vendor appliance does not support MFA until Q3 upgrade",
        risk_accepted="Medium residual risk of credential-stuffing against VPN",
        owner="ciso@example.com",
        expiry=now_fn() + 30 * 86400,
    )
    base.update(overrides)
    return base


def test_create_exception_requires_future_expiry(tmp_path, monkeypatch):
    from app.db import now
    from app.services.exceptions import create_exception

    uid = _setup(monkeypatch, tmp_path)
    with pytest.raises(ValueError, match="expiry"):
        create_exception(uid, **_valid_kwargs(now, expiry=now() - 86400))


def test_create_exception_requires_expiry_present(tmp_path, monkeypatch):
    from app.db import now
    from app.services.exceptions import create_exception

    uid = _setup(monkeypatch, tmp_path)
    kwargs = _valid_kwargs(now)
    del kwargs["expiry"]
    with pytest.raises(TypeError):
        create_exception(uid, **kwargs)


def test_create_exception_rejects_indefinite_grant(tmp_path, monkeypatch):
    from app.db import now
    from app.services.exceptions import MAX_EXCEPTION_DAYS, create_exception

    uid = _setup(monkeypatch, tmp_path)
    with pytest.raises(ValueError, match="365|days"):
        create_exception(uid, **_valid_kwargs(now, expiry=now() + (MAX_EXCEPTION_DAYS + 10) * 86400))


def test_create_exception_requires_owner_and_risk_accepted(tmp_path, monkeypatch):
    from app.db import now
    from app.services.exceptions import create_exception

    uid = _setup(monkeypatch, tmp_path)
    with pytest.raises(ValueError, match="owner"):
        create_exception(uid, **_valid_kwargs(now, owner=""))
    with pytest.raises(ValueError, match="risk_accepted"):
        create_exception(uid, **_valid_kwargs(now, risk_accepted=""))


def test_create_exception_defaults_to_pending_approval(tmp_path, monkeypatch):
    from app.db import now
    from app.services.exceptions import create_exception

    uid = _setup(monkeypatch, tmp_path)
    exc = create_exception(uid, **_valid_kwargs(now))
    assert exc["status"] == "pending_approval"
    assert exc["is_active_coverage"] is False  # not approved yet
    assert exc["expired"] is False


def test_approve_exception_sets_active_coverage(tmp_path, monkeypatch):
    from app.db import now
    from app.services.exceptions import approve_exception, create_exception

    uid = _setup(monkeypatch, tmp_path)
    exc = create_exception(uid, **_valid_kwargs(now))
    approved = approve_exception(uid, exc["id"], approved_by="ciso@example.com")
    assert approved["status"] == "approved"
    assert approved["approved_by"] == "ciso@example.com"
    assert approved["is_active_coverage"] is True


def test_approve_expired_exception_raises(tmp_path, monkeypatch):
    from app.db import get_conn, now
    from app.services.exceptions import approve_exception, create_exception

    uid = _setup(monkeypatch, tmp_path)
    exc = create_exception(uid, **_valid_kwargs(now))
    # Simulate time passing past expiry via direct SQL (mirrors the SLA-breach test pattern elsewhere).
    c = get_conn()
    c.execute("UPDATE securaiq_exceptions SET expiry = ? WHERE id = ?", (now() - 3600, exc["id"]))
    c.commit()
    with pytest.raises(ValueError, match="expiry"):
        approve_exception(uid, exc["id"], approved_by="ciso@example.com")


def test_reject_exception(tmp_path, monkeypatch):
    from app.db import now
    from app.services.exceptions import create_exception, reject_exception

    uid = _setup(monkeypatch, tmp_path)
    exc = create_exception(uid, **_valid_kwargs(now))
    rejected = reject_exception(uid, exc["id"], rejected_by="ciso@example.com", reason="Not sufficient")
    assert rejected["status"] == "rejected"
    assert rejected["rejected_reason"] == "Not sufficient"
    assert rejected["is_active_coverage"] is False


def test_revoke_approved_exception(tmp_path, monkeypatch):
    from app.db import now
    from app.services.exceptions import approve_exception, create_exception, revoke_exception

    uid = _setup(monkeypatch, tmp_path)
    exc = create_exception(uid, **_valid_kwargs(now))
    approve_exception(uid, exc["id"], approved_by="ciso@example.com")
    revoked = revoke_exception(uid, exc["id"], revoked_by="ciso@example.com")
    assert revoked["status"] == "revoked"
    assert revoked["is_active_coverage"] is False


def test_update_exception_rejects_bad_expiry(tmp_path, monkeypatch):
    from app.db import now
    from app.services.exceptions import create_exception, update_exception

    uid = _setup(monkeypatch, tmp_path)
    exc = create_exception(uid, **_valid_kwargs(now))
    with pytest.raises(ValueError, match="future"):
        update_exception(uid, exc["id"], {"expiry": now() - 100})


def test_update_exception_whitelists_fields(tmp_path, monkeypatch):
    from app.db import now
    from app.services.exceptions import create_exception, update_exception

    uid = _setup(monkeypatch, tmp_path)
    exc = create_exception(uid, **_valid_kwargs(now))
    updated = update_exception(uid, exc["id"], {"owner": "new-owner@example.com", "status": "approved"})
    assert updated["owner"] == "new-owner@example.com"
    assert updated["status"] == "pending_approval"  # status is NOT in the whitelist -- ignored


def test_delete_exception(tmp_path, monkeypatch):
    from app.db import now
    from app.services.exceptions import create_exception, delete_exception, get_exception

    uid = _setup(monkeypatch, tmp_path)
    exc = create_exception(uid, **_valid_kwargs(now))
    assert delete_exception(uid, exc["id"]) is True
    assert get_exception(uid, exc["id"]) is None
    assert delete_exception(uid, exc["id"]) is False


def test_list_exceptions_scoped_to_user(tmp_path, monkeypatch):
    from app.db import now
    from app.services.exceptions import create_exception, list_exceptions

    uid_a = _setup(monkeypatch, tmp_path, username="exc_owner_a")
    from app.auth import login, register_user

    register_user("exc_owner_b", "password123", role="admin")
    uid_b, _t = login("exc_owner_b", "password123")
    create_exception(uid_a, **_valid_kwargs(now))
    assert len(list_exceptions(uid_a)) == 1
    assert len(list_exceptions(uid_b.id)) == 0


def test_exceptions_summary_counts(tmp_path, monkeypatch):
    from app.db import now
    from app.services.exceptions import approve_exception, create_exception, exceptions_summary

    uid = _setup(monkeypatch, tmp_path)
    e1 = create_exception(uid, **_valid_kwargs(now, title="Exc 1"))
    create_exception(uid, **_valid_kwargs(now, title="Exc 2"))
    approve_exception(uid, e1["id"], approved_by="ciso@example.com")

    summary = exceptions_summary(uid)
    assert summary["total"] == 2
    assert summary["by_status"]["approved"] == 1
    assert summary["by_status"]["pending_approval"] == 1
    assert summary["active_coverage"] == 1


def test_exceptions_summary_expiring_soon(tmp_path, monkeypatch):
    from app.db import now
    from app.services.exceptions import approve_exception, create_exception, exceptions_summary

    uid = _setup(monkeypatch, tmp_path)
    soon = create_exception(uid, **_valid_kwargs(now, title="Expiring soon", expiry=now() + 5 * 86400))
    approve_exception(uid, soon["id"], approved_by="ciso@example.com")
    summary = exceptions_summary(uid)
    assert summary["expiring_soon_30d"] == 1


def test_create_exception_records_evidence(tmp_path, monkeypatch):
    from app.db import now
    from app.services.evidence import get_evidence_for
    from app.services.exceptions import create_exception

    uid = _setup(monkeypatch, tmp_path)
    exc = create_exception(uid, **_valid_kwargs(now))
    trail = get_evidence_for(uid, entity_type="compliance_exception", entity_id=exc["id"])
    assert len(trail) == 1
    assert trail[0]["source"] == "declared"
