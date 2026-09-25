"""Lab-closable product leftovers: trust, service accounts, onboarding, ROI, lineage."""

from __future__ import annotations

from tests._http_test_utils import configure_isolated_settings


def test_trust_center_and_service_account(tmp_path, monkeypatch):
    configure_isolated_settings(monkeypatch, tmp_path)
    from app.auth import register_user
    from app.db import init_schema
    from app.product_close import onboarding_progress, roi_metrics, tamper_status
    from app.service_accounts import (
        create_service_account,
        list_service_accounts,
        revoke_service_account,
        rotate_service_account,
    )
    from app.tenancy import ensure_tenant_schema
    from app.trust_center import trust_center_payload

    init_schema()
    ensure_tenant_schema()
    u = register_user("sa_close", "password123")
    raw, meta = create_service_account(u.id, "ci-bot", ["read:assets", "read:risk"])
    assert raw.startswith("sa_")
    assert meta["kind"] == "service_account"
    assert "read:assets" in meta["scopes"]
    listed = list_service_accounts(u.id)
    assert listed and listed[0]["active"] is True
    rotated = rotate_service_account(u.id, meta["id"])
    assert rotated and rotated[0].startswith("sa_")
    assert revoke_service_account(u.id, rotated[1]["id"]) is True

    trust = trust_center_payload()
    assert trust["ok"] is True
    assert "honesty" in trust
    assert trust["claims"]["ev_authenticode"] is False

    tamper = tamper_status(u.id)
    assert "audit_chain_ok" in tamper
    onboard = onboarding_progress(u.id)
    assert onboard["total"] == 6
    assert {s["id"] for s in onboard["steps"]} == {
        "org",
        "agent",
        "asset",
        "frameworks",
        "risk",
        "pulse",
    }
    roi = roi_metrics(u.id)
    assert roi["ok"] is True
    assert "disclaimer" in roi


def test_evidence_lineage_records(tmp_path, monkeypatch):
    configure_isolated_settings(monkeypatch, tmp_path)
    from app.auth import register_user
    from app.db import init_schema
    from app.evidence_spine.vault import _access
    from app.product_close import list_evidence_lineage
    from app.tenancy import ensure_tenant_schema

    init_schema()
    ensure_tenant_schema()
    u = register_user("lineage_u", "password123")
    _access(u.id, evidence_id="ev1", action="read", detail="test")
    rows = list_evidence_lineage(u.id)
    assert rows and rows[0]["action"] == "read"
