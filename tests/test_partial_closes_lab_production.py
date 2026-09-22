"""Lab-production closes for remaining Partial control-plane areas."""

from __future__ import annotations

import pytest

from tests._http_test_utils import configure_isolated_settings


def test_compliance_ops_l3_escalation_and_summary(tmp_path, monkeypatch):
    configure_isolated_settings(monkeypatch, tmp_path)
    import time

    from app.auth import login, register_user
    from app.compliance_ops import create_task, get_task
    from app.compliance_ops.automation import run_compliance_ops_tick
    from app.db import get_conn, now
    from app.tenancy import ensure_tenant_schema

    ensure_tenant_schema()
    register_user("esc_l3", "password123", role="admin")
    user, _ = login("esc_l3", "password123")
    past = time.time() - 15 * 86400
    task = create_task(
        user.id,
        {
            "title": "Deep overdue review",
            "department": "IT",
            "due_at": past,
            "evidence_required": False,
            "manager_id": user.id,
            "priority": "medium",
        },
    )
    get_conn().execute(
        "UPDATE compliance_tasks SET overdue_notified = 1, escalation_level = 2, "
        "last_escalated_at = ? WHERE id = ?",
        (now() - 20 * 3600, task["id"]),
    )
    get_conn().commit()
    out = run_compliance_ops_tick(user.id, materialize=False)
    assert out["ok"] is True
    assert "escalation_summary" in out
    refreshed = get_task(user.id, task["id"])
    assert int(refreshed.get("escalation_level") or 0) >= 3
    assert (refreshed.get("priority") or "").lower() == "critical"


def test_cmmc_tier1_lab_readiness(tmp_path, monkeypatch):
    configure_isolated_settings(monkeypatch, tmp_path)
    from app.auth import login, register_user
    from app.cmmc.tier1_lab import tier1_lab_readiness
    from app.tenancy import ensure_tenant_schema

    ensure_tenant_schema()
    register_user("cmmc_t1", "password123", role="admin")
    user, _ = login("cmmc_t1", "password123")
    out = tier1_lab_readiness(user.id)
    assert out["c3pao_submit"] is False
    assert out["sprs_submit"] is False
    assert out["checks"]["audit_pack"]["ok"] is True
    assert out["checks"]["sprs_prep"]["ok"] is True
    assert out["lab_production"] is True


def test_object_store_org_fail_closed(tmp_path, monkeypatch):
    configure_isolated_settings(monkeypatch, tmp_path)
    from app.auth import login, register_user
    from app.commercial_ext import create_org
    from app.object_storage import assert_key_belongs_to_org, evidence_key, get_bytes_for_org, put_bytes
    from app.tenancy import ensure_tenant_schema
    from app.uploads import save_upload

    ensure_tenant_schema()
    register_user("os_a", "password123", role="user")
    register_user("os_b", "password123", role="user")
    alice, _ = login("os_a", "password123")
    bob, _ = login("os_b", "password123")
    org_a = create_org(alice.id, "OrgA-OS")
    org_b = create_org(bob.id, "OrgB-OS")
    up = save_upload(alice.id, "secret.txt", b"alice-blob", ingest=False)
    assert up.get("org_id") == org_a["id"]
    key = evidence_key(org_a["id"], up["id"], "secret.txt")
    put_bytes(key, b"alice-blob")
    assert get_bytes_for_org(org_a["id"], key) == b"alice-blob"
    with pytest.raises(PermissionError):
        assert_key_belongs_to_org(key, org_b["id"])
    with pytest.raises(PermissionError):
        get_bytes_for_org(org_b["id"], key)


def test_oidc_and_idp_readiness_facades(tmp_path, monkeypatch):
    configure_isolated_settings(monkeypatch, tmp_path)
    from app.oidc import status as oidc_status
    from app.saml_scaffold import status as saml_status

    o = oidc_status()
    assert o["protocol"] == "oidc"
    assert "production_ready" in o
    assert o["configured"] is False  # lab default
    s = saml_status()
    assert s["protocol"] == "saml2"


def test_audit_sealed_export_and_tamper_detect(tmp_path, monkeypatch):
    configure_isolated_settings(monkeypatch, tmp_path)
    from app.audit_chain import append_chained, export_sealed_snapshot, verify_chain
    from app.db import get_conn

    append_chained("lab_action", "u1", {"k": 1})
    append_chained("lab_action", "u1", {"k": 2})
    seal = export_sealed_snapshot(limit=1000)
    assert seal["ok"] is True
    assert seal["worm"] is False
    assert seal["seal_hash"]
    # Mutate a row → chain breaks
    get_conn().execute(
        "UPDATE audit_log SET detail = ? WHERE action = ?",
        ('{"k": 99}', "lab_action"),
    )
    get_conn().commit()
    broken = verify_chain(limit=1000)
    assert broken["ok"] is False


def test_soft_checkin_ladder_250_500(tmp_path, monkeypatch):
    configure_isolated_settings(monkeypatch, tmp_path)
    from app.auth import login, register_user
    from app.capacity_soft import soft_checkin_ladder
    from app.tenancy import ensure_tenant_schema

    ensure_tenant_schema()
    register_user("cap_soft", "password123", role="admin")
    user, _ = login("cap_soft", "password123")
    # Keep CI fast: 25/50 stand in for ladder shape; production soft uses 100/250/500
    out = soft_checkin_ladder(user.id, rungs=[25, 50])
    assert out["ok"] is True
    assert out["http_500_measured"] is False
    assert all(r["success_pct"] == 100.0 for r in out["rungs"])


def test_self_security_dogfood_report(tmp_path, monkeypatch):
    configure_isolated_settings(monkeypatch, tmp_path)
    from app.self_security import generate_dogfood_report, latest_dogfood_report

    # Skip live Bandit in unit test for speed/availability
    report = generate_dogfood_report(run_scan=False)
    assert report.get("id")
    assert "markdown" in report
    latest = latest_dogfood_report()
    assert latest is not None
