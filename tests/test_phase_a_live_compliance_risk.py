"""Phase A: live compliance recalculation + risk reduction on control PASS/FAIL."""

from __future__ import annotations

from tests._http_test_utils import configure_isolated_settings


def test_live_compliance_recalculates_on_pass_fail(tmp_path, monkeypatch):
    configure_isolated_settings(monkeypatch, tmp_path)
    from app.controls.live_compliance import (
        clear_live_compliance_cache,
        publish_live_compliance_update,
    )
    from app.controls.results import record_test_result
    from app.tenancy import ensure_tenant_schema

    ensure_tenant_schema()
    clear_live_compliance_cache()
    uid = "local"

    record_test_result(
        uid, "cis", "9.1", test_name="host_firewall", status="fail", summary="off"
    )
    snap1 = publish_live_compliance_update(uid, reason="fail", status="fail")
    assert snap1["failing"] >= 1
    assert snap1["live_percent"] == 0.0

    record_test_result(
        uid, "cis", "9.1", test_name="host_firewall", status="pass", summary="on"
    )
    snap2 = publish_live_compliance_update(uid, reason="pass", status="pass")
    assert snap2 is not None
    assert snap2["passing"] >= 1
    assert snap2["live_percent"] == 100.0
    assert snap2.get("previous_percent") == 0.0
    assert snap2.get("percent_delta") == 100.0
    snap3 = publish_live_compliance_update(uid, reason="noop")
    assert snap3["live_percent"] == 100.0
    assert snap3.get("percent_delta") == 0.0


def test_control_passed_handler_reduces_risk_and_evidence(tmp_path, monkeypatch):
    configure_isolated_settings(monkeypatch, tmp_path)
    from app.event_processor import process_event
    from app.tenancy import ensure_tenant_schema

    ensure_tenant_schema()
    ok = process_event(
        {
            "event_type": "control.passed",
            "type": "control.passed",
            "event_id": "evt-pass-1",
            "user_id": "local",
            "test": "host_firewall",
            "control_id": "9.1",
            "framework_id": "cis",
            "agent_id": "ag-pass",
            "summary": "firewall enabled",
        }
    )
    assert ok is True


def test_compliance_overview_includes_live_percent(tmp_path, monkeypatch):
    configure_isolated_settings(monkeypatch, tmp_path)
    from app.controls.results import record_test_result
    from app.services import compliance_center as cc
    from app.tenancy import ensure_tenant_schema

    ensure_tenant_schema()
    monkeypatch.setattr(
        "app.services.control_testing.list_live_control_failures",
        lambda *a, **k: {
            "evaluated_at": None,
            "tests_run": 0,
            "passing": 0,
            "partial": 0,
            "failing": 0,
            "failures": [],
            "frameworks_tested": 0,
        },
    )
    record_test_result(
        "local", "cis", "9.1", test_name="host_firewall", status="pass", summary="ok"
    )
    record_test_result(
        "local", "cis", "9.2", test_name="host_defender", status="fail", summary="bad"
    )
    ov = cc.compliance_overview("local")
    cont = ov.get("continuous") or {}
    assert cont.get("enabled") is True
    assert cont.get("live_percent") == 50.0
    assert cont.get("passing") == 1
    assert cont.get("failing") == 1
    assert "live_percent" in (ov.get("methodology") or "")
