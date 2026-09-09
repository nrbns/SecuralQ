"""Continuous live-control fail queue + Fix with SecuraIQ remediations."""

from __future__ import annotations

from tests._http_test_utils import configure_isolated_settings


def _setup(monkeypatch, tmp_path, username="live_fail_tester"):
    configure_isolated_settings(monkeypatch, tmp_path)
    from app.auth import login, register_user
    from app.tenancy import ensure_tenant_schema

    ensure_tenant_schema()
    register_user(username, "password123", role="admin")
    u, _token = login(username, "password123")
    return u.id


def test_list_live_control_failures_ranks_and_reports(tmp_path, monkeypatch):
    from app.services.control_testing import list_live_control_failures

    uid = _setup(monkeypatch, tmp_path)
    live = list_live_control_failures(uid, record_evidence=False)
    assert "failures" in live
    assert live["tests_run"] >= 1
    assert "disclaimer" in live
    # Empty inventory → asset_inventory fails somewhere in mapped frameworks
    assert live["failing"] + live["partial"] + live["passing"] + live.get("unknown", 0) == live["tests_run"]
    scores = [f["risk_score"] for f in live["failures"]]
    assert scores == sorted(scores, reverse=True) or len(scores) <= 1


def test_create_remediations_from_live_failures(tmp_path, monkeypatch):
    from app.enterprise import create_remediations_from_live_failures, list_remediations
    from app.services.control_testing import list_live_control_failures

    uid = _setup(monkeypatch, tmp_path, username="live_fix_tester")
    live = list_live_control_failures(uid, record_evidence=False)
    created = create_remediations_from_live_failures(uid, live.get("failures") or [])
    assert isinstance(created, list)
    if live.get("failures"):
        assert len(created) >= 1
        open_rems = list_remediations(uid, status="open")
        assert any(r.get("control_id") for r in open_rems)
        # Second call dedupes open controls
        again = create_remediations_from_live_failures(uid, live.get("failures") or [])
        assert again == []


def test_compliance_overview_includes_continuous(tmp_path, monkeypatch):
    from app.services.compliance_center import compliance_overview

    uid = _setup(monkeypatch, tmp_path, username="cont_cc_tester")
    overview = compliance_overview(uid)
    assert "continuous" in overview
    cont = overview["continuous"]
    assert cont.get("label")
    assert "live_failures" in cont
    assert "tests_run" in cont
