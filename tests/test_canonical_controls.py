"""Tests for app.services.canonical_controls -- the cross-framework control
engine. Every status assertion checks that the computed value comes from a
real gap assessment, never a static/theoretical guess."""

from __future__ import annotations

from tests._http_test_utils import configure_isolated_settings


def _setup(monkeypatch, tmp_path, username="canon_tester"):
    configure_isolated_settings(monkeypatch, tmp_path)
    from app.auth import login, register_user
    from app.tenancy import ensure_tenant_schema

    ensure_tenant_schema()
    register_user(username, "password123", role="admin")
    u, _token = login(username, "password123")
    return u.id


def test_list_canonical_controls():
    from app.services.canonical_controls import list_canonical_controls

    ccs = list_canonical_controls()
    assert len(ccs) >= 20
    ids = {c["id"] for c in ccs}
    assert "mfa" in ids


def test_get_canonical_control():
    from app.services.canonical_controls import get_canonical_control

    mfa = get_canonical_control("mfa")
    assert mfa is not None
    assert mfa["name"] == "Multi-Factor Authentication"
    assert "cmmc_l2" in mfa["frameworks"]

    assert get_canonical_control("does-not-exist") is None


def test_canonical_controls_for_reverse_lookup():
    from app.services.canonical_controls import canonical_controls_for

    # IA.L2-3.5.3 is cmmc_l2's real MFA control per the registry
    result = canonical_controls_for("cmmc_l2", "IA.L2-3.5.3")
    assert any(c["id"] == "mfa" for c in result)

    # case-insensitive match
    result_lower = canonical_controls_for("cmmc_l2", "ia.l2-3.5.3")
    assert any(c["id"] == "mfa" for c in result_lower)

    # a control not in the registry maps to nothing
    assert canonical_controls_for("cmmc_l2", "AC.L2-3.1.99") == []


def test_status_not_assessed_when_no_assessment_exists(tmp_path, monkeypatch):
    from app.services.canonical_controls import compute_canonical_status

    uid = _setup(monkeypatch, tmp_path)
    status = compute_canonical_status(uid, "mfa")
    assert status is not None
    assert status["overall_status"] == "not_assessed"
    assert status["frameworks_assessed"] == 0
    for fw_detail in status["frameworks"].values():
        assert fw_detail["status"] == "not_assessed"
        assert fw_detail["has_assessment"] is False


def test_status_reflects_real_assessment_data(tmp_path, monkeypatch):
    """Run a real cmmc_l2 assessment with evidence that implements the real
    MFA control, then confirm the canonical status reflects it -- computed
    from the actual scored result, not guessed."""
    from app.gap_analysis import load_framework, run_gap_analysis
    from app.services.canonical_controls import compute_canonical_status

    uid = _setup(monkeypatch, tmp_path)
    fw = load_framework("cmmc_l2")
    mfa_control = next(c for c in fw["controls"] if c["id"] == "IA.L2-3.5.3")
    evidence = f"{mfa_control['title']} {' '.join(mfa_control['keywords'])}"

    assessment = run_gap_analysis(framework_id="cmmc_l2", evidence=evidence, user_id=uid, title="mfa-test")
    implemented = next(r for r in assessment["results"] if r["control_id"] == "IA.L2-3.5.3")
    assert implemented["status"] == "implemented"

    status = compute_canonical_status(uid, "mfa")
    assert status["frameworks"]["cmmc_l2"]["status"] == "implemented"
    assert status["frameworks"]["cmmc_l2"]["has_assessment"] is True
    assert status["frameworks_satisfied"] >= 1
    # other mapped frameworks have no assessment yet -- must say so honestly
    assert status["frameworks"]["iso27001"]["status"] == "not_assessed"
    # overall_status is computed only over frameworks actually assessed so far
    # (1 of N here, and that one is fully satisfied) -- frameworks_total_mapped
    # vs frameworks_assessed lets the UI show "implemented (1 of N assessed)".
    assert status["overall_status"] == "implemented"
    assert status["frameworks_assessed"] == 1
    assert status["frameworks_total_mapped"] > 1


def test_status_missing_when_control_not_implemented(tmp_path, monkeypatch):
    from app.gap_analysis import run_gap_analysis
    from app.services.canonical_controls import compute_canonical_status

    uid = _setup(monkeypatch, tmp_path)
    run_gap_analysis(framework_id="cmmc_l2", evidence="", user_id=uid, title="empty")

    status = compute_canonical_status(uid, "mfa")
    assert status["frameworks"]["cmmc_l2"]["status"] == "missing"
    assert status["frameworks"]["cmmc_l2"]["has_assessment"] is True
    assert status["frameworks_satisfied"] == 0
    assert status["overall_status"] == "missing"


def test_compute_status_returns_none_for_unknown_canonical_control(tmp_path, monkeypatch):
    from app.services.canonical_controls import compute_canonical_status

    uid = _setup(monkeypatch, tmp_path)
    assert compute_canonical_status(uid, "does-not-exist") is None


def test_compute_all_canonical_statuses(tmp_path, monkeypatch):
    from app.services.canonical_controls import compute_all_canonical_statuses, list_canonical_controls

    uid = _setup(monkeypatch, tmp_path)
    statuses = compute_all_canonical_statuses(uid)
    assert len(statuses) == len(list_canonical_controls())
    assert all(s["overall_status"] == "not_assessed" for s in statuses)


def test_live_signal_none_for_canonical_control_without_a_live_source(tmp_path, monkeypatch):
    """Most canonical controls (e.g. backup_recovery) have no real telemetry
    source yet -- live_signal must say so honestly, never fabricate one."""
    from app.services.canonical_controls import compute_canonical_status

    uid = _setup(monkeypatch, tmp_path)
    status = compute_canonical_status(uid, "backup_recovery")
    assert status["live_signal"] is None


def test_live_signal_mfa_coverage_reflects_real_user_accounts(tmp_path, monkeypatch):
    """MFA live signal is computed from real users.mfa_enabled rows, not
    guessed -- a freshly registered admin has MFA disabled by default, so
    coverage must honestly report a gap on the highest-privilege account."""
    from app.services.canonical_controls import compute_canonical_status

    uid = _setup(monkeypatch, tmp_path)
    status = compute_canonical_status(uid, "mfa")
    live = status["live_signal"]
    assert live is not None
    assert live["test"] == "mfa_coverage"
    assert live["detail"]["total_users"] >= 1
    assert live["detail"]["admins_without_mfa"] >= 1
    assert live["status"] in ("partial", "fail")


def test_live_signal_mfa_coverage_passes_once_enabled(tmp_path, monkeypatch):
    import time

    from app.mfa import _decode_secret, mfa_enroll_confirm, mfa_enroll_start, totp_at
    from app.services.canonical_controls import compute_canonical_status

    uid = _setup(monkeypatch, tmp_path, username="mfa_pass_tester")
    enroll = mfa_enroll_start(uid, username="mfa_pass_tester")
    code = totp_at(_decode_secret(enroll["secret"]), counter=int(time.time()) // 30)
    mfa_enroll_confirm(uid, code)

    status = compute_canonical_status(uid, "mfa")
    live = status["live_signal"]
    assert live["status"] == "pass"
    assert live["detail"]["admins_without_mfa"] == 0


def test_live_signal_logging_monitoring_fails_with_no_agents(tmp_path, monkeypatch):
    from app.services.canonical_controls import compute_canonical_status

    uid = _setup(monkeypatch, tmp_path)
    status = compute_canonical_status(uid, "logging_monitoring")
    live = status["live_signal"]
    assert live is not None
    assert live["test"] == "logging_monitoring"
    assert live["status"] == "fail"
    assert live["detail"]["total_agents"] == 0


def test_live_signal_reuses_control_testing_for_asset_and_vuln_canonical_controls(tmp_path, monkeypatch):
    """asset_inventory/vulnerability_management canonical ids reuse the exact
    same test functions as app.services.control_testing -- one real signal,
    surfaced at both the per-framework-control layer and the cross-framework
    canonical layer, never two independently-computed answers to the same
    question."""
    from app.services.canonical_controls import compute_canonical_status
    from app.services.control_testing import TEST_ASSET_INVENTORY, run_live_test

    uid = _setup(monkeypatch, tmp_path)
    direct = run_live_test(uid, TEST_ASSET_INVENTORY)
    status = compute_canonical_status(uid, "asset_inventory")
    live = status["live_signal"]
    assert live["test"] == direct["test"]
    assert live["status"] == direct["status"]
    assert live["detail"] == direct["detail"]
