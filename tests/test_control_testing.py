"""Tests for app.services.control_testing -- Live Control Testing, which
computes a control's status directly from real product data instead of
relying only on pasted evidence text. Every test result must be a real,
reproducible read of actual assets/vulnerabilities/patch-inventory rows,
never a fabricated status.
"""

from __future__ import annotations

from tests._http_test_utils import configure_isolated_settings


def _setup(monkeypatch, tmp_path, username="control_test_tester"):
    configure_isolated_settings(monkeypatch, tmp_path)
    from app.auth import login, register_user
    from app.tenancy import ensure_tenant_schema

    ensure_tenant_schema()
    register_user(username, "password123", role="admin")
    u, _token = login(username, "password123")
    return u.id


def test_controls_with_live_tests_only_returns_mapped_controls():
    from app.services.control_testing import controls_with_live_tests

    cis_tested = controls_with_live_tests("cis_controls")
    assert "CIS-1" in cis_tested
    assert "CIS-7" in cis_tested
    assert "CIS-3" not in cis_tested  # Data Protection has no live test mapped

    assert controls_with_live_tests("owasp_top10") == set()  # no mappings for this framework at all


def test_asset_inventory_test_fails_with_no_assets(tmp_path, monkeypatch):
    from app.services.control_testing import run_live_test

    uid = _setup(monkeypatch, tmp_path)
    result = run_live_test(uid, "asset_inventory")
    assert result["status"] == "fail"
    assert result["detail"]["total_assets"] == 0


def test_asset_inventory_test_partial_when_no_agent_coverage(tmp_path, monkeypatch):
    from app.enterprise import create_asset
    from app.services.control_testing import run_live_test

    uid = _setup(monkeypatch, tmp_path)
    create_asset(uid, "MANUAL-01", asset_type="web")
    create_asset(uid, "MANUAL-02", asset_type="web")

    result = run_live_test(uid, "asset_inventory")
    assert result["status"] == "partial"
    assert result["detail"]["total_assets"] == 2
    assert result["detail"]["agent_covered"] == 0


def test_asset_inventory_test_passes_with_agent_coverage(tmp_path, monkeypatch):
    from app.agents import checkin, enroll_agent
    from app.enterprise import create_asset
    from app.services.control_testing import run_live_test

    uid = _setup(monkeypatch, tmp_path)
    create_asset(uid, "AGENT-HOST", asset_type="server")
    agent = enroll_agent(uid, name="ct-agent")
    checkin(agent["agent_id"], {"hostname": "AGENT-HOST", "os": "linux"})

    result = run_live_test(uid, "asset_inventory")
    assert result["status"] == "pass"
    assert result["detail"]["agent_covered"] == 1


def test_vulnerability_management_fails_with_no_vulns(tmp_path, monkeypatch):
    from app.services.control_testing import run_live_test

    uid = _setup(monkeypatch, tmp_path)
    result = run_live_test(uid, "vulnerability_management")
    assert result["status"] == "fail"
    assert result["detail"]["total"] == 0


def test_vulnerability_management_passes_within_sla(tmp_path, monkeypatch):
    from app.enterprise import create_asset, create_vulnerability
    from app.services.control_testing import run_live_test

    uid = _setup(monkeypatch, tmp_path)
    a = create_asset(uid, "VM-01", asset_type="web")
    create_vulnerability(
        uid, {"asset_id": a["id"], "asset_name": "VM-01", "title": "Recent finding", "severity": "critical", "status": "open"}
    )
    result = run_live_test(uid, "vulnerability_management")
    assert result["status"] == "pass"
    assert result["detail"]["sla_breaches"] == 0


def test_vulnerability_management_flags_sla_breach(tmp_path, monkeypatch):
    from app.db import get_conn, now
    from app.enterprise import create_asset, create_vulnerability
    from app.services.control_testing import run_live_test, _CRITICAL_SLA_DAYS

    uid = _setup(monkeypatch, tmp_path)
    a = create_asset(uid, "VM-02", asset_type="web")
    v = create_vulnerability(
        uid, {"asset_id": a["id"], "asset_name": "VM-02", "title": "Old finding", "severity": "critical", "status": "open"}
    )
    c = get_conn()
    old_ts = now() - (_CRITICAL_SLA_DAYS + 5) * 86400
    c.execute("UPDATE vulnerabilities SET created_at = ? WHERE id = ?", (old_ts, v["id"]))
    c.commit()

    result = run_live_test(uid, "vulnerability_management")
    assert result["status"] in ("partial", "fail")
    assert result["detail"]["sla_breaches"] == 1


def test_patch_management_fails_with_no_inventory(tmp_path, monkeypatch):
    from app.services.control_testing import run_live_test

    uid = _setup(monkeypatch, tmp_path)
    result = run_live_test(uid, "patch_management")
    assert result["status"] == "fail"


def test_run_live_test_unknown_name_returns_none(tmp_path, monkeypatch):
    from app.services.control_testing import run_live_test

    uid = _setup(monkeypatch, tmp_path)
    assert run_live_test(uid, "not_a_real_test") is None


def test_run_live_tests_for_control_records_evidence(tmp_path, monkeypatch):
    from app.enterprise import create_asset
    from app.services.control_testing import run_live_tests_for_control
    from app.services.evidence import get_evidence_for

    uid = _setup(monkeypatch, tmp_path)
    create_asset(uid, "EV-01", asset_type="web")

    results = run_live_tests_for_control(uid, "cis_controls", "CIS-1")
    assert len(results) == 1
    assert results[0]["test"] == "asset_inventory"

    trail = get_evidence_for(uid, entity_type="control_test", entity_id="cis_controls:CIS-1")
    assert len(trail) == 1
    assert trail[0]["source"] == "derived"


def test_run_live_tests_for_control_no_mapping_returns_empty(tmp_path, monkeypatch):
    from app.services.control_testing import run_live_tests_for_control

    uid = _setup(monkeypatch, tmp_path)
    assert run_live_tests_for_control(uid, "cis_controls", "CIS-3") == []


def test_control_with_two_mapped_tests_returns_both(tmp_path, monkeypatch):
    from app.services.control_testing import run_live_tests_for_control

    uid = _setup(monkeypatch, tmp_path)
    results = run_live_tests_for_control(uid, "cis_controls", "CIS-7")
    names = {r["test"] for r in results}
    assert names == {"vulnerability_management", "patch_management"}


def test_run_live_tests_for_framework_covers_all_mapped_controls(tmp_path, monkeypatch):
    from app.services.control_testing import controls_with_live_tests, run_live_tests_for_framework

    uid = _setup(monkeypatch, tmp_path)
    out = run_live_tests_for_framework(uid, "cis_controls")
    assert set(out.keys()) == controls_with_live_tests("cis_controls")


def test_run_gap_analysis_attaches_live_tests_without_overriding_declared_status(tmp_path, monkeypatch):
    """The pasted-evidence status/confidence must stay exactly what the
    heuristic computed -- live_tests is an additive, separate field."""
    from app.gap_analysis import run_gap_analysis

    uid = _setup(monkeypatch, tmp_path)
    result = run_gap_analysis(framework_id="cis_controls", evidence="", user_id=uid, title="t")
    cis1 = next(r for r in result["results"] if r["control_id"] == "CIS-1")
    assert cis1["status"] == "missing"  # no pasted evidence -> heuristic says missing
    assert cis1["live_tests"]
    assert cis1["live_tests"][0]["test"] == "asset_inventory"
    assert cis1["live_tests"][0]["status"] == "fail"  # no real assets either, in this test

    cis3 = next(r for r in result["results"] if r["control_id"] == "CIS-3")
    assert cis3["live_tests"] == []  # no live test mapped to this control
