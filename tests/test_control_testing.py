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


def test_host_firewall_fail_when_disabled():
    from app.services.control_testing import evaluate_host_firewall_payload

    r = evaluate_host_firewall_payload(
        {"firewall_status": {"collected": True, "enabled": False, "backend": "ufw"}},
        agent_id="a1",
        asset_id="as1",
    )
    assert r["status"] == "fail"
    assert r["test"] == "host_firewall"
    assert r["source"] == "securaiq_agent"
    assert r["agent_id"] == "a1"


def test_host_firewall_pass_when_enabled():
    from app.services.control_testing import evaluate_host_firewall_payload

    r = evaluate_host_firewall_payload(
        {"firewall_status": {"collected": True, "enabled": True, "backend": "ufw"}},
        agent_id="a1",
    )
    assert r["status"] == "pass"


def test_host_firewall_unknown_when_not_collected():
    from app.services.control_testing import evaluate_host_firewall_payload

    r = evaluate_host_firewall_payload({"firewall_status": {"collected": False, "enabled": None}})
    assert r["status"] == "unknown"


def test_host_defender_fail_when_realtime_off():
    from app.services.control_testing import evaluate_host_defender_payload

    r = evaluate_host_defender_payload(
        {
            "os": "Windows",
            "defender_status": {
                "collected": True,
                "antivirus_enabled": True,
                "realtime_protection_enabled": False,
            },
        },
        os_name="Windows",
    )
    assert r["status"] == "fail"


def test_host_ssh_root_fail_on_permit_yes():
    from app.services.control_testing import evaluate_host_ssh_root_payload

    r = evaluate_host_ssh_root_payload(
        {"ssh_config": {"collected": True, "settings": {"PermitRootLogin": "yes"}}}
    )
    assert r["status"] == "fail"


def test_host_ssh_root_pass_on_permit_no():
    from app.services.control_testing import evaluate_host_ssh_root_payload

    r = evaluate_host_ssh_root_payload(
        {"ssh_config": {"collected": True, "settings": {"PermitRootLogin": "no"}}}
    )
    assert r["status"] == "pass"


def test_evaluate_agent_host_controls_firewall_loop_and_checkin_safe(tmp_path, monkeypatch):
    """FAIL → remediation stub → re-check PASS; check-in must not raise."""
    from app.agents import checkin, enroll_agent
    from app.enterprise import list_remediations
    from app.services.control_testing import evaluate_agent_host_controls
    from app.services.evidence import get_evidence_for

    uid = _setup(monkeypatch, tmp_path, username="host_ctrl_tester")
    agent = enroll_agent(uid, name="fw-agent")
    aid = agent["agent_id"]

    disabled = {
        "hostname": "fw-host",
        "os": "linux",
        "firewall_status": {"collected": True, "enabled": False, "backend": "ufw"},
        "defender_status": {"collected": False, "reason": "Not applicable on linux"},
        "ssh_config": {"collected": True, "settings": {"PermitRootLogin": "no"}},
    }
    out = evaluate_agent_host_controls(uid, aid, disabled, asset_id="")
    assert out["ok"] is True
    fw = next(r for r in out["results"] if r["test"] == "host_firewall")
    assert fw["status"] == "fail"
    assert out.get("remediation_id") or any(
        "host_firewall" in (r.get("notes") or "") or "host_firewall" in (r.get("recommendation") or "")
        for r in list_remediations(uid, status="open")
    )
    trail = get_evidence_for(uid, entity_type="agent_host_control", entity_id=f"{aid}:host_firewall")
    assert trail
    assert trail[0]["source"] == "observed"

    enabled = {
        **disabled,
        "firewall_status": {"collected": True, "enabled": True, "backend": "ufw"},
    }
    out2 = evaluate_agent_host_controls(uid, aid, enabled, asset_id="")
    fw2 = next(r for r in out2["results"] if r["test"] == "host_firewall")
    assert fw2["status"] == "pass"

    # Check-in hook must not raise even if evaluator misbehaves
    def _boom(*_a, **_k):
        raise RuntimeError("simulated evaluator failure")

    monkeypatch.setattr(
        "app.services.control_testing.evaluate_agent_host_controls", _boom
    )
    result = checkin(aid, enabled)
    assert result["ok"] is True


def test_list_live_failures_includes_host_firewall_when_agent_online(tmp_path, monkeypatch):
    from app.agents import checkin, enroll_agent
    from app.services.control_testing import list_live_control_failures

    uid = _setup(monkeypatch, tmp_path, username="host_live_fail")
    agent = enroll_agent(uid, name="live-fw")
    checkin(
        agent["agent_id"],
        {
            "hostname": "live-fw-host",
            "os": "linux",
            "firewall_status": {"collected": True, "enabled": False, "backend": "ufw"},
            "defender_status": {"collected": False},
            "ssh_config": {"collected": False},
        },
    )
    live = list_live_control_failures(uid, record_evidence=False, framework_ids=["cis_controls"])
    fw_fails = [f for f in live["failures"] if f.get("test") == "host_firewall"]
    assert fw_fails
    assert fw_fails[0]["status"] == "fail"
    assert fw_fails[0]["control_id"] == "CIS-12"

def test_host_ssh_root_fail_opens_poam_and_pass_closes(tmp_path, monkeypatch):
    """Sprint 4/5 — non-firewall host FAIL also opens POA&M stub; PASS closes."""
    from app.agents import enroll_agent
    from app.controls.poam import poam_marker
    from app.enterprise import list_remediations
    from app.services.control_testing import evaluate_agent_host_controls

    uid = _setup(monkeypatch, tmp_path, username="poam_ssh_tester")
    agent = enroll_agent(uid, name="ssh-agent")
    aid = agent["agent_id"]
    bad = {
        "hostname": "ssh-host",
        "os": "linux",
        "firewall_status": {"collected": True, "enabled": True, "backend": "ufw"},
        "defender_status": {"collected": False, "reason": "Not applicable on linux"},
        "ssh_config": {"collected": True, "settings": {"PermitRootLogin": "yes"}},
    }
    out = evaluate_agent_host_controls(uid, aid, bad)
    assert out["ok"] is True
    ssh = next(r for r in out["results"] if r["test"] == "host_ssh_root")
    assert ssh["status"] == "fail"
    marker = poam_marker("host_ssh_root", aid)
    assert any(
        marker in (r.get("notes") or "") or marker in (r.get("recommendation") or "")
        for r in list_remediations(uid, status="open")
    )

    good = {
        **bad,
        "ssh_config": {"collected": True, "settings": {"PermitRootLogin": "no"}},
    }
    out2 = evaluate_agent_host_controls(uid, aid, good)
    ssh2 = next(r for r in out2["results"] if r["test"] == "host_ssh_root")
    assert ssh2["status"] == "pass"
    assert not any(
        marker in (r.get("notes") or "") or marker in (r.get("recommendation") or "")
        for r in list_remediations(uid, status="open")
    )
