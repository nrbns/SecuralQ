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
    assert "CIS-3" in cis_tested  # host_disk_encryption
    assert "CIS-12" in cis_tested  # host_firewall

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
    assert run_live_tests_for_control(uid, "cis_controls", "CIS-2") == []


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
    assert cis3["live_tests"]
    assert cis3["live_tests"][0]["test"] == "host_disk_encryption"

    cis2 = next(r for r in result["results"] if r["control_id"] == "CIS-2")
    assert cis2["live_tests"] == []  # no live test mapped to this control


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


def test_host_disk_encryption_fail_when_not_encrypted():
    from app.services.control_testing import evaluate_host_disk_encryption_payload

    r = evaluate_host_disk_encryption_payload(
        {
            "disk_encryption_status": {
                "collected": True,
                "encrypted": False,
                "backend": "bitlocker",
            }
        }
    )
    assert r["test"] == "host_disk_encryption"
    assert r["status"] == "fail"


def test_host_disk_encryption_pass_when_encrypted():
    from app.services.control_testing import evaluate_host_disk_encryption_payload

    r = evaluate_host_disk_encryption_payload(
        {
            "disk_encryption_status": {
                "collected": True,
                "encrypted": True,
                "backend": "luks",
            }
        }
    )
    assert r["status"] == "pass"


def test_host_disk_encryption_unknown_when_not_collected():
    from app.services.control_testing import evaluate_host_disk_encryption_payload

    r = evaluate_host_disk_encryption_payload(
        {"disk_encryption_status": {"collected": False, "encrypted": None, "reason": "lsblk unavailable"}}
    )
    assert r["status"] == "unknown"


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
    # Control Center KPIs read securaiq_control_test_results — must persist on check-in path.
    from app.controls.results import get_results_for_control

    cmmc_rows = get_results_for_control(uid, "cmmc_l2", "SC.L2-3.13.1")
    assert any(r.get("test_name") == "host_firewall" and r.get("status") == "fail" for r in cmmc_rows)

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


def test_control_test_registry_loads_firewall_bindings():
    """Registry is the single source of truth for host_firewall control maps."""
    from app.controls.test_registry import (
        TEST_HOST_DISK_ENCRYPTION,
        TEST_HOST_FIREWALL,
        build_control_test_map,
        get_test_entry,
    )
    from app.services.control_testing import _CONTROL_TEST_MAP

    entry = get_test_entry(TEST_HOST_FIREWALL)
    assert entry is not None
    assert entry["frequency"] == "checkin"
    assert entry["verifiability"] == "machine"
    bindings = {(b[0], b[1]) for b in entry["control_bindings"]}
    assert ("cis_controls", "CIS-12") in bindings
    assert ("cmmc_l2", "SC.L2-3.13.1") in bindings
    assert ("nist_800_171", "3.13.1") in bindings

    derived = build_control_test_map()
    assert derived[("cis_controls", "CIS-12")] == [TEST_HOST_FIREWALL]
    assert _CONTROL_TEST_MAP[("cis_controls", "CIS-12")] == [TEST_HOST_FIREWALL]
    assert _CONTROL_TEST_MAP[("cmmc_l2", "SC.L2-3.13.1")] == [TEST_HOST_FIREWALL]

    disk = get_test_entry(TEST_HOST_DISK_ENCRYPTION)
    assert disk is not None
    assert disk["frequency"] == "checkin"
    disk_bindings = {(b[0], b[1]) for b in disk["control_bindings"]}
    assert ("cmmc_l2", "SC.L2-3.13.16") in disk_bindings
    assert ("nist_800_171", "3.13.16") in disk_bindings
    assert _CONTROL_TEST_MAP[("cmmc_l2", "SC.L2-3.13.16")] == [TEST_HOST_DISK_ENCRYPTION]


def test_open_poam_from_aggregate_fail_uses_agents_list(tmp_path, monkeypatch):
    """failing_agents is an int on aggregate results; open from detail.agents FAIL rows."""
    from app.controls.poam import open_poam_from_control_fail_result, poam_marker
    from app.enterprise import list_remediations

    uid = _setup(monkeypatch, tmp_path, username="poam_agg_user")
    opened = open_poam_from_control_fail_result(
        uid,
        framework_id="cmmc_l2",
        control_id="SC.L2-3.13.16",
        result={
            "test": "host_disk_encryption",
            "status": "fail",
            "summary": "1 of 1 online agent(s) failed",
            "detail": {
                "failing_agents": 1,
                "agents": [
                    {
                        "agent_id": "agt-disk-1",
                        "hostname": "lab-disk",
                        "status": "fail",
                    },
                    {
                        "agent_id": "agt-ok",
                        "hostname": "ok-host",
                        "status": "pass",
                    },
                ],
            },
        },
    )
    assert opened
    marker = poam_marker("host_disk_encryption", "agt-disk-1")
    assert any(
        marker in (r.get("notes") or "") or marker in (r.get("recommendation") or "")
        for r in list_remediations(uid, status="open")
    )
    # Must not open a row for the PASS agent
    assert not any(
        poam_marker("host_disk_encryption", "agt-ok") in (r.get("notes") or "")
        for r in list_remediations(uid, status="open")
    )


def test_enable_firewall_in_supported_command_kinds():
    from app.agents import SUPPORTED_COMMAND_KINDS

    assert "enable_firewall" in SUPPORTED_COMMAND_KINDS
    assert "enable_defender" in SUPPORTED_COMMAND_KINDS
    assert "patch_package" in SUPPORTED_COMMAND_KINDS
    assert "agent_upgrade" in SUPPORTED_COMMAND_KINDS


def test_enable_defender_in_supported_command_kinds():
    from app.agents import SUPPORTED_COMMAND_KINDS, request_enable_defender_command

    assert "enable_defender" in SUPPORTED_COMMAND_KINDS
    assert callable(request_enable_defender_command)


def test_evaluate_agent_host_controls_publishes_risk_changed_on_fail(
    tmp_path, monkeypatch
):
    """Host FAIL → org risk.changed with previous_score/score_delta when known."""
    from app.agents import enroll_agent
    from app import event_processor
    from app.services.control_testing import evaluate_agent_host_controls

    uid = _setup(monkeypatch, tmp_path, username="host_risk_delta")
    agent = enroll_agent(uid, name="risk-fw-agent")
    aid = agent["agent_id"]

    publishes: list[dict] = []
    scores = iter(
        [
            {"score": 12.0, "band": "low", "total_open": 1},
            {"score": 40.0, "band": "elevated", "total_open": 5},
        ]
    )
    event_processor._last_org_risk_score.pop(uid, None)
    monkeypatch.setattr(
        "app.services.risk_priority.compute_org_risk_score",
        lambda user_id, **kw: next(scores),
    )
    monkeypatch.setattr(
        "app.realtime_bus.publish", lambda **kw: publishes.append(kw)
    )

    # Seed previous score so the FAIL publish includes score_delta
    event_processor._maybe_publish_org_risk(uid, reason="seed")
    publishes.clear()

    disabled = {
        "hostname": "risk-fw-host",
        "os": "linux",
        "firewall_status": {"collected": True, "enabled": False, "backend": "ufw"},
        "defender_status": {"collected": False, "reason": "Not applicable on linux"},
        "ssh_config": {"collected": True, "settings": {"PermitRootLogin": "no"}},
    }
    out = evaluate_agent_host_controls(uid, aid, disabled, asset_id="")
    assert out["ok"] is True
    changed = [
        p
        for p in publishes
        if p.get("event_type") == "risk.changed" or (
            p.get("type") == "risk" and "score" in p and "previous_score" in p
        )
    ]
    assert changed, f"expected risk.changed; got {publishes!r}"
    assert any(p.get("previous_score") == 12.0 for p in changed)
    assert any(
        p.get("event_type") == "control.failed" or p.get("type") == "control.failed"
        for p in publishes
    )
