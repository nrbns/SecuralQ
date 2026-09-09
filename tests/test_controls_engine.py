"""Sprint 1 Control & Configuration Engine — catalog, summary, verifiability."""

from __future__ import annotations

from tests._http_test_utils import configure_isolated_settings


def _setup(monkeypatch, tmp_path, username="controls_engine_tester"):
    configure_isolated_settings(monkeypatch, tmp_path)
    from app.auth import login, register_user
    from app.tenancy import ensure_tenant_schema

    ensure_tenant_schema()
    register_user(username, "password123", role="admin")
    u, _token = login(username, "password123")
    return u.id


def test_cmmc_l2_catalog_has_about_110_controls():
    from app.controls.catalog import list_framework_controls, normalize_cmmc_control_id

    controls = list_framework_controls("cmmc_l2")
    assert 100 <= len(controls) <= 120
    assert len(controls) == 110
    ids = {c.id for c in controls}
    assert "AC.L2-3.1.1" in ids
    assert "SC.L2-3.13.1" in ids
    assert normalize_cmmc_control_id("sc.l2-3.13.1") == "SC.L2-3.13.1"


def test_get_control_normalizes_cmmc_id():
    from app.controls.catalog import get_control

    c = get_control("cmmc_l2", "si.l2-3.14.2")
    assert c is not None
    assert c.id == "SI.L2-3.14.2"
    assert any(t.name == "host_defender" for t in c.tests)


def test_control_center_summary_returns(tmp_path, monkeypatch):
    from app.controls.catalog import control_center_summary

    uid = _setup(monkeypatch, tmp_path)
    summary = control_center_summary(uid, framework_id="cmmc_l2")
    assert summary["framework_id"] == "cmmc_l2"
    assert summary["controls_total"] == 110
    assert summary["passing"] == 0
    assert summary["failing"] == 0
    assert summary["unknown"] == 0
    assert summary["na"] == 0
    assert "disclaimer" in summary
    assert summary.get("last_test") is None


def test_verifiability_marks_mapped_controls_machine_or_partial():
    from app.controls.catalog import verifiability_map

    vmap = verifiability_map("cmmc_l2")
    assert vmap["controls_total"] == 110
    # Host-mapped practices from Sprint 1 explicit map
    for cid in ("SC.L2-3.13.1", "CM.L2-3.4.2", "SI.L2-3.14.2", "AC.L2-3.1.5"):
        row = vmap["controls"][cid]
        assert row["verifiability"] in ("machine", "partial"), cid
        assert row["live_tests"], cid
    # Unmapped practice stays human
    human = vmap["controls"]["AC.L2-3.1.1"]
    assert human["verifiability"] == "human"
    assert human["live_tests"] == []
    assert vmap["counts"]["machine"] + vmap["counts"]["partial"] >= 4
    assert vmap["counts"]["human"] >= 100


def test_nist_800_171_host_mappings_verifiability():
    from app.controls.catalog import get_control

    fw = get_control("nist_800_171", "3.13.1")
    assert fw is not None
    assert fw.verifiability in ("machine", "partial")
    assert any(t.name == "host_firewall" for t in fw.tests)

    defn = get_control("nist_800_171", "3.14.2")
    assert defn is not None
    assert any(t.name == "host_defender" for t in defn.tests)


def test_run_control_tests_persists_and_summary_updates(tmp_path, monkeypatch):
    from app.controls.catalog import control_center_summary
    from app.controls.test_engine import run_control_tests

    uid = _setup(monkeypatch, tmp_path, username="controls_run_tester")
    out = run_control_tests(uid, "cmmc_l2", "SI.L2-3.14.2", record_evidence=False)
    assert out["ok"] is True
    assert out["results"], "mapped control should run at least one live test"
    summary = control_center_summary(uid, framework_id="cmmc_l2")
    assert summary["controls_total"] == 110
    # At least one control now has a stored result contributing to buckets
    asserted = summary["passing"] + summary["failing"] + summary["unknown"] + summary["na"]
    assert asserted >= 1
    assert summary.get("last_test") is not None


def test_get_control_with_live_results_exposes_why_and_deviations(tmp_path, monkeypatch):
    """Sprint 3 — failing stored results surface clear why / deviations."""
    from app.controls.results import record_test_result
    from app.controls.test_engine import get_control_with_live_results

    uid = _setup(monkeypatch, tmp_path, username="why_fail_tester")
    record_test_result(
        uid,
        "cmmc_l2",
        "SC.L2-3.13.1",
        test_name="host_firewall",
        status="fail",
        summary="Firewall disabled on 1 agent",
        detail={
            "failing_agents": [{"agent_id": "agt-1", "hostname": "lab-1"}],
            "expected": True,
            "actual": False,
            "deviations": [
                {"setting": "firewall.enabled", "expected": True, "actual": False},
            ],
        },
    )
    payload = get_control_with_live_results(uid, "cmmc_l2", "SC.L2-3.13.1")
    assert payload is not None
    assert payload["why"], "top-level why required"
    assert payload["why_failing"] == payload["why"]
    assert any("host_firewall" in w for w in payload["why"])
    assert any("Firewall disabled" in w for w in payload["why"])
    assert payload["deviations"]
    assert any("firewall.enabled" in d for d in payload["deviations"])
    live = payload["live_results"]
    assert live and live[0]["status"] == "fail"
    assert live[0]["why"]
    assert live[0]["deviations"]


def test_poam_opens_on_host_fail_and_closes_on_pass(tmp_path, monkeypatch):
    """Sprint 4 — POA&M-like gap_remediation open on FAIL, done on PASS."""
    from app.controls.poam import close_poam_for_host_pass, open_poam_for_host_fail, poam_marker
    from app.enterprise import list_remediations

    uid = _setup(monkeypatch, tmp_path, username="poam_stub_tester")
    aid = "agent-poam-1"
    rem = open_poam_for_host_fail(
        uid,
        agent_id=aid,
        hostname="poam-host",
        test_name="host_firewall",
        result={"summary": "Firewall disabled", "status": "fail"},
        control_id="CIS-12",
    )
    assert rem is not None
    assert rem.get("id")
    marker = poam_marker("host_firewall", aid)
    open_rows = list_remediations(uid, status="open")
    assert any(
        marker in (r.get("notes") or "") or marker in (r.get("recommendation") or "")
        for r in open_rows
    )
    # Idempotent — second open reuses
    rem2 = open_poam_for_host_fail(
        uid,
        agent_id=aid,
        hostname="poam-host",
        test_name="host_firewall",
        result={"summary": "Firewall disabled", "status": "fail"},
    )
    assert rem2 and rem2.get("id") == rem.get("id")

    closed = close_poam_for_host_pass(uid, agent_id=aid, test_name="host_firewall")
    assert closed >= 1
    still_open = list_remediations(uid, status="open")
    assert not any(
        marker in (r.get("notes") or "") or marker in (r.get("recommendation") or "")
        for r in still_open
    )
