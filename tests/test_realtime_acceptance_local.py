"""Local-path acceptance for RT-10/11 host fail → remediate → pass (no network)."""

from __future__ import annotations

from tests._http_test_utils import configure_isolated_settings


def test_realtime_acceptance_local_firewall_fail_then_pass(tmp_path, monkeypatch):
    configure_isolated_settings(monkeypatch, tmp_path)
    from app.agents import enroll_agent
    from app.auth import login, register_user
    from app.controls.poam import poam_marker
    from app.enterprise import list_remediations
    from app.tenancy import ensure_tenant_schema
    from scripts.realtime_acceptance_demo import (
        LOCAL_STEP_NAMES,
        LOCAL_VERIFY_STEP,
        OPTIONAL_ENABLE_FW_STEP,
        run_local_chain,
    )

    ensure_tenant_schema()
    register_user("rt_accept_tester", "password123", role="admin")
    user, _token = login("rt_accept_tester", "password123")
    agent = enroll_agent(user.id, name="rt-accept-pytest")
    aid = agent["agent_id"]

    report = run_local_chain(user.id, aid)

    assert report.mode == "local"
    assert report.disclaimer == "lab acceptance harness — not a 5k/HA proof"
    assert len(report.steps) == len(LOCAL_STEP_NAMES) + 1

    names = [s.name for s in report.steps]
    assert names[:10] == list(LOCAL_STEP_NAMES)
    assert names[10] == LOCAL_VERIFY_STEP
    assert OPTIONAL_ENABLE_FW_STEP == "6_enable_firewall_command"

    by_name = {s.name: s for s in report.steps}
    assert by_name["1_firewall_off_host_control_fail"].ok is True
    assert by_name["1_firewall_off_host_control_fail"].data.get("firewall_status") == "fail"
    assert by_name["2_evidence_created_observed"].ok is True
    assert by_name["3_compliance_or_control_failed_event"].ok is True
    assert by_name["4_poam_gap_remediation_open"].ok is True
    assert by_name["4_poam_gap_remediation_open"].data.get("open_count", 0) >= 1
    assert by_name["5_risk_event_published"].ok is True

    fw_cmd = by_name["6_enable_firewall_command"]
    assert fw_cmd.ok is True
    assert "SKIPPED" not in (fw_cmd.detail or "")
    assert fw_cmd.data.get("pending_ok") is True
    assert fw_cmd.data.get("approve_ok") is True
    assert fw_cmd.data.get("final_status") == "done"

    assert by_name["7_firewall_on_pass"].ok is True
    assert by_name["7_firewall_on_pass"].data.get("firewall_status") == "pass"
    assert by_name["8_evidence_pass"].ok is True
    assert by_name["9_poam_closed_rem_done"].ok is True
    assert by_name["9_poam_closed_rem_done"].data.get("still_open") == 0
    assert by_name["10_risk_reduction_hint"].ok is True
    assert by_name[LOCAL_VERIFY_STEP].ok is True
    assert by_name[LOCAL_VERIFY_STEP].data.get("verification_status") == "verified"

    marker = poam_marker("host_firewall", aid)
    assert not any(
        marker in (r.get("notes") or "") or marker in (r.get("recommendation") or "")
        for r in list_remediations(user.id, status="open")
    )
    assert any(
        marker in (r.get("notes") or "") or marker in (r.get("recommendation") or "")
        for r in list_remediations(user.id, status="done")
    )

    assert report.ok is True


def test_realtime_acceptance_local_triple_host_loops(tmp_path, monkeypatch):
    """RT-11 parity: firewall + Defender + SSH each close FAIL→approve→PASS→verified."""
    configure_isolated_settings(monkeypatch, tmp_path)
    from app.agents import enroll_agent
    from app.auth import login, register_user
    from app.controls.poam import poam_marker
    from app.enterprise import list_remediations
    from app.tenancy import ensure_tenant_schema
    from scripts.realtime_acceptance_demo import HOST_LOOPS, LOCAL_VERIFY_STEP, run_local_all_host_loops

    ensure_tenant_schema()
    register_user("rt_accept_triple", "password123", role="admin")
    user, _token = login("rt_accept_triple", "password123")
    agent = enroll_agent(user.id, name="rt-accept-triple")
    aid = agent["agent_id"]

    report = run_local_all_host_loops(user.id, aid)
    assert report.ok is True
    # 3 loops × (10 core + 1 verify) = 33
    assert len(report.steps) == 33

    for loop in HOST_LOOPS:
        prefix = loop.test_id
        fail_step = next(s for s in report.steps if s.name == f"{prefix}:{loop.step_names[0]}")
        assert fail_step.ok is True
        assert fail_step.data.get(loop.status_key) == "fail"

        cmd_step = next(s for s in report.steps if s.name == f"{prefix}:{loop.step_names[5]}")
        assert cmd_step.ok is True
        assert cmd_step.data.get("final_status") == "done"

        pass_step = next(s for s in report.steps if s.name == f"{prefix}:{loop.step_names[6]}")
        assert pass_step.ok is True
        assert pass_step.data.get(loop.status_key) == "pass"

        verify = next(s for s in report.steps if s.name == f"{prefix}:{LOCAL_VERIFY_STEP}")
        assert verify.ok is True
        assert verify.data.get("verification_status") == "verified"

        marker = poam_marker(loop.test_id, aid)
        assert not any(
            marker in (r.get("notes") or "") or marker in (r.get("recommendation") or "")
            for r in list_remediations(user.id, status="open")
        )
        assert any(
            marker in (r.get("notes") or "") or marker in (r.get("recommendation") or "")
            for r in list_remediations(user.id, status="done")
        )
