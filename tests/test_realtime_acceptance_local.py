"""Local-path acceptance for RT-10/11 firewall fail → pass (no network)."""

from __future__ import annotations

from tests._http_test_utils import configure_isolated_settings


def test_realtime_acceptance_local_firewall_fail_then_pass(tmp_path, monkeypatch):
    configure_isolated_settings(monkeypatch, tmp_path)
    from app.agents import enroll_agent
    from app.auth import login, register_user
    from app.tenancy import ensure_tenant_schema
    from scripts.realtime_acceptance_demo import run_local_chain

    ensure_tenant_schema()
    register_user("rt_accept_tester", "password123", role="admin")
    user, _token = login("rt_accept_tester", "password123")
    agent = enroll_agent(user.id, name="rt-accept-pytest")

    report = run_local_chain(user.id, agent["agent_id"])

    assert report.mode == "local"
    assert report.disclaimer == "lab acceptance harness — not a 5k/HA proof"
    assert len(report.steps) == 3

    names = [s.name for s in report.steps]
    assert names == [
        "firewall_disabled_compliance_fail",
        "evidence_and_compliance_event",
        "firewall_enabled_compliance_pass",
    ]
    assert report.steps[0].ok is True
    assert report.steps[0].data.get("firewall_status") == "fail"
    assert report.steps[1].ok is True
    assert report.steps[2].ok is True
    assert report.steps[2].data.get("firewall_status") == "pass"
    assert report.ok is True
