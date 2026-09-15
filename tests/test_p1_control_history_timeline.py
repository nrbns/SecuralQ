"""P1: control_results history, affected recompute, agent timeline, production profile."""

from __future__ import annotations

from tests._http_test_utils import configure_isolated_settings


def test_control_results_append_only_history(tmp_path, monkeypatch):
    configure_isolated_settings(monkeypatch, tmp_path)
    from app.controls.history import append_control_result, list_control_results
    from app.controls.results import record_test_result
    from app.tenancy import ensure_tenant_schema

    ensure_tenant_schema()
    uid = "local"
    r1 = append_control_result(
        uid,
        framework_id="cis",
        control_id="9.1",
        test_name="host_firewall",
        result="fail",
        summary="firewall off",
        agent_id="ag-1",
    )
    assert r1["id"]
    r2 = append_control_result(
        uid,
        framework_id="cis",
        control_id="9.1",
        test_name="host_firewall",
        result="pass",
        summary="firewall on",
        agent_id="ag-1",
    )
    assert r2["previous_result_id"] == r1["id"]

    # Dual-write from last-result upsert
    record_test_result(
        uid,
        "cis",
        "9.1",
        test_name="host_firewall",
        status="pass",
        summary="via record",
        detail={"agent_id": "ag-1"},
    )
    rows = list_control_results(uid, agent_id="ag-1", limit=10)
    assert len(rows) >= 3
    assert rows[0]["result"] in {"pass", "fail", "unknown"}
    assert any(r.get("previous_result_id") for r in rows)


def test_affected_controls_recompute_software_and_config(tmp_path, monkeypatch):
    configure_isolated_settings(monkeypatch, tmp_path)
    from app.controls.recompute import recompute_affected_controls, tests_for_event_type
    from app.tenancy import ensure_tenant_schema

    ensure_tenant_schema()
    assert "patch_management" in tests_for_event_type("software.installed")
    assert "host_firewall" in tests_for_event_type("configuration.drift_detected")
    assert tests_for_event_type("control.failed") == ()

    skipped = recompute_affected_controls("local", {"event_type": "noise.event"})
    assert skipped.get("skipped") is True

    out = recompute_affected_controls(
        "local",
        {"event_type": "software.updated", "agent_id": ""},
    )
    assert out.get("ok") is True
    assert "patch_management" in out.get("tests", [])


def test_agent_timeline_merge(tmp_path, monkeypatch):
    configure_isolated_settings(monkeypatch, tmp_path)
    from app.agent_timeline import build_agent_timeline
    from app.agents import enroll_agent, request_enable_firewall_command
    from app.controls.history import append_control_result
    from app.tenancy import ensure_tenant_schema

    ensure_tenant_schema()
    enrolled = enroll_agent("local", name="timeline-host")
    aid = enrolled["agent_id"]
    request_enable_firewall_command("local", aid)
    append_control_result(
        "local",
        framework_id="cis",
        control_id="9.1",
        test_name="host_firewall",
        result="fail",
        summary="off",
        agent_id=aid,
    )
    tl = build_agent_timeline("local", aid, limit=40)
    assert tl["ok"] is True
    kinds = {e["kind"] for e in tl["events"]}
    assert "command" in kinds
    assert "control" in kinds


def test_production_profile_status_flags(tmp_path, monkeypatch):
    configure_isolated_settings(monkeypatch, tmp_path)
    from app.config import settings
    from app.production_profile import production_profile_status

    monkeypatch.setattr(settings, "agent_mtls_enabled", False, raising=False)
    monkeypatch.setattr(settings, "agent_require_command_signature", False, raising=False)
    monkeypatch.setattr(settings, "agent_require_replay_protection", False, raising=False)
    monkeypatch.setattr(settings, "agent_mtls_proxy_verify", False, raising=False)

    st = production_profile_status()
    assert st["ok"] is True
    assert st["production_ready_agent_security"] is False
    assert "AGENT_MTLS_ENABLED=true" in st["env_hints"]

    monkeypatch.setattr(settings, "agent_mtls_enabled", True, raising=False)
    monkeypatch.setattr(settings, "agent_mtls_proxy_verify", True, raising=False)
    monkeypatch.setattr(settings, "agent_require_command_signature", True, raising=False)
    monkeypatch.setattr(settings, "agent_require_replay_protection", True, raising=False)
    st2 = production_profile_status()
    assert st2["production_ready_agent_security"] is True
