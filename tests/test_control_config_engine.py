"""Configurable control engine — registry schema + host_risky_listeners (#4)."""

from __future__ import annotations

from tests._http_test_utils import configure_isolated_settings


def test_registry_entries_expose_configurable_fields():
    from app.controls.test_registry import TEST_HOST_FIREWALL, get_test_entry, list_registry

    rows = list_registry()
    assert any(r["test_name"] == TEST_HOST_FIREWALL for r in rows)
    fw = get_test_entry(TEST_HOST_FIREWALL)
    assert fw is not None
    for key in (
        "name",
        "description",
        "applicability",
        "pass_condition",
        "fail_condition",
        "risk_weight",
        "evidence_rule",
        "verification_rule",
        "data_sources",
        "control_bindings",
    ):
        assert key in fw, key
    assert fw["risk_weight"] >= 1.0
    assert fw["pass_condition"]
    assert "os" in (fw.get("applicability") or {})


def test_host_risky_listeners_fail_pass_unknown():
    from app.controls.test_registry import TEST_HOST_RISKY_LISTENERS
    from app.services.control_testing import evaluate_host_risky_listeners_payload

    fail = evaluate_host_risky_listeners_payload(
        {"listening_ports": [80, 3389, 6379]}, agent_id="a1"
    )
    assert fail["test"] == TEST_HOST_RISKY_LISTENERS
    assert fail["status"] == "fail"
    assert 3389 in (fail.get("detail") or {}).get("risky_ports", [])

    ok = evaluate_host_risky_listeners_payload({"listening_ports": [22, 443]}, agent_id="a1")
    assert ok["status"] == "pass"

    unk = evaluate_host_risky_listeners_payload({"hostname": "x"}, agent_id="a1")
    assert unk["status"] == "unknown"

    empty = evaluate_host_risky_listeners_payload({"listening_ports": []}, agent_id="a1")
    assert empty["status"] == "pass"


def test_risky_listeners_in_agent_host_controls(tmp_path, monkeypatch):
    configure_isolated_settings(monkeypatch, tmp_path)
    from app.agents import enroll_agent
    from app.auth import login, register_user
    from app.tenancy import ensure_tenant_schema
    from app.services.control_testing import evaluate_agent_host_controls

    ensure_tenant_schema()
    register_user("ctrl_risky", "password123", role="admin")
    user, _ = login("ctrl_risky", "password123")
    agent = enroll_agent(user.id, name="risky-lab")
    out = evaluate_agent_host_controls(
        user.id,
        agent["agent_id"],
        {
            "hostname": "risky-lab",
            "os": "linux",
            "listening_ports": [3389],
            "firewall_status": {"collected": True, "enabled": True},
            "disk_encryption_status": {"collected": True, "encrypted": True, "backend": "luks"},
            "ssh_config": {"collected": True, "settings": {"PermitRootLogin": "no"}},
            "defender_status": {"collected": False, "reason": "na"},
        },
    )
    assert out.get("ok") is True
    by_test = {r["test"]: r for r in out.get("results") or []}
    assert "host_risky_listeners" in by_test
    assert by_test["host_risky_listeners"]["status"] == "fail"
