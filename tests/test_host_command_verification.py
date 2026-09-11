"""Host remediation command verification closes on live control PASS/FAIL."""

from __future__ import annotations

from tests._http_test_utils import configure_isolated_settings


def _setup(monkeypatch, tmp_path, username="host_cmd_verify"):
    configure_isolated_settings(monkeypatch, tmp_path)
    from app.auth import login, register_user
    from app.tenancy import ensure_tenant_schema

    ensure_tenant_schema()
    register_user(username, "password123", role="admin")
    u, _token = login(username, "password123")
    return u.id


def test_enable_firewall_verifies_on_host_pass(tmp_path, monkeypatch):
    from app.agents import (
        approve_command,
        checkin,
        enroll_agent,
        report_command_result,
        request_enable_firewall_command,
    )
    from app.db import get_conn

    uid = _setup(monkeypatch, tmp_path)
    enrolled = enroll_agent(uid, name="fw-verify-agent")
    aid = enrolled["agent_id"]

    checkin(
        aid,
        {
            "hostname": "fw-verify",
            "os": "linux",
            "firewall_status": {"collected": True, "enabled": False, "backend": "ufw"},
        },
    )

    cmd = request_enable_firewall_command(uid, aid)
    approve_command(uid, aid, cmd["id"], approver_id=uid)
    report_command_result(
        aid,
        cmd["id"],
        status="done",
        result={"ok": True, "lab": True, "summary": "enabled"},
    )
    row = dict(
        get_conn()
        .execute(
            "SELECT verification_status, kind FROM securaiq_agent_commands WHERE id=?",
            (cmd["id"],),
        )
        .fetchone()
    )
    assert row["verification_status"] == "pending"
    assert row["kind"] == "enable_firewall"

    # PASS check-in closes host-command verification (no advisory job)
    checkin(
        aid,
        {
            "hostname": "fw-verify",
            "os": "linux",
            "firewall_status": {"collected": True, "enabled": True, "backend": "ufw"},
        },
    )
    row2 = dict(
        get_conn()
        .execute(
            "SELECT verification_status FROM securaiq_agent_commands WHERE id=?",
            (cmd["id"],),
        )
        .fetchone()
    )
    assert row2["verification_status"] == "verified"


def test_enable_firewall_fails_verification_on_still_fail(tmp_path, monkeypatch):
    from app.agents import (
        approve_command,
        checkin,
        enroll_agent,
        report_command_result,
        request_enable_firewall_command,
    )
    from app.db import get_conn

    uid = _setup(monkeypatch, tmp_path, username="host_cmd_fail")
    enrolled = enroll_agent(uid, name="fw-fail-agent")
    aid = enrolled["agent_id"]
    checkin(
        aid,
        {
            "hostname": "fw-fail",
            "os": "linux",
            "firewall_status": {"collected": True, "enabled": False, "backend": "ufw"},
        },
    )
    cmd = request_enable_firewall_command(uid, aid)
    approve_command(uid, aid, cmd["id"], approver_id=uid)
    report_command_result(aid, cmd["id"], status="done", result={"ok": True})
    checkin(
        aid,
        {
            "hostname": "fw-fail",
            "os": "linux",
            "firewall_status": {"collected": True, "enabled": False, "backend": "ufw"},
        },
    )
    row = dict(
        get_conn()
        .execute(
            "SELECT verification_status FROM securaiq_agent_commands WHERE id=?",
            (cmd["id"],),
        )
        .fetchone()
    )
    assert row["verification_status"] == "verification_failed"
