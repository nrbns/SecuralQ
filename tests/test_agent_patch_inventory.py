"""Agent check-in → software inventory → patch verify loop."""

from __future__ import annotations

from tests._http_test_utils import configure_isolated_settings


def _reload(monkeypatch, data_dir):
    return configure_isolated_settings(monkeypatch, data_dir)


def test_checkin_ingests_packages_into_inventory(tmp_path, monkeypatch):
    _reload(monkeypatch, tmp_path)
    from app.agents import checkin, enroll_agent, ensure_schema, get_agent
    from app.db import get_conn
    from app.software.models import ensure_schema as ensure_sw
    from app.software.sources.base import all_sources

    ensure_schema()
    ensure_sw()
    keys = {s.key for s in all_sources()}
    assert "securaiq_agent" in keys

    enrolled = enroll_agent("local", name="lab-host")
    aid = enrolled["agent_id"]
    result = checkin(
        aid,
        {
            "hostname": "lab-host",
            "os": "linux",
            "os_version": "6.1",
            "packages": [
                {"name": "curl", "version": "7.88.1"},
                {"name": "openssl", "version": "3.0.2"},
            ],
        },
    )
    assert result.get("ok")
    assert result.get("asset_id")
    agent = get_agent(aid)
    assert agent and agent.get("asset_id")

    c = get_conn()
    legacy = c.execute(
        "SELECT COUNT(*) AS n FROM asset_software WHERE user_id=? AND source='securaiq_agent'",
        ("local",),
    ).fetchone()
    assert int(legacy["n"] if hasattr(legacy, "keys") else legacy[0]) >= 2

    eng = c.execute(
        "SELECT COUNT(*) AS n FROM software_installations WHERE user_id=? AND source='securaiq_agent'",
        ("local",),
    ).fetchone()
    assert int(eng["n"] if hasattr(eng, "keys") else eng[0]) >= 2


def test_patch_result_stamps_version_and_verifies(tmp_path, monkeypatch):
    _reload(monkeypatch, tmp_path)
    from app.agents import (
        approve_command,
        checkin,
        enroll_agent,
        ensure_schema,
        report_command_result,
        request_command,
        _dispatch_queued_commands,
    )
    from app.db import get_conn
    from app.jobs import _verify_patch_command
    from app.software.models import ensure_schema as ensure_sw

    ensure_schema()
    ensure_sw()
    enrolled = enroll_agent("local", name="patch-host")
    aid = enrolled["agent_id"]
    checkin(
        aid,
        {
            "hostname": "patch-host",
            "os": "linux",
            "packages": [{"name": "curl", "version": "7.80.0"}],
        },
    )
    req = request_command(
        "local",
        aid,
        kind="patch_package",
        payload={"manager": "apt", "package": "curl", "target_version": "7.88.1"},
    )
    approve_command("local", aid, req["id"], approver_id="local")
    cmds = _dispatch_queued_commands(aid)
    assert cmds and cmds[0]["id"] == req["id"]

    report_command_result(
        aid,
        req["id"],
        status="done",
        result={"ok": True, "package": "curl", "old_version": "7.80.0", "new_version": "7.88.1"},
    )
    c = get_conn()
    row = c.execute(
        "SELECT version FROM software_installations i "
        "JOIN software_products p ON p.id=i.software_product_id "
        "WHERE i.user_id=? AND LOWER(p.name) LIKE '%curl%' ORDER BY i.updated_at DESC LIMIT 1",
        ("local",),
    ).fetchone()
    assert row
    assert "7.88" in str(row["version"] if hasattr(row, "keys") else row[0])

    _verify_patch_command(req["id"])
    cmd = c.execute(
        "SELECT verification_status FROM securaiq_agent_commands WHERE id=?", (req["id"],)
    ).fetchone()
    assert (cmd["verification_status"] if hasattr(cmd, "keys") else cmd[0]) == "verified"
