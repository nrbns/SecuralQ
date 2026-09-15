"""Phase A/B commercial foundations: MFA identity, licensing, AI boundary, RBAC."""

from __future__ import annotations

from tests._http_test_utils import configure_isolated_settings


def test_licensing_activate_renew_usage(tmp_path, monkeypatch):
    configure_isolated_settings(monkeypatch, tmp_path)
    from app.auth import register_user
    from app import licensing
    from app.tenancy import ensure_tenant_schema

    ensure_tenant_schema()
    u = register_user("lic_phaseb", "password123", role="admin")
    act = licensing.activate_trial(u.id, plan="pro", days=14)
    assert act["ok"] is True
    assert act["activation"]["ok"] is True
    assert act["activation"]["plan"] == "pro"

    usage = licensing.usage_against_entitlements(u.id)
    assert usage["ok"] is True
    assert usage["enforcement_enabled"] in (True, False)
    assert "enrollment" in usage

    renewed = licensing.renew_subscription(u.id, days=30)
    assert renewed["ok"] is True
    assert renewed["action"] == "renew"
    gate = licensing.commercial_licensing_status(u.id)
    assert gate["ok"] is True
    assert gate["activation"]["ok"] is True


def test_auth_commercial_identity_v1(tmp_path, monkeypatch):
    configure_isolated_settings(monkeypatch, tmp_path)
    from app.auth import register_user
    from app import auth_commercial
    from app.mfa import mfa_enroll_confirm, mfa_enroll_start
    from app.tenancy import ensure_tenant_schema
    import time

    ensure_tenant_schema()
    u = register_user("id_v1", "password123")
    enroll = mfa_enroll_start(u.id, username=u.username)
    from app.mfa import _decode_secret, totp_at

    code = totp_at(_decode_secret(enroll["secret"]), counter=int(time.time()) // 30)
    mfa_enroll_confirm(u.id, code)
    st = auth_commercial.identity_v1_status(u.id)
    assert st["ok"] is True
    assert st["totp_mfa"]["enabled"] is True
    assert "agent.approve" in st["rbac"]["actions"]
    assert "webauthn" in st["v2_deferred"]


def test_secops_ai_propose_only_no_shell(tmp_path, monkeypatch):
    configure_isolated_settings(monkeypatch, tmp_path)
    from app.secops.tools import (
        ALLOWED_TOOLS,
        DENIED_TOOL_NAMES,
        READ_TOOLS,
        WRITE_TOOLS,
        call_tool,
    )

    assert WRITE_TOOLS.isdisjoint(READ_TOOLS)
    assert WRITE_TOOLS <= ALLOWED_TOOLS
    assert "verify_host_remediation" in READ_TOOLS
    denied = call_tool("shell", "local", args={"cmd": "whoami"})
    assert denied["ok"] is False
    assert denied["error"] == "tool_not_allowed"
    for name in ("exec", "approve_command", "run_command"):
        assert name in DENIED_TOOL_NAMES
        assert call_tool(name, "local")["ok"] is False

    prop = call_tool(
        "propose_remediation",
        "local",
        args={"title": "Enable firewall", "control_id": "9.1"},
    )
    assert prop["ok"] is True
    assert prop["data"]["proposed"] is True
    assert prop["data"]["mutated"] is False

    appr = call_tool(
        "propose_approval",
        "local",
        args={"agent_id": "ag-1", "command_kind": "enable_firewall"},
    )
    assert appr["ok"] is True
    assert appr["data"]["mutated"] is False
