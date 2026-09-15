"""Sprint 2–5 foundation tests: mTLS lifecycle, auto evidence, command lifecycle, licensing facade."""

from __future__ import annotations

from tests._http_test_utils import configure_isolated_settings


def test_mtls_issue_rotate_revoke_renew(tmp_path, monkeypatch):
    configure_isolated_settings(monkeypatch, tmp_path)
    from app.agent_certs import (
        is_fingerprint_revoked,
        issue_agent_client_certificate,
        renew_agent_client_certificate,
        revoke_agent_certificate,
        rotate_agent_client_certificate,
        verify_proxy_client_cert,
    )
    from app.agents import enroll_agent
    from app.config import settings
    from app.tenancy import ensure_tenant_schema

    ensure_tenant_schema()
    monkeypatch.setattr(settings, "agent_mtls_enabled", True, raising=False)
    monkeypatch.setattr(settings, "agent_mtls_proxy_verify", True, raising=False)
    monkeypatch.setattr(settings, "agent_mtls_require_fingerprint_match", True, raising=False)

    out = enroll_agent("local", name="mtls-lifecycle")
    aid = out["agent_id"]
    issued = issue_agent_client_certificate(aid, days=30)
    fp1 = issued["fingerprint"]
    assert fp1
    assert "BEGIN CERTIFICATE" in issued["certificate_pem"]

    rotated = rotate_agent_client_certificate(aid, days=30, rotated_by="local")
    fp2 = rotated["mtls"]["fingerprint"]
    assert fp2 and fp2 != fp1
    assert is_fingerprint_revoked(fp1)

    err = verify_proxy_client_cert(
        {"certificate_fingerprint": fp2},
        client_verify="SUCCESS",
        client_fingerprint=fp1,
    )
    assert err and "revoked" in err.lower()

    ok = verify_proxy_client_cert(
        {"certificate_fingerprint": fp2},
        client_verify="SUCCESS",
        client_fingerprint=fp2,
    )
    assert ok is None

    renew = renew_agent_client_certificate(aid, force=False, renew_before_sec=0)
    assert renew.get("renewed") is False  # not due (far expiry)

    renew_force = renew_agent_client_certificate(aid, force=True, renewed_by="local")
    assert renew_force.get("renewed") is True
    fp3 = renew_force["mtls"]["fingerprint"]
    assert fp3 != fp2

    revoked = revoke_agent_certificate(aid, reason="test", revoked_by="local")
    assert revoked["ok"] is True
    assert is_fingerprint_revoked(fp3)


def test_command_lifecycle_closed_loop_vocabulary():
    from app.agents import command_lifecycle

    assert command_lifecycle("recommended") == "RECOMMENDED"
    assert command_lifecycle("pending_approval") == "PENDING_APPROVAL"
    assert command_lifecycle("queued") == "APPROVED"
    assert command_lifecycle("sent") == "SENT"
    assert command_lifecycle("acked") == "ACK"
    assert command_lifecycle("done") == "EXECUTED"
    assert command_lifecycle("done", verification_status="pending") == "VERIFYING"
    assert command_lifecycle("done", verification_status="verified") == "VERIFIED"
    assert command_lifecycle("rejected") == "REJECTED"
    assert command_lifecycle("timeout", error="expired before delivery") == "EXPIRED"
    assert command_lifecycle("rollback") == "ROLLBACK"
    assert command_lifecycle("queued", phase="SIGNED") == "SIGNED"


def test_auto_control_evidence(tmp_path, monkeypatch):
    configure_isolated_settings(monkeypatch, tmp_path)
    from app.controls.auto_evidence import record_control_result_evidence
    from app.controls.types_extended import Check, ControlResult, Observation, Requirement
    from app.tenancy import ensure_tenant_schema

    ensure_tenant_schema()
    req = Requirement(id="r1", framework_id="cis", title="Firewall", control_ids=["fw"])
    chk = Check(id="firewall_status", control_id="fw", framework_id="cis", name="firewall")
    assert req.to_dict()["id"] == "r1"
    assert chk.to_dict()["id"] == "firewall_status"

    row = record_control_result_evidence(
        "local",
        control_id="fw",
        result="fail",
        framework_id="cis",
        check_id="firewall_status",
        agent_id="a1",
        event_id="e1",
    )
    assert row and row.get("id")
    assert (row.get("detail") or row.get("detail_json") or "")
    # second call with same summary folds; different result summary creates chain
    row2 = record_control_result_evidence(
        "local",
        control_id="fw",
        result="pass",
        framework_id="cis",
        check_id="firewall_status",
        agent_id="a1",
        previous_evidence_id=row["id"],
        summary="Control fw → PASS",
    )
    assert row2 and row2.get("id")
    cr = ControlResult(control_id="fw", framework_id="cis", result="pass", evidence_id=row2["id"])
    assert cr.to_dict()["result"] == "pass"
    obs = Observation(
        id="o1",
        check_id="firewall_status",
        control_id="fw",
        result="pass",
        observed_at=1.0,
        agent_id="a1",
    )
    assert obs.to_dict()["result"] == "pass"


def test_licensing_and_auth_commercial_facades(tmp_path, monkeypatch):
    configure_isolated_settings(monkeypatch, tmp_path)
    from app import auth_commercial, licensing
    from app.auth import register_user
    from app.tenancy import ensure_tenant_schema

    ensure_tenant_schema()
    register_user("lic_facade", "password123", role="admin")
    ent = licensing.entitlements_for_plan("pro")
    assert ent.get("max_agents") == 100
    summary = licensing.activation_summary("local")
    assert "ok" in summary
    st = auth_commercial.mfa_status("local")
    assert isinstance(st, dict)


def test_production_profile_checklist_doc_exists():
    from pathlib import Path

    p = Path(__file__).resolve().parents[1] / "docs" / "SPRINTS-2-6-PRODUCTION.md"
    assert p.is_file()
    text = p.read_text(encoding="utf-8")
    assert "mTLS" in text
    assert "PENDING_APPROVAL" in text or "VERIFYING" in text
