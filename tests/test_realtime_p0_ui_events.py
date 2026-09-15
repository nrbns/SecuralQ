"""Realtime P0: aliased events, license/update bus, RealtimeManager helpers."""

from __future__ import annotations

from tests._http_test_utils import configure_isolated_settings


def _reload(monkeypatch, data_dir):
    return configure_isolated_settings(monkeypatch, data_dir)


def test_command_status_event_type_mapping():
    from app.realtime_events import command_status_event_type

    assert command_status_event_type("pending_approval") == "command.pending"
    assert command_status_event_type("queued") == "command.approved"
    assert command_status_event_type("sent") == "command.sent"
    assert command_status_event_type("acked") == "command.ack"
    assert command_status_event_type("done") == "command.completed"
    assert command_status_event_type("done", verification_status="verified") == "verification.pass"
    assert (
        command_status_event_type("done", verification_status="verification_failed")
        == "verification.fail"
    )


def test_publish_aliased_emits_primary_and_alias(tmp_path, monkeypatch):
    _reload(monkeypatch, tmp_path)
    seen: list[str] = []

    def fake_publish(**kwargs):
        seen.append(str(kwargs.get("type") or kwargs.get("event_type") or ""))

    monkeypatch.setattr("app.realtime_bus.publish", fake_publish)
    from app.realtime_events import publish_aliased

    publish_aliased("agent", aliases=["agent.online", "agent.connected"], id="a1", status="online")
    assert seen[0] == "agent"
    assert "agent.online" in seen
    assert "agent.connected" in seen


def test_evidence_publish_on_create(tmp_path, monkeypatch):
    _reload(monkeypatch, tmp_path)
    seen: list[dict] = []

    def fake_publish(**kwargs):
        seen.append(dict(kwargs))

    monkeypatch.setattr("app.realtime_bus.publish", fake_publish)
    from app.services.evidence import record_evidence

    row = record_evidence(
        "local",
        entity_type="control",
        entity_id="host_firewall:x",
        source="observed",
        summary="firewall disabled",
        detail={"agent_id": "ag1"},
    )
    assert row and row.get("id")
    types = [s.get("type") for s in seen]
    assert "evidence" in types
    assert "evidence.created" in types


def test_license_updated_on_issue(tmp_path, monkeypatch):
    _reload(monkeypatch, tmp_path)
    from app.agent_security import generate_ed25519_keypair
    from app.auth import register_user
    from app.config import settings

    kp = generate_ed25519_keypair()
    monkeypatch.setattr(settings, "license_ed25519_private_key", kp["private_b64"])
    monkeypatch.setattr(settings, "license_ed25519_public_key", kp["public_b64"])

    seen: list[str] = []

    def fake_publish(**kwargs):
        seen.append(str(kwargs.get("type") or ""))

    monkeypatch.setattr("app.realtime_bus.publish", fake_publish)
    u = register_user("lic_rt", "password123")
    from app.license_service import issue_license

    issue_license(u.id, plan="pro")
    assert "license.updated" in seen


def test_agent_update_available_publish(tmp_path, monkeypatch):
    _reload(monkeypatch, tmp_path)
    from app.agent_security import generate_ed25519_keypair
    from app.agent_updates import publish_script_release
    from app.config import settings

    kp = generate_ed25519_keypair()
    monkeypatch.setattr(settings, "agent_ed25519_private_key", kp["private_b64"])
    monkeypatch.setattr(settings, "agent_ed25519_public_key", kp["public_b64"])

    seen: list[str] = []

    def fake_publish(**kwargs):
        seen.append(str(kwargs.get("type") or ""))

    monkeypatch.setattr("app.realtime_bus.publish", fake_publish)
    publish_script_release(version="9.9.8", notes="rt")
    assert "agent.update.available" in seen


def test_event_registry_includes_p0_types():
    from app.event_schema import EVENT_TYPE_REGISTRY

    for t in (
        "license.updated",
        "agent.update.available",
        "command.pending",
        "command.approved",
        "verification.pass",
        "compliance.updated",
        "agent.online",
        "evidence.created",
    ):
        assert t in EVENT_TYPE_REGISTRY


def test_publish_agent_command_aliases(tmp_path, monkeypatch):
    _reload(monkeypatch, tmp_path)
    seen: list[str] = []

    def fake_publish(**kwargs):
        seen.append(str(kwargs.get("type") or ""))

    monkeypatch.setattr("app.realtime_bus.publish", fake_publish)
    from app.agents import _publish_agent_command

    _publish_agent_command(agent_id="a1", command_id="c1", status="pending_approval", kind="enable_firewall")
    assert "agent_command" in seen
    assert "command.pending" in seen
