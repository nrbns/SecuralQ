"""Realtime fabric + agent security lab-production closes."""

from __future__ import annotations

from tests._http_test_utils import configure_isolated_settings


def test_realtime_fabric_status_lab_production(tmp_path, monkeypatch):
    configure_isolated_settings(monkeypatch, tmp_path)
    from app.realtime_ops import fabric_status

    fab = fabric_status()
    assert fab["lab_production"] is True
    assert fab["ha_exactly_once"] is False
    assert "dlq_soft_recover" in fab["capabilities"]
    assert "last_event_id_replay" in fab["capabilities"]


def test_agent_security_lab_production_flags_off(tmp_path, monkeypatch):
    configure_isolated_settings(monkeypatch, tmp_path)
    monkeypatch.delenv("AGENT_LAB_SEALED_MODE", raising=False)
    monkeypatch.delenv("AGENT_REQUIRE_COMMAND_SIGNATURE", raising=False)
    from app.production_profile import agent_security_readiness, production_profile_status

    ag = agent_security_readiness()
    assert ag["lab_production"] is True
    assert ag["lab_flags_default_off"] is True
    assert ag["commercial_ready"] is False
    assert ag["allowlist"]["count"] >= 5
    assert ag["seals"]["apis_ready"] is True
    assert ag["mtls"]["apis_ready"] is True
    st = production_profile_status()
    assert st["lab_production_agent_security"] is True
    assert st["production_ready_agent_security"] is False


def test_agent_lab_sealed_mode_enables_seals(tmp_path, monkeypatch):
    configure_isolated_settings(monkeypatch, tmp_path)
    monkeypatch.setenv("AGENT_LAB_SEALED_MODE", "true")
    from app.agent_security import _require_command_signature, _require_replay_protection
    from app.production_profile import agent_security_readiness

    assert _require_command_signature() is True
    assert _require_replay_protection() is True
    ag = agent_security_readiness()
    assert ag["lab_sealed_active"] is True
    assert ag["commercial_ready"] is False  # mTLS still off


def test_mission_control_includes_fabric_and_agent_security(tmp_path, monkeypatch):
    configure_isolated_settings(monkeypatch, tmp_path)
    from app.mission_control import mission_control_snapshot

    snap = mission_control_snapshot()
    assert "realtime_fabric" in snap["components"]
    assert snap["components"]["realtime_fabric"]["lab_production"] is True
    assert "agent_security" in snap["components"]
    assert snap["components"]["agent_security"]["lab_production"] is True
