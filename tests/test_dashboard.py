"""Mission Control dashboard API smoke tests."""

from __future__ import annotations

import importlib


def _boot(tmp_path, monkeypatch):
    monkeypatch.setenv("DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setenv("AUTH_ENABLED", "false")
    monkeypatch.setenv("WORKSPACE_ZERO_START", "false")
    monkeypatch.setenv("DATABASE_URL", "")
    import app.config as config_mod
    import app.db as db_mod

    importlib.reload(config_mod)
    db_mod.reset_conn_for_tests()
    importlib.reload(db_mod)
    db_mod.init_schema()
    return config_mod


def test_dashboard_empty_workspace(tmp_path, monkeypatch):
    _boot(tmp_path, monkeypatch)
    from app.enterprise import enterprise_dashboard

    dash = enterprise_dashboard("local")
    assert dash["is_empty"] is True
    assert dash["security_index"] == 0
    assert (dash.get("mission_control") or {}).get("today") is not None


def test_dashboard_with_asset(tmp_path, monkeypatch):
    _boot(tmp_path, monkeypatch)
    from app.enterprise import create_asset, enterprise_dashboard

    create_asset("local", "lab-host-1", asset_type="server")
    dash = enterprise_dashboard("local")
    assert dash["is_empty"] is False
    assert dash["assets_total"] >= 1
    recent = dash.get("recent_assets") or []
    assert len(recent) >= 1
    assert recent[0]["name"] == "lab-host-1"
    hk = dash.get("hardening") or {}
    assert "installed" in hk
    assert "audit_done" in hk
    assert hk.get("setup_script")
    today = (dash.get("mission_control") or {}).get("today") or {}
    assert "critical_findings" in today
    assert "open_risks" in today
    posture = dash.get("compliance_posture") or {}
    assert posture.get("overall_percent") is None
    assert "fix_first" in dash
    assert isinstance(dash["fix_first"], list)
    fleet = dash.get("agents_fleet") or {}
    assert "total" in fleet
    assert "online" in fleet
    assert "org_risk" in dash


def test_dashboard_empty_honest_compliance(tmp_path, monkeypatch):
    _boot(tmp_path, monkeypatch)
    from app.enterprise import enterprise_dashboard

    dash = enterprise_dashboard("local")
    assert dash["is_empty"] is True
    posture = dash.get("compliance_posture") or {}
    assert posture.get("overall_percent") is None
    assert posture.get("frameworks_assessed") == 0
    assert dash.get("fix_first") == []
    assert "evidence_queue_count" in posture
    assert posture.get("evidence_queue_count") == 0