"""Lab-unblocked P0 launch items — identity card, drawer, intents, profile."""

from __future__ import annotations

import pytest

from tests._http_test_utils import configure_isolated_settings


def test_production_mode_enforces_commercial_profile(tmp_path, monkeypatch):
    configure_isolated_settings(monkeypatch, tmp_path)
    from app.config import settings
    from app.production_profile import assert_commercial_profile, commercial_profile_enforced

    monkeypatch.setattr(settings, "deployment_mode", "production", raising=False)
    monkeypatch.setattr(settings, "allow_lab_insecure", False, raising=False)
    monkeypatch.delenv("SECURAIQ_ALLOW_LAB_INSECURE", raising=False)
    monkeypatch.delenv("SECURAIQ_COMMERCIAL_PROFILE", raising=False)
    assert commercial_profile_enforced() is True
    with pytest.raises(RuntimeError, match="COMMERCIAL_PROFILE|commercial"):
        assert_commercial_profile()

    monkeypatch.setattr(settings, "allow_lab_insecure", True, raising=False)
    assert commercial_profile_enforced() is False
    assert_commercial_profile()


def test_identity_card_and_drawer_http(tmp_path, monkeypatch):
    configure_isolated_settings(monkeypatch, tmp_path, auth_enabled=False)
    from fastapi.testclient import TestClient

    from app.db import init_schema
    from app.enterprise import create_asset
    from app.main import app
    from app.tenancy import ensure_tenant_schema

    init_schema()
    ensure_tenant_schema()
    client = TestClient(app)
    # Lab open-auth user is created on first request
    created = create_asset("local", "PC-001", owner="lab")
    aid = created["id"] if isinstance(created, dict) else created
    card = client.get(f"/api/assets/{aid}/identity-card")
    assert card.status_code == 200
    body = card.json()
    assert body["ok"] is True
    assert body["name"]
    assert "exposure" in body
    drawer = client.get("/api/decisions/drawer", params={"kind": "asset", "target_id": aid})
    assert drawer.status_code == 200
    d = drawer.json()
    assert d["ok"] is True
    assert d["what"]
    assert d["verify"]
    risk = client.get("/api/decisions/drawer", params={"kind": "risk"})
    assert risk.status_code == 200
    assert risk.json()["kind"] == "risk"
    why = client.get("/api/compliance/why")
    assert why.status_code == 200
    assert "live_percent" in why.json()
    pulse = client.get("/api/command-center/pulse")
    assert pulse.status_code == 200
    assert pulse.json()["ok"] is True
    assert "what_changed" in pulse.json()


def test_scan_intents_and_legal_hold(tmp_path, monkeypatch):
    configure_isolated_settings(monkeypatch, tmp_path, auth_enabled=False)
    from fastapi.testclient import TestClient

    from app.db import init_schema
    from app.evidence_spine.legal_hold import is_on_legal_hold, place_legal_hold
    from app.evidence_spine.vault import run_vault_expiry_tick
    from app.main import app
    from app.realtime_bus import tenant_stream_key
    from app.scan_intents import list_scan_intents, resolve_scan_intent
    from app.tenancy import ensure_tenant_schema

    init_schema()
    ensure_tenant_schema()
    intents = list_scan_intents()
    ids = {i["id"] for i in intents["intents"]}
    assert {"quick", "full", "easm", "web", "endpoint", "compliance"} <= ids
    assert resolve_scan_intent("web")["scanner"] == "zap"
    client = TestClient(app)
    r = client.get("/api/scans/intents")
    assert r.status_code == 200
    assert r.json()["ok"] is True
    hold = place_legal_hold("default", "ev-hold-1", reason="litigation")
    assert hold["ok"] is True
    assert is_on_legal_hold("default", "ev-hold-1") is True
    tick = run_vault_expiry_tick()
    assert tick["ok"] is True
    assert tenant_stream_key("org-a") != tenant_stream_key("org-b")
    assert tenant_stream_key("") != tenant_stream_key("org-a")
    finding = client.get("/api/risk/finding/missing/why")
    assert finding.status_code == 200
    assert finding.json()["ok"] is False
