"""Engagement scope + tool policy + service-layer smoke tests."""

from __future__ import annotations

import importlib

import pytest

from app.services.tool_policy import (
    assert_structured_scope,
    assert_tool_target_allowed,
    normalize_scope_json,
    requires_structured_scope,
    target_in_scope,
)


def test_requires_structured_scope_for_engine_and_va():
    assert requires_structured_scope("nmap", "discovery") is True
    assert requires_structured_scope("nuclei", "web") is True
    assert requires_structured_scope("zap", "web") is True
    assert requires_structured_scope("securaiq", "discovery") is False
    assert requires_structured_scope("securaiq", "vulnerability") is True
    assert requires_structured_scope("securaiq", "full") is True
    ok, _ = assert_structured_scope(scanner_id="nmap", profile="discovery", scope=[])
    assert not ok
    ok2, reason = assert_structured_scope(
        scanner_id="nmap", profile="discovery", scope=["192.168.56.0/24"]
    )
    assert ok2 and "present" in reason
    ok3, _ = assert_structured_scope(scanner_id="securaiq", profile="discovery", scope=[])
    assert ok3


def test_normalize_scope_json_variants():
    assert normalize_scope_json(["10.0.0.0/24", "api.example.com"]) == [
        "10.0.0.0/24",
        "api.example.com",
    ]
    assert normalize_scope_json('["lab.local", "127.0.0.1"]') == ["lab.local", "127.0.0.1"]
    assert normalize_scope_json("a.com\nb.com, c.com") == ["a.com", "b.com", "c.com"]
    assert normalize_scope_json("") == []
    assert normalize_scope_json(None) == []


def test_target_in_scope_host_cidr_and_wildcard():
    ok, reason = target_in_scope(target="api.example.com", ip="1.2.3.4", scope=["*.example.com"])
    assert ok and "host" in reason
    ok, _ = target_in_scope(target="evil.com", ip="1.2.3.4", scope=["*.example.com"])
    assert not ok
    ok, reason = target_in_scope(target="x", ip="10.0.0.5", scope=["10.0.0.0/24"])
    assert ok and "cidr" in reason
    ok, _ = target_in_scope(target="x", ip="11.0.0.5", scope=["10.0.0.0/24"])
    assert not ok
    ok, reason = target_in_scope(target=None, ip=None, scope=["10.0.0.0/24"])
    assert not ok and reason == "no_target_to_check"
    ok, reason = target_in_scope(target="any", ip="1.1.1.1", scope=[])
    assert ok and reason == "no_structured_scope"


def test_assert_tool_target_allowed_with_engagement(tmp_path, monkeypatch):
    monkeypatch.setenv("DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setenv("WORKSPACE_ZERO_START", "false")
    monkeypatch.setenv("AUTH_ENABLED", "false")
    monkeypatch.setenv("DATABASE_URL", "")
    import app.config as config_mod
    import app.db as db_mod
    import app.workspace as ws
    from app.auth import register_user

    importlib.reload(config_mod)
    db_mod.reset_conn_for_tests()
    importlib.reload(db_mod)
    importlib.reload(ws)

    user = register_user("scopeuser", "password123", role="user")
    eng = ws.create_engagement(
        user.id,
        "Lab",
        scope_notes="demo",
        scope_json=["127.0.0.1", "10.0.0.0/8"],
    )
    meta = assert_tool_target_allowed(
        user_id=user.id,
        engagement_id=eng["id"],
        target="127.0.0.1",
        ip="127.0.0.1",
        authorized=True,
    )
    assert meta["enforced"] is True

    with pytest.raises(ValueError, match="out of engagement scope"):
        assert_tool_target_allowed(
            user_id=user.id,
            engagement_id=eng["id"],
            target="8.8.8.8",
            ip="8.8.8.8",
            authorized=True,
        )

    # Empty scope → legacy passthrough
    eng2 = ws.create_engagement(user.id, "Open", scope_json=[])
    meta2 = assert_tool_target_allowed(
        user_id=user.id,
        engagement_id=eng2["id"],
        target="8.8.8.8",
        ip="8.8.8.8",
        authorized=True,
    )
    assert meta2["enforced"] is False


def test_services_reexport_assets_findings(tmp_path, monkeypatch):
    monkeypatch.setenv("DATA_DIR", str(tmp_path / "data2"))
    monkeypatch.setenv("WORKSPACE_ZERO_START", "false")
    monkeypatch.setenv("AUTH_ENABLED", "false")
    monkeypatch.setenv("DATABASE_URL", "")
    import app.config as config_mod
    import app.db as db_mod
    from app.auth import register_user
    from app.services import assets, findings
    from app.tenancy import ensure_tenant_schema

    importlib.reload(config_mod)
    db_mod.reset_conn_for_tests()
    importlib.reload(db_mod)
    ensure_tenant_schema()

    user = register_user("svcuser", "password123", role="user")
    a = assets.create_asset(user.id, "svc-host.example", asset_type="server")
    assert a and a["name"] == "svc-host.example"
    f = findings.create_finding(
        user.id,
        {
            "title": "Test finding",
            "severity": "low",
            "asset_name": "svc-host.example",
            "description": "service layer smoke",
        },
    )
    assert f and f.get("title") == "Test finding"


def test_db_backend_defaults_to_sqlite(tmp_path, monkeypatch):
    monkeypatch.setenv("DATA_DIR", str(tmp_path / "data3"))
    monkeypatch.setenv("DATABASE_URL", "")
    monkeypatch.setenv("WORKSPACE_ZERO_START", "false")
    import app.config as config_mod
    import app.db as db_mod

    importlib.reload(config_mod)
    db_mod.reset_conn_for_tests()
    importlib.reload(db_mod)
    assert db_mod.using_postgres() is False
    assert db_mod.current_backend() == "sqlite"
    c = db_mod.get_conn()
    cols = db_mod.table_columns(c, "engagements")
    assert "scope_json" in cols
    assert "status" in cols
