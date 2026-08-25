"""Combo assessment workflow — scan → evidence → investigate → triage."""

from __future__ import annotations

import importlib

import pytest


@pytest.mark.asyncio
async def test_run_combo_assessment_inline(tmp_path, monkeypatch):
    monkeypatch.setenv("DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setenv("WORKSPACE_ZERO_START", "false")
    monkeypatch.setenv("AUTH_ENABLED", "true")
    monkeypatch.setenv("DEPLOYMENT_MODE", "lab")
    monkeypatch.setenv("DATABASE_URL", "")
    import app.config as config_mod
    import app.db as db_mod

    importlib.reload(config_mod)
    db_mod.reset_conn_for_tests()
    importlib.reload(db_mod)

    from app.auth import register_user
    from app.combo_assessment import run_combo_assessment
    from app.tenancy import ensure_tenant_schema

    ensure_tenant_schema()
    user = register_user("combo_user", "password123", role="user")

    result = await run_combo_assessment(
        user_id=user.id,
        target="127.0.0.1",
        scope=["127.0.0.1", "127.0.0.0/8"],
        authorized=True,
        profile="discovery",
        include_web=False,
        auto_triage_high=True,
        scanners=["securaiq"],  # force builtin only for deterministic CI
    )
    assert result["ok"] is True
    assert result["workflow"] == "combo_assessment"
    assert result["primary_scan_id"]
    assert result["prompt"]
    assert "combo assessment" in result["prompt"]
    assert result["summary"]["scanners_ok"] >= 1
    assert any(s["id"] == "investigate" and s["status"] == "done" for s in result["steps"])


def test_default_scope_for_target():
    from app.combo_assessment import default_scope_for_target

    scope = default_scope_for_target("127.0.0.1")
    assert "127.0.0.1" in scope
    assert "127.0.0.0/8" in scope
    scope2 = default_scope_for_target("http://192.168.56.101/path")
    assert "192.168.56.101" in scope2
    assert "192.168.0.0/16" in scope2


@pytest.mark.asyncio
async def test_combo_requires_auth_and_scope(tmp_path, monkeypatch):
    monkeypatch.setenv("DATA_DIR", str(tmp_path / "data2"))
    monkeypatch.setenv("WORKSPACE_ZERO_START", "false")
    monkeypatch.setenv("AUTH_ENABLED", "true")
    monkeypatch.setenv("DEPLOYMENT_MODE", "lab")
    monkeypatch.setenv("DATABASE_URL", "")
    import app.config as config_mod
    import app.db as db_mod

    importlib.reload(config_mod)
    db_mod.reset_conn_for_tests()
    importlib.reload(db_mod)

    from app.auth import register_user
    from app.combo_assessment import run_combo_assessment
    from app.tenancy import ensure_tenant_schema

    ensure_tenant_schema()
    user = register_user("combo_block", "password123", role="user")

    no_auth = await run_combo_assessment(
        user_id=user.id,
        target="127.0.0.1",
        scope=["127.0.0.1"],
        authorized=False,
        scanners=["securaiq"],
    )
    assert no_auth.get("blocked") is True

    # Empty target cannot derive scope
    no_target = await run_combo_assessment(
        user_id=user.id,
        target="",
        scope=[],
        authorized=True,
        profile="vulnerability",
        scanners=["nmap"],
    )
    assert no_target.get("blocked") is True
