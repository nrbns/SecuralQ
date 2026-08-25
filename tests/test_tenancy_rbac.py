"""Sprint-1 foundation: RBAC + tenant isolation + password reset + deploy auth guard."""

from __future__ import annotations

import importlib

import pytest


def _reload_db(monkeypatch, data_dir):
    monkeypatch.setenv("DATA_DIR", str(data_dir))
    monkeypatch.setenv("WORKSPACE_ZERO_START", "false")
    monkeypatch.setenv("AUTH_ENABLED", "true")
    monkeypatch.setenv("DEPLOYMENT_MODE", "lab")
    # Reset cached settings + sqlite connection
    import app.config as config_mod
    import app.db as db_mod

    importlib.reload(config_mod)
    db_mod.reset_conn_for_tests()
    importlib.reload(db_mod)
    return config_mod, db_mod


def test_assert_safe_deployment_blocks_prod_without_auth(tmp_path, monkeypatch):
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    monkeypatch.setenv("DATA_DIR", str(data_dir))
    monkeypatch.setenv("AUTH_ENABLED", "false")
    monkeypatch.setenv("DEPLOYMENT_MODE", "production")
    monkeypatch.setenv("HOST", "127.0.0.1")
    monkeypatch.setenv("REQUIRE_POSTGRES_IN_PRODUCTION", "false")
    import app.config as config_mod
    import app.auth as auth_mod

    importlib.reload(config_mod)
    importlib.reload(auth_mod)
    with pytest.raises(RuntimeError, match="AUTH_ENABLED"):
        auth_mod.assert_safe_deployment_auth()


def test_assert_safe_deployment_blocks_prod_without_postgres(tmp_path, monkeypatch):
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    monkeypatch.setenv("DATA_DIR", str(data_dir))
    monkeypatch.setenv("AUTH_ENABLED", "true")
    monkeypatch.setenv("DEPLOYMENT_MODE", "production")
    monkeypatch.setenv("HOST", "127.0.0.1")
    monkeypatch.setenv("DATABASE_URL", "")
    monkeypatch.setenv("REQUIRE_POSTGRES_IN_PRODUCTION", "true")
    import app.config as config_mod
    import app.auth as auth_mod

    importlib.reload(config_mod)
    importlib.reload(auth_mod)
    with pytest.raises(RuntimeError, match="DATABASE_URL"):
        auth_mod.assert_safe_deployment_auth()


def test_assert_safe_deployment_blocks_open_bind_without_auth(tmp_path, monkeypatch):
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    monkeypatch.setenv("DATA_DIR", str(data_dir))
    monkeypatch.setenv("AUTH_ENABLED", "false")
    monkeypatch.setenv("DEPLOYMENT_MODE", "lab")
    monkeypatch.setenv("HOST", "0.0.0.0")
    monkeypatch.setenv("ALLOW_OPEN_LAN", "false")
    import app.config as config_mod
    import app.auth as auth_mod

    importlib.reload(config_mod)
    importlib.reload(auth_mod)
    with pytest.raises(RuntimeError, match="AUTH_ENABLED"):
        auth_mod.assert_safe_deployment_auth()


def test_assert_safe_deployment_allows_open_lan_flag(tmp_path, monkeypatch):
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    monkeypatch.setenv("DATA_DIR", str(data_dir))
    monkeypatch.setenv("AUTH_ENABLED", "false")
    monkeypatch.setenv("DEPLOYMENT_MODE", "lab")
    monkeypatch.setenv("HOST", "0.0.0.0")
    monkeypatch.setenv("ALLOW_OPEN_LAN", "true")
    import app.config as config_mod
    import app.auth as auth_mod

    importlib.reload(config_mod)
    importlib.reload(auth_mod)
    auth_mod.assert_safe_deployment_auth()


def test_rbac_viewer_cannot_write(tmp_path, monkeypatch):
    data_dir = tmp_path / "d"
    data_dir.mkdir()
    _reload_db(monkeypatch, data_dir)
    from app.auth import AuthUser, register_user
    from app.commercial_ext import add_org_member, create_org
    from app.rbac import has_perm

    admin = register_user("orgadmin1", "password123", role="user")
    org = create_org(admin.id, "Acme")
    viewer = register_user("viewer1", "password123", role="user")
    add_org_member(admin.id, org["id"], "viewer1", role="viewer")
    u = AuthUser(id=viewer.id, username="viewer1", role="user")
    assert has_perm(u, "asset.read", org_id=org["id"])
    assert not has_perm(u, "asset.write", org_id=org["id"])
    assert not has_perm(u, "vuln.triage", org_id=org["id"])


def test_tenant_isolation_assets(tmp_path, monkeypatch):
    data_dir = tmp_path / "d2"
    data_dir.mkdir()
    _reload_db(monkeypatch, data_dir)
    from app.auth import register_user
    from app.commercial_ext import create_org
    from app.enterprise import create_asset, list_assets
    from app.tenancy import ensure_tenant_schema

    ensure_tenant_schema()
    a = register_user("alice_t", "password123", role="user")
    b = register_user("bob_t", "password123", role="user")
    org_a = create_org(a.id, "OrgA")
    org_b = create_org(b.id, "OrgB")
    create_asset(a.id, "asset-a-only", org_id=org_a["id"])
    create_asset(b.id, "asset-b-only", org_id=org_b["id"])

    alice_assets = {x["name"] for x in list_assets(a.id, org_id=org_a["id"])}
    bob_assets = {x["name"] for x in list_assets(b.id, org_id=org_b["id"])}
    assert "asset-a-only" in alice_assets
    assert "asset-b-only" not in alice_assets
    assert "asset-b-only" in bob_assets
    assert "asset-a-only" not in bob_assets


def test_password_reset_flow(tmp_path, monkeypatch):
    data_dir = tmp_path / "d3"
    data_dir.mkdir()
    _reload_db(monkeypatch, data_dir)
    from app.auth import login, register_user, request_password_reset, reset_password_with_token, verify_password
    from app.db import get_conn
    from app.tenancy import ensure_tenant_schema

    ensure_tenant_schema()
    register_user("resetme", "oldpassword1", role="user")
    out = request_password_reset("resetme")
    assert out.get("ok")
    token = out.get("reset_token")
    assert token
    reset_password_with_token(token, "newpassword9")
    row = get_conn().execute("SELECT password_hash FROM users WHERE username = ?", ("resetme",)).fetchone()
    assert verify_password("newpassword9", row["password_hash"])
    assert not verify_password("oldpassword1", row["password_hash"])
    user, _tok = login("resetme", "newpassword9")
    assert user.username == "resetme"
