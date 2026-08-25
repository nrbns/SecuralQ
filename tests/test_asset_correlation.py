"""Asset correlation: IP ↔ hostname merge across scans."""

from __future__ import annotations

import importlib
import json


def test_ensure_asset_correlates_by_ip_and_hostname(tmp_path, monkeypatch):
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
    from app.enterprise import ensure_asset_for_target, list_assets
    from app.tenancy import ensure_tenant_schema

    ensure_tenant_schema()
    user = register_user("asset_corr", "password123", role="user")

    a1 = ensure_asset_for_target(
        user.id,
        "192.168.56.101",
        notes=json.dumps({"ip": "192.168.56.101", "host": "192.168.56.101", "source": "scan:nmap"}),
    )
    assert a1 and a1["id"]
    a2 = ensure_asset_for_target(
        user.id,
        "lab.local",
        notes=json.dumps({"ip": "192.168.56.101", "host": "lab.local", "source": "scan:nuclei"}),
    )
    assert a2["id"] == a1["id"]
    assert "lab.local" in (a2.get("name") or "")
    notes = json.loads(a2.get("notes") or "{}")
    assert notes.get("ip") == "192.168.56.101"
    assert notes.get("host") == "lab.local"
    assets = list_assets(user.id)
    assert len(assets) == 1
