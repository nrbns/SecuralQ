"""Live Open-AudIT-style inventory during LAN/VA scans."""

from __future__ import annotations

import importlib


def test_guess_os_windows_from_smb_ports():
    from app.lan_inventory import guess_os_and_type

    os_name, dtype = guess_os_and_type([135, 139, 445])
    assert os_name == "Windows"
    assert dtype == "computer"


def test_ingest_live_device_publishes_inventory(tmp_path, monkeypatch):
    monkeypatch.setenv("DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setenv("DATABASE_URL", "")
    monkeypatch.setenv("WORKSPACE_ZERO_START", "false")
    monkeypatch.setenv("AUTH_ENABLED", "true")
    import app.config as config_mod
    import app.db as db_mod

    importlib.reload(config_mod)
    db_mod.reset_conn_for_tests()
    importlib.reload(db_mod)
    db_mod.init_schema()

    from app.auth import register_user
    from app.openaudit import ingest_live_device, list_devices
    from app.tenancy import ensure_tenant_schema

    ensure_tenant_schema()
    user = register_user("oa_live", "password123", role="user")
    out = ingest_live_device(
        user.id,
        {
            "device_id": "live:192.168.0.45",
            "name": "lab-pc",
            "hostname": "lab-pc",
            "ip": "192.168.0.45",
            "type": "computer",
            "os": "Windows",
            "description": "ports=445,3389; shares=Users",
            "raw": {"source": "securaiq_audit", "open_ports": [445, 3389], "shares": ["Users"]},
        },
    )
    assert out["ok"] is True
    assert out["asset_id"]
    rows = list_devices()
    assert any(r.get("ip") == "192.168.0.45" for r in rows)
    hit = next(r for r in rows if r.get("ip") == "192.168.0.45")
    assert hit.get("open_ports") == [445, 3389]
    assert "Users" in (hit.get("shares") or [])

    from app.openaudit import status as oa_status

    st = oa_status()
    assert st.get("live") is True
    assert st.get("devices_cached", 0) >= 1


def test_refresh_lan_queues_inventory_job(tmp_path, monkeypatch):
    monkeypatch.setenv("DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setenv("DATABASE_URL", "")
    monkeypatch.setenv("WORKSPACE_ZERO_START", "false")
    monkeypatch.setenv("AUTH_ENABLED", "false")
    monkeypatch.setenv("HOST", "0.0.0.0")
    import app.config as config_mod
    import app.db as db_mod
    import app.jobs as jobs_mod

    importlib.reload(config_mod)
    db_mod.reset_conn_for_tests()
    importlib.reload(db_mod)
    db_mod.init_schema()
    importlib.reload(jobs_mod)

    import app.lan_sync as lan_sync

    monkeypatch.setattr(lan_sync, "host_scan_target", lambda: "192.168.0.227")
    monkeypatch.setattr(lan_sync, "warm_lan_subnet", lambda **_: {"ok": True, "subnet": "192.168.0.0/24", "attempted": 2})
    monkeypatch.setattr(lan_sync, "list_lan_neighbors", lambda: [{"ip": "192.168.0.1", "mac": "aa:bb:cc:dd:ee:ff"}])
    monkeypatch.setattr(lan_sync, "queue_target_scan", lambda *a, **k: {"ok": True, "target": a[0] if a else ""})

    out = lan_sync.refresh_lan_assets("local", queue_scan=False)
    job = out.get("inventory_job") or {}
    assert job.get("kind") == "lan_inventory_audit" or job.get("id")
