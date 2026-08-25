"""LAN device-to-device: open bind, auto-scan this host only, start scripts."""

from __future__ import annotations

import importlib
from pathlib import Path


REPO = Path(__file__).resolve().parent.parent


def _reload_db(monkeypatch, data_dir, **env):
    monkeypatch.setenv("DATA_DIR", str(data_dir))
    monkeypatch.setenv("DATABASE_URL", "")
    monkeypatch.setenv("WORKSPACE_ZERO_START", "false")
    monkeypatch.setenv("AUTH_ENABLED", "false")
    for key, value in env.items():
        monkeypatch.setenv(key, value)
    import app.config as config_mod
    import app.db as db_mod

    importlib.reload(config_mod)
    db_mod.reset_conn_for_tests()
    importlib.reload(db_mod)
    db_mod.init_schema()
    return config_mod


def test_lan_auto_scan_skips_localhost(tmp_path, monkeypatch):
    _reload_db(monkeypatch, tmp_path / "data", HOST="127.0.0.1", LAN_AUTO_SCAN="true")
    from app.lan_sync import maybe_queue_lan_auto_scan

    out = maybe_queue_lan_auto_scan()
    assert out["ok"] is False
    assert out["skipped"] == "not_lan_bind"


def test_lan_auto_scan_skips_when_off(tmp_path, monkeypatch):
    _reload_db(monkeypatch, tmp_path / "data", HOST="0.0.0.0", LAN_AUTO_SCAN="false")
    from app.lan_sync import maybe_queue_lan_auto_scan

    out = maybe_queue_lan_auto_scan()
    assert out["ok"] is False
    assert out["skipped"] == "lan_auto_scan_off"


def test_lan_auto_scan_queues_this_host(tmp_path, monkeypatch):
    _reload_db(
        monkeypatch,
        tmp_path / "data",
        HOST="0.0.0.0",
        LAN_AUTO_SCAN="true",
        ALLOW_OPEN_LAN="true",
    )
    from app.lan_sync import maybe_queue_lan_auto_scan
    from app.scan_engine.models import get_scan, list_scans

    out = maybe_queue_lan_auto_scan()
    assert out["ok"] is True
    assert out.get("scanner") == "securaiq"
    assert out.get("target")
    scan = get_scan(out["scan_id"])
    assert scan is not None
    assert scan["authorized"] in (1, True)
    assert list_scans("local")

    again = maybe_queue_lan_auto_scan()
    assert again["ok"] is False
    assert again["skipped"] == "scan_in_flight"


def test_rank_lan_ips_prefers_wifi_over_vbox():
    from app.platform_info import rank_lan_ips

    ranked = rank_lan_ips(
        ["192.168.56.1", "192.168.0.227", "169.254.1.1"],
        preferred="192.168.0.227",
    )
    assert ranked[0] == "192.168.0.227"
    assert "192.168.56.1" in ranked
    assert ranked.index("192.168.0.227") < ranked.index("192.168.56.1")


def test_parse_arp_table_windows_and_linux():
    from app.lan_sync import parse_arp_table

    win = """
Interface: 192.168.0.227 --- 0xe
  Internet Address      Physical Address      Type
  192.168.0.1           aa-bb-cc-dd-ee-ff     dynamic
  192.168.0.255         ff-ff-ff-ff-ff-ff     static
  224.0.0.22            01-00-5e-00-00-16     static
"""
    rows = parse_arp_table(win)
    assert rows == [{"ip": "192.168.0.1", "mac": "aa:bb:cc:dd:ee:ff"}]

    linux = "192.168.0.10 dev eth0 lladdr 11:22:33:44:55:66 REACHABLE\n"
    assert parse_arp_table(linux)[0]["ip"] == "192.168.0.10"


def test_lan_subnet_hint_uses_preferred_host(monkeypatch):
    import app.lan_sync as lan_sync

    monkeypatch.setattr(lan_sync, "host_scan_target", lambda: "192.168.0.227")
    assert lan_sync.lan_subnet_hint() == "192.168.0.0/24"


def test_refresh_lan_assets_queues_inventory_without_blocking_warm(tmp_path, monkeypatch):
    _reload_db(monkeypatch, tmp_path / "data", HOST="0.0.0.0", ALLOW_OPEN_LAN="true")
    import app.lan_sync as lan_sync

    monkeypatch.setattr(lan_sync, "host_scan_target", lambda: "192.168.0.227")
    monkeypatch.setattr(lan_sync, "lan_subnet_hint", lambda: "192.168.0.0/24")
    monkeypatch.setattr(
        lan_sync,
        "list_lan_neighbors",
        lambda: [
            {"ip": "192.168.0.1", "mac": "aa:bb:cc:dd:ee:ff"},
            {"ip": "192.168.0.45", "mac": "11:22:33:44:55:66"},
        ],
    )
    warm_calls = []
    monkeypatch.setattr(lan_sync, "warm_lan_subnet", lambda **_: warm_calls.append(1) or {"ok": True})

    out = lan_sync.refresh_lan_assets("local", queue_scan=False)
    assert out["ok"] is True
    assert out["subnet"] == "192.168.0.0/24"
    assert out["sweep_attempted"] == 0
    assert out["sweep_queued"] is True
    assert warm_calls == []  # warm runs in background job, not on HTTP path
    assert len(out["neighbors"]) == 2
    assert out["assets_upserted"] >= 3
    assert (out.get("inventory_job") or {}).get("id") or (out.get("inventory_job") or {}).get("kind")


def test_refresh_lan_assets_queues_scans_for_discovered_hosts(tmp_path, monkeypatch):
    _reload_db(monkeypatch, tmp_path / "data", HOST="0.0.0.0", ALLOW_OPEN_LAN="true")
    import app.lan_sync as lan_sync

    monkeypatch.setattr(lan_sync, "host_scan_target", lambda: "192.168.0.227")
    monkeypatch.setattr(lan_sync, "lan_subnet_hint", lambda: "192.168.0.0/24")
    monkeypatch.setattr(lan_sync, "warm_lan_subnet", lambda **_: {"ok": True, "subnet": "192.168.0.0/24", "attempted": 254})
    monkeypatch.setattr(
        lan_sync,
        "list_lan_neighbors",
        lambda: [
            {"ip": "192.168.0.1", "mac": "aa:bb:cc:dd:ee:ff"},
            {"ip": "192.168.0.45", "mac": "11:22:33:44:55:66"},
        ],
    )

    queued = []

    def _queue(target, **kwargs):
        queued.append((target, kwargs))
        return {"ok": True, "target": target, "job_id": f"job-{target}"}

    monkeypatch.setattr(lan_sync, "queue_target_scan", _queue)
    out = lan_sync.refresh_lan_assets("local", queue_scan=True)
    assert out["ok"] is True
    assert len(out["queued_scans"]) == 3
    assert [item[0] for item in queued] == ["192.168.0.227", "192.168.0.1", "192.168.0.45"]


def test_cors_star_when_open_lan(tmp_path, monkeypatch):
    _reload_db(
        monkeypatch,
        tmp_path / "data",
        HOST="0.0.0.0",
        ALLOW_OPEN_LAN="true",
        CORS_ORIGINS="http://127.0.0.1:8080",
    )
    from app.config import cors_origin_list

    assert cors_origin_list() == ["*"]


def test_lan_start_scripts_enable_device_share():
    ps1 = (REPO / "scripts" / "start.ps1").read_text(encoding="utf-8")
    sh = (REPO / "scripts" / "start.sh").read_text(encoding="utf-8")
    for body in (ps1, sh):
        assert "ALLOW_OPEN_LAN" in body
        assert "LAN_AUTO_SCAN" in body
        assert "WORKSPACE_ZERO_START" in body
