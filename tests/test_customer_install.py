"""Customer / other-device install board."""

from __future__ import annotations

from pathlib import Path

from tests._http_test_utils import configure_isolated_settings


def test_customer_install_board_and_http(tmp_path, monkeypatch):
    configure_isolated_settings(monkeypatch, tmp_path, auth_enabled=False)
    monkeypatch.setattr("app.config.settings.host", "127.0.0.1")
    from app.customer_install import customer_install_board
    from app.db import init_schema
    from app.platform_info import clear_platform_cache
    from app.tenancy import ensure_tenant_schema

    init_schema()
    ensure_tenant_schema()
    clear_platform_cache()
    board = customer_install_board()
    ids = {f["id"] for f in board["functions"]}
    assert "lan_bind" in ids
    assert "control_why" in ids
    assert "golden_loop" in ids
    assert board["scripts"]["windows"] is True
    assert board["other_device"]["never"]
    assert board["lan_mode"] is False
    assert board["customer_ready"] is False

    monkeypatch.setattr("app.config.settings.host", "0.0.0.0")
    clear_platform_cache()
    lan = customer_install_board()
    assert lan["lan_mode"] is True


def test_customer_check_http(tmp_path, monkeypatch):
    configure_isolated_settings(monkeypatch, tmp_path, auth_enabled=False)
    from fastapi.testclient import TestClient

    from app.db import init_schema
    from app.main import app
    from app.tenancy import ensure_tenant_schema

    init_schema()
    ensure_tenant_schema()
    client = TestClient(app)
    r = client.get("/api/install/customer-check")
    assert r.status_code == 200
    body = r.json()
    assert "functions" in body
    assert "other_device" in body
    win = client.get("/api/agents/install-script/windows")
    assert win.status_code == 200
    text = win.text
    assert "SecuraIQ-Agent.exe" in text
    assert "127.0.0.1" in text
    linux = client.get("/api/agents/install-script/linux")
    assert linux.status_code == 200
    assert "SECURAIQ_SERVER" in linux.text
    mac = client.get("/api/agents/install-script/macos")
    assert mac.status_code == 200
    assert "SecuraIQ-Agent" in mac.text
    start_ps1 = (Path(__file__).resolve().parents[1] / "scripts" / "start.ps1").read_text(encoding="utf-8")
    assert "$runArgs += \"--lan\"" in start_ps1 or "--lan" in start_ps1
    assert "wait_open.py" in start_ps1
