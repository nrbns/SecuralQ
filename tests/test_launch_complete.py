"""Unified launch + all-phases completion board."""

from __future__ import annotations

from tests._http_test_utils import configure_isolated_settings


def test_launch_complete_board(tmp_path, monkeypatch):
    configure_isolated_settings(monkeypatch, tmp_path)
    from app.db import init_schema
    from app.launch_complete import launch_complete_board
    from app.tenancy import ensure_tenant_schema

    init_schema()
    ensure_tenant_schema()
    board = launch_complete_board()
    assert board["ok"] is True
    assert board["engineering_complete"] is True
    assert board["launch"]["open_count"] == 0
    assert board["launch"]["p0_count"] == 50
    assert board["world_class"]["all_lab"] is True
    assert board["total_phase"]["all_lab"] is True
    assert board["total_phase"]["master_build_count"] == 46
    assert board["checklists"]["all_complete"] is True
    ids = {i["id"] for i in board["checklists"]["items"]}
    assert ids == {"master", "world_class", "priority", "closed_beta", "total_phase", "launch"}
    assert all(i["complete"] for i in board["checklists"]["items"])
    leftover = set(board["still_ops"])
    assert leftover
    assert "digital_twin" in leftover
    assert "macos_m1_m2" in leftover
    assert "scale_5k" in leftover
    assert len(leftover) <= 10
    assert board["still_ops_detail"]


def test_launch_complete_http(tmp_path, monkeypatch):
    configure_isolated_settings(monkeypatch, tmp_path, auth_enabled=False)
    from fastapi.testclient import TestClient

    from app.db import init_schema
    from app.main import app
    from app.tenancy import ensure_tenant_schema

    init_schema()
    ensure_tenant_schema()
    client = TestClient(app)
    r = client.get("/api/launch/complete")
    assert r.status_code == 200
    body = r.json()
    assert body["engineering_complete"] is True
    assert body["launch"]["open_count"] == 0
    phases = client.get("/api/phases")
    assert phases.status_code == 200
    assert phases.json()["all_lab"] is True
    total = client.get("/api/phases/total")
    assert total.status_code == 200
    assert total.json()["all_lab"] is True
    checks = client.get("/api/checklists")
    assert checks.status_code == 200
    assert checks.json()["all_complete"] is True
