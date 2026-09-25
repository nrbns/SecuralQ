"""Measured-ops ladder — SQLite RTO/RPO + in-process restart reclaim."""

from __future__ import annotations

from tests._http_test_utils import configure_isolated_settings


def test_sqlite_drill_publishes_rto_rpo(tmp_path, monkeypatch):
    monkeypatch.setenv("SECURAIQ_OPS_LOG_DIR", str(tmp_path / "ops"))
    from scripts.backup_restore_drill import run_drill

    result = run_drill(keep=False, persist=True)
    assert result["ok"] is True
    assert result["rto_ms"] is not None
    assert result["rpo_ms"] == 0.0
    assert result["backup_ms"] >= 0
    assert result["restore_ms"] >= 0
    from app.measured_ops import sqlite_dr_published, sqlite_dr_status

    assert sqlite_dr_published() is True
    status = sqlite_dr_status()
    assert status["status"] == "lab"
    assert status["rto_ms"] is not None
    assert "postgres_restore" in status["leftover"]


def test_restart_reclaim_drill(tmp_path, monkeypatch):
    configure_isolated_settings(monkeypatch, tmp_path)
    monkeypatch.setenv("SECURAIQ_OPS_LOG_DIR", str(tmp_path / "ops"))
    from app.db import init_schema
    from app.measured_ops import restart_reclaim_published, restart_reclaim_status
    from app.restart_recovery import run_restart_reclaim_drill
    from app.tenancy import ensure_tenant_schema

    init_schema()
    ensure_tenant_schema()
    result = run_restart_reclaim_drill(persist=True)
    assert result["ok"] is True
    assert result["status_after"] == "pending"
    assert result["reclaim_ms"] is not None
    assert restart_reclaim_published() is True
    rec = restart_reclaim_status()
    assert rec["published"] is True
    assert rec["reclaim_ms"] is not None


def test_measured_ops_http_and_launch_p013(tmp_path, monkeypatch):
    configure_isolated_settings(monkeypatch, tmp_path, auth_enabled=False)
    monkeypatch.setenv("SECURAIQ_OPS_LOG_DIR", str(tmp_path / "ops"))
    from fastapi.testclient import TestClient

    from app.db import init_schema
    from app.launch_plan import launch_p0_rows
    from app.main import app
    from app.restart_recovery import run_restart_reclaim_drill
    from app.tenancy import ensure_tenant_schema
    from scripts.backup_restore_drill import run_drill

    init_schema()
    ensure_tenant_schema()
    assert run_drill(persist=True)["ok"] is True
    assert run_restart_reclaim_drill(persist=True)["ok"] is True
    p013 = next(r for r in launch_p0_rows() if r["id"] == "P0-13")
    assert p013["status"] == "lab"
    assert "postgres_restore" in p013["ops_blocked"]
    p040 = next(r for r in launch_p0_rows() if r["id"] == "P0-40")
    assert p040["status"] == "lab"
    assert "kill_at_5k" in p040["ops_blocked"]
    client = TestClient(app)
    measured = client.get("/api/ops/measured")
    assert measured.status_code == 200
    body = measured.json()
    assert body["ok"] is True
    assert body["sqlite_dr"]["published"] is True
    assert body["restart_reclaim"]["published"] is True
    assert "http_top_measured" in body["http_capacity"]
    assert "http_5k_100k" in body["still_ops"]
    assert "stage_latency" in body
    ingest = (body["stage_latency"] or {}).get("ingest") or {}
    assert "count" in ingest
    if ingest.get("count"):
        assert ingest.get("p95_ms") is not None
    else:
        assert ingest.get("p95_ms") is None
    rec = client.get("/api/ops/restart-recovery")
    assert rec.status_code == 200
    assert rec.json()["jobs"]["requeue_on_boot"] is True
