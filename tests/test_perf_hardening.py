"""Phase 1–2 performance isolation: named pools + SSE finding batch."""

from __future__ import annotations

from tests._http_test_utils import configure_isolated_settings


def test_job_pool_routing():
    from app.jobs import job_pool_for

    assert job_pool_for("scan_execute") == "scan"
    assert job_pool_for("combo_assessment") == "scan"
    assert job_pool_for("compliance_ops_tick") == "control"
    assert job_pool_for("vault_expiry_tick") == "evidence"
    assert job_pool_for("report_export") == "report"
    assert job_pool_for("kev_sync") == "default"


def test_sse_batches_normal_findings_keeps_critical_immediate(tmp_path, monkeypatch):
    configure_isolated_settings(monkeypatch, tmp_path, auth_enabled=False)
    monkeypatch.setenv("SSE_BATCH_MS", "50")
    from app.realtime_bus import flush_sse_batches, publish, sse_batch_stats, subscribe, unsubscribe

    q = subscribe(maxsize=64)
    try:
        for i in range(5):
            publish(type="vuln", id=f"v{i}", severity="medium")
        stats = sse_batch_stats()
        assert stats["pending"] >= 1
        flush_sse_batches()
        got = []
        while not q.empty():
            got.append(q.get_nowait())
        types = [str(ev.get("type") or ev.get("event_type") or "") for ev in got]
        assert "findings.batch" in types
        assert types.count("vuln") == 0
        publish(type="vuln", id="crit1", severity="critical")
        immediate = []
        while not q.empty():
            immediate.append(q.get_nowait())
        imm_types = [str(ev.get("type") or ev.get("event_type") or "") for ev in immediate]
        assert any(t == "vuln" or t.endswith("vuln") for t in imm_types)
    finally:
        unsubscribe(q)


def test_perf_hardening_http(tmp_path, monkeypatch):
    configure_isolated_settings(monkeypatch, tmp_path, auth_enabled=False)
    from fastapi.testclient import TestClient

    from app.db import init_schema
    from app.main import app
    from app.perf_hardening import perf_hardening_board
    from app.tenancy import ensure_tenant_schema

    init_schema()
    ensure_tenant_schema()
    board = perf_hardening_board()
    assert board["phase"] == "1-2"
    assert board["git_truth"]["named_pools"] is True
    assert board["git_truth"]["sse_finding_batch"] is True
    assert "postgres_ha" in board["still_ops"]
    assert "agent_100k_sim" in board["still_ops"]
    client = TestClient(app)
    r = client.get("/api/ops/perf-hardening")
    assert r.status_code == 200
    body = r.json()
    assert "measured" in body
    assert body["measured"]["database"]["backend"]
    alive = client.get("/api/alive")
    assert alive.status_code == 200
    assert alive.json().get("ok") is True


def test_dashboard_lite_and_asset_lite(tmp_path, monkeypatch):
    configure_isolated_settings(monkeypatch, tmp_path, auth_enabled=False)
    from fastapi.testclient import TestClient

    from app.db import init_schema
    from app.fast_cache import cache_clear
    from app.main import app
    from app.tenancy import ensure_tenant_schema

    init_schema()
    ensure_tenant_schema()
    cache_clear()
    client = TestClient(app)
    lite = client.get("/api/dashboard/lite")
    assert lite.status_code == 200
    body = lite.json()
    assert body.get("lite") is True
    assert "security_index" in body
    assert "assets_total" in body
    again = client.get("/api/dashboard/lite")
    assert again.status_code == 200
    assets = client.get("/api/assets?lite=1")
    assert assets.status_code == 200
    assert assets.json().get("lite") is True
    assert isinstance(assets.json().get("assets"), list)
    sw = client.get("/api/software/inventory?lite=1&limit=80")
    assert sw.status_code == 200
    assert sw.json().get("status") == "ok"
