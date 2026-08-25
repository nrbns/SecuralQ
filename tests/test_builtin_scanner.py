"""Real tests for the SecuraIQ builtin scan-engine adapter.

Root cause fixed here (found via live end-to-end testing after a report of
"scan n vapt is not working"): the "New scan" golden path
(POST /api/scans -> app/scan_engine/executor.py) only had "nmap" registered
as engine-enabled, and Nmap isn't installed on most users' machines. Every
scan attempt 503'd immediately with "nmap not found on PATH" before it ever
ran anything. `app/scanners/builtin.py` adds a pure-Python scanner (reusing
the same async port-probe/banner-grab code already proven for the tools
palette's `ports`/`netvuln_scan`) that is always `available()`, registered
first in the scanner list, and is now the default scanner id.

These tests use a real local TCP listener (no mocking of the scan logic
itself) to prove ports are actually detected, plus one full
create_scan -> execute_scan -> get_scan integration test proving the golden
path completes and creates a real vulnerability without Nmap installed.
"""

from __future__ import annotations

import asyncio
import importlib
import socket

from app.scanners.builtin import BuiltinScanner
from app.scanners.registry import ENGINE_ENABLED, list_scanners


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


# --- registry wiring ---------------------------------------------------------


def test_builtin_scanner_is_engine_enabled_and_first_in_list():
    ids = [s["id"] for s in list_scanners()]
    assert ids[0] == "securaiq"  # first -> default <option> in the frontend <select>
    assert "securaiq" in ENGINE_ENABLED


def test_builtin_scanner_always_available_even_without_nmap():
    entries = {s["id"]: s for s in list_scanners()}
    assert entries["securaiq"]["available"] is True
    assert entries["securaiq"]["engine_enabled"] is True


# --- validate_target ---------------------------------------------------------


def test_validate_target_accepts_ip_and_hostname():
    sc = BuiltinScanner()
    ok, val = sc.validate_target("127.0.0.1")
    assert ok is True and val == "127.0.0.1"
    ok, val = sc.validate_target("https://example.com/path")
    assert ok is True and val == "example.com"


def test_validate_target_rejects_shell_metacharacters():
    sc = BuiltinScanner()
    ok, err = sc.validate_target("127.0.0.1; rm -rf /")
    assert ok is False


def test_validate_target_rejects_empty():
    sc = BuiltinScanner()
    ok, err = sc.validate_target("")
    assert ok is False
    assert "required" in err.lower()


# --- real port detection (actual TCP listener, no mocking) ------------------


def test_execute_detects_a_real_open_port(tmp_path, monkeypatch):
    from app.scanners.base import ScanContext
    import app.scanners.builtin as builtin_mod

    port = _free_port()
    # Only probe the ephemeral listener — avoid Windows RPC/SMB noise on discovery.
    monkeypatch.setitem(builtin_mod._PROFILE_PORTS, "discovery", [port])

    async def _run():
        server = await asyncio.start_server(lambda r, w: None, "127.0.0.1", port)
        try:
            sc = BuiltinScanner()
            ctx = ScanContext(
                scan_id="t1",
                target="127.0.0.1",
                profile="discovery",
                scope=[],
                authorized=True,
                evidence_dir=tmp_path,
            )
            raw = await sc.execute(ctx)
            parsed = sc.parse(raw, ctx)
            normalized = sc.normalize(parsed, ctx)
            return raw, parsed, normalized
        finally:
            server.close()
            await server.wait_closed()

    raw, parsed, normalized = asyncio.run(_run())
    assert raw.exit_code == 0
    assert port in parsed["open_ports"]
    ports_found = {s.port for s in normalized.services}
    assert port in ports_found
    assert (tmp_path / "securaiq_scan.json").exists()
    assert (tmp_path / "command.txt").exists()


def test_execute_reports_no_open_ports_honestly_when_nothing_listens(tmp_path, monkeypatch):
    from app.scanners.base import ScanContext
    import app.scanners.builtin as builtin_mod

    # High ephemeral ports that nothing should be listening on.
    quiet = [_free_port(), _free_port(), _free_port()]
    monkeypatch.setitem(builtin_mod._PROFILE_PORTS, "discovery", quiet)

    async def _run():
        sc = BuiltinScanner()
        ctx = ScanContext(
            scan_id="t2",
            target="127.0.0.1",
            profile="discovery",
            scope=[],
            authorized=True,
            evidence_dir=tmp_path,
        )
        raw = await sc.execute(ctx)
        return sc.parse(raw, ctx)

    parsed = asyncio.run(_run())
    assert parsed["open_ports"] == []


# --- normalize(): risky-port findings (pure data, no sockets needed) -------


def test_normalize_flags_redis_as_critical():
    from app.scanners.base import ScanContext

    sc = BuiltinScanner()
    # Public address (not RFC1918 / not TEST-NET) — Redis stays high
    ctx = ScanContext(
        scan_id="t3",
        target="8.8.8.8",
        profile="discovery",
        scope=[],
        authorized=True,
        evidence_dir=None,
    )
    normalized = sc.normalize({"open_ports": [6379], "banners": {}, "checked_ports": 20}, ctx)
    redis_findings = [f for f in normalized.findings if "Redis" in f.title or f.raw.get("port") == 6379]
    assert redis_findings
    assert redis_findings[0].severity == "high"


def test_normalize_clean_scan_has_only_no_risky_findings():
    from app.scanners.base import ScanContext

    sc = BuiltinScanner()
    ctx = ScanContext(
        scan_id="t4",
        target="127.0.0.1",
        profile="discovery",
        scope=[],
        authorized=True,
        evidence_dir=None,
    )
    normalized = sc.normalize({"open_ports": [80], "banners": {}, "checked_ports": 20}, ctx)
    assert len(normalized.findings) == 1
    assert normalized.findings[0].severity == "info"


# --- full golden-path integration: create_scan -> execute_scan -> get_scan -


def _reload_db(monkeypatch, data_dir):
    monkeypatch.setenv("DATA_DIR", str(data_dir))
    monkeypatch.setenv("WORKSPACE_ZERO_START", "false")
    monkeypatch.setenv("AUTH_ENABLED", "true")
    monkeypatch.setenv("DEPLOYMENT_MODE", "lab")
    monkeypatch.setenv("DATABASE_URL", "")
    import app.config as config_mod
    import app.db as db_mod

    importlib.reload(config_mod)
    db_mod.reset_conn_for_tests()
    importlib.reload(db_mod)
    return config_mod, db_mod


def test_scanner_all_queues_available_only(tmp_path, monkeypatch):
    """scanner=all must queue securaiq and skip unavailable PATH tools.

    Uses a minimal FastAPI app wrapping only app.scans_api.router, rather
    than importing/reloading the full app.main. Real bug found via full-
    suite verification: reloading app.main mid test-session (it builds a
    brand-new FastAPI() instance and re-runs all its module-level wiring)
    left 10+ unrelated tests in other files failing with a NameError deep in
    app/enterprise.py — a cross-test pollution bug, not a real product bug.
    app.db/app.auth/app.scans_api all still see the fresh _reload_db() state
    correctly here because importlib.reload() mutates a module's __dict__ in
    place, so already-bound `get_conn` references in other modules keep
    resolving against the reloaded app.db globals — no need to reload them,
    and definitely no need to reload the heavy, side-effecting app.main.
    """
    _reload_db(monkeypatch, tmp_path / "data")
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    from app.auth import login, register_user
    from app.scan_engine.models import ensure_scans_schema
    from app.scans_api import router as scans_router
    from app.tenancy import ensure_tenant_schema

    ensure_tenant_schema()
    ensure_scans_schema()
    register_user("batch_u", "password123", role="user")
    _u, token = login("batch_u", "password123")

    test_app = FastAPI()
    test_app.include_router(scans_router)
    client = TestClient(test_app)
    res = client.post(
        "/api/scans",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "target": "127.0.0.1",
            "scanner": "all",
            "profile": "discovery",
            "authorized": True,
            "scope": ["127.0.0.1"],
        },
    )
    assert res.status_code == 200, res.text
    data = res.json()
    assert data["scanner"] == "all"
    assert data["count"] >= 1
    ids = [s["scanner"] for s in data["scans"]]
    assert "securaiq" in ids
    skipped_ids = {s["scanner"] for s in data.get("skipped") or []}
    for sid in ids:
        assert sid not in skipped_ids


def test_new_scan_golden_path_completes_without_nmap(tmp_path, monkeypatch):
    """Before the fix this flow 503'd with 'nmap not found on PATH'.
    It must reach status=='completed' using only the builtin scanner."""
    _reload_db(monkeypatch, tmp_path / "data")
    import app.scanners.builtin as builtin_mod
    from app.scan_engine.executor import execute_scan
    from app.scan_engine.models import create_scan, get_scan

    port = _free_port()
    monkeypatch.setitem(builtin_mod._PROFILE_PORTS, "discovery", [port])

    async def _run():
        server = await asyncio.start_server(lambda r, w: None, "127.0.0.1", port)
        try:
            scan = create_scan(
                user_id="local",
                target="127.0.0.1",
                scanner="securaiq",
                profile="discovery",
                scope=[],
                authorized=True,
            )
            result = await execute_scan(scan["id"])
            final = get_scan(scan["id"])
            return result, final
        finally:
            server.close()
            await server.wait_closed()

    result, final = asyncio.run(_run())
    assert result["ok"] is True
    assert final["status"] == "completed"
    assert final["error"] == ""
    assert final["summary"]["scanner"] == "securaiq"
    assert final["summary"]["findings_created"] >= 1
    assert final["summary"].get("report_url", "").endswith("/report")
    from pathlib import Path

    report = Path(final["summary"]["report"])
    assert report.is_file()
    text = report.read_text(encoding="utf-8")
    assert "SecuraIQ Scan Report" in text
    assert "127.0.0.1" in text
