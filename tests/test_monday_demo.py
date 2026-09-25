"""Monday demo P0s: scan isolation, SSE batch, AI off, affected controls, job HUD API."""

from __future__ import annotations

from tests._http_test_utils import configure_isolated_settings


def test_scan_jobs_use_dedicated_thread_not_default_executor():
    from app.jobs import _SCAN_EXEC, _HEAVY_EXEC, _worker_boot_delay, job_pool_for, job_runs_isolated, worker_pool_status

    assert job_runs_isolated("scan_execute") is True
    assert job_runs_isolated("report_export") is True
    assert job_runs_isolated("software_sync_all") is True
    assert job_runs_isolated("kev_sync") is False
    assert _HEAVY_EXEC._max_workers >= 1

    assert job_pool_for("scan_execute") == "scan"
    assert _worker_boot_delay("scan") <= 1.0
    assert _SCAN_EXEC._max_workers >= 1
    status = worker_pool_status()
    assert status["scan_jobs_off_event_loop"] is True
    assert status["heavy_jobs_off_event_loop"] is True
    assert status["scanner_binaries_are_subprocesses"] is True
    assert status["separate_os_workers"] is False


def test_nmap_available_skips_version_probe_on_request_path(monkeypatch):
    from app.scanners.nmap import NmapScanner

    calls = {"run": 0}

    def fake_run(*_a, **_k):
        calls["run"] += 1
        raise AssertionError("nmap --version must not run on the POST/catalog path")

    monkeypatch.setattr("subprocess.run", fake_run)
    sc = NmapScanner()
    sc._avail_cache.clear()
    monkeypatch.setattr(sc, "_resolve_path", lambda: r"C:\fake\nmap.exe")
    ok, detail = sc.available()
    assert ok is True
    assert "nmap" in detail.lower()
    assert calls["run"] == 0


def test_high_scan_findings_are_batchable_not_immediate(monkeypatch):
    monkeypatch.setenv("SSE_BATCH_MS", "50")
    from app.realtime_bus import _is_batchable_event, _is_immediate_event

    high = {"type": "vuln", "event_type": "vuln", "severity": "high", "scan_id": "s1"}
    crit = {"type": "vuln", "event_type": "vuln", "severity": "critical"}
    assert _is_immediate_event(high) is False
    assert _is_immediate_event(crit) is True
    assert _is_batchable_event(high) is True


def test_affected_controls_not_full_catalog():
    from app.controls.recompute import recompute_affected_controls, tests_for_event_type

    tests = tests_for_event_type("software.updated")
    assert tests
    assert len(tests) <= 3
    assert tests_for_event_type("control.failed") == ()
    skipped = recompute_affected_controls("local", {"type": "unknown.event"})
    assert skipped.get("skipped") is True


def test_demo_ai_and_monday_board(tmp_path, monkeypatch):
    configure_isolated_settings(monkeypatch, tmp_path, auth_enabled=False)
    monkeypatch.setattr("app.config.settings.demo_disable_ai", True, raising=False)
    from app.ai_limits import demo_ai_blocked
    from app.db import get_conn, init_schema
    from app.jobs import live_scan_jobs
    from app.monday_demo import monday_demo_board

    assert demo_ai_blocked()
    init_schema()
    board = monday_demo_board()
    assert board["p0"]["scanner_isolation"]["scan_jobs_off_event_loop"] is True
    assert board["p0"]["scanner_isolation"]["cpu_parse_normalize_pdf_offloaded"] is True
    assert board["p0"]["compliance"]["affected_only"] is True
    assert "nmap" in board["p0"]["scanners"]
    assert board["p0"]["scanners"]["zap"]["builtin"] is True
    assert "200ms" in " ".join(board["do_not_claim"])
    assert live_scan_jobs() == []
    row = get_conn().execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name='org_members'"
    ).fetchone()
    assert row is not None


def test_init_schema_creates_org_members(tmp_path, monkeypatch):
    configure_isolated_settings(monkeypatch, tmp_path, auth_enabled=False)
    from app.commercial_ext import ensure_org_schema
    from app.db import get_conn, init_schema

    init_schema()
    ensure_org_schema()
    row = get_conn().execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name='org_members'"
    ).fetchone()
    assert row is not None


def test_offline_pass_is_unknown():
    from app.control_truth import resolve_result_truth

    out = resolve_result_truth(
        {"status": "pass", "test_name": "host_firewall", "tested_at": 1, "summary": "ok"},
        agents_online=False,
        now_ts=10,
    )
    assert out["status"] == "unknown"
    assert "offline" in out["reason"].lower() or "unavailable" in out["reason"].lower()


def test_nuclei_jsonl_line_and_stream_helper():
    import asyncio
    import sys

    from app.scanners.nuclei import parse_nuclei_jsonl, parse_nuclei_jsonl_line
    from app.scanners.stream import stream_subprocess

    line = '{"info":{"name":"Exposed Redis","severity":"high"},"matched-at":"http://lab.local","template-id":"redis"}'
    row = parse_nuclei_jsonl_line(line)
    assert row and row["title"] == "Exposed Redis"
    assert parse_nuclei_jsonl(line + "\nnot-json\n")[0]["severity"] == "high"

    async def _echo():
        code, out, _err = await stream_subprocess(
            [sys.executable, "-c", "print('open-line')"],
            timeout=8,
            max_capture=2000,
        )
        assert code == 0
        assert "open-line" in out

    asyncio.run(_echo())


def test_command_center_skips_full_reload_on_scan_findings():
    from pathlib import Path

    js = (Path(__file__).resolve().parents[1] / "static" / "app.js").read_text(encoding="utf-8")
    assert "CC_SKIP_FULL_RELOAD" in js
    assert "scheduleCommandCenterRefresh" in js
    assert 'panels.add("command")' not in js.split("if (t.startsWith(\"software\")")[1][:400]


def test_ui_defaults_to_builtin_not_combo():
    from pathlib import Path

    repo = Path(__file__).resolve().parents[1]
    html = (repo / "static" / "index.html").read_text(encoding="utf-8")
    js = (repo / "static" / "app.js").read_text(encoding="utf-8")
    assert 'option value="securaiq" selected' in html
    assert "preferCombo = true" not in js
    assert 'sel.value = prefer ? prefer.id : "securaiq"' in js
    assert 'engineSel.value = "combo"' not in js
    assert 'prefer = "combo"' not in js
    assert 'engineSel.value = "securaiq"' in js
    assert 'document.getElementById("toolsEngineScanner")?.value || "securaiq"' in js
    # Network profile fallback must be builtin, not combo.
    assert 'sel.value = "securaiq"' in js


def test_start_scripts_limit_ai():
    from pathlib import Path

    repo = Path(__file__).resolve().parents[1]
    ps1 = (repo / "scripts" / "start.ps1").read_text(encoding="utf-8")
    sh = (repo / "scripts" / "start.sh").read_text(encoding="utf-8")
    run_sh = (repo / "scripts" / "run_proper.sh").read_text(encoding="utf-8")
    assert "DEMO_DISABLE_AI" in ps1
    assert "DEMO_DISABLE_AI" in sh
    assert "huggingface" not in run_sh.lower() or "Do not auto-install HuggingFace" in run_sh
