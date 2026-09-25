"""Monday demo board — honest P0 status, no invented latency numbers."""

from __future__ import annotations

from typing import Any


def scanner_preflight() -> dict[str, Any]:
    try:
        from app.scanners.nmap import NmapScanner

        nmap_ok, nmap_detail = NmapScanner().available(probe=False)
        nmap = nmap_detail if nmap_ok else ""
    except Exception:
        import shutil

        nmap = shutil.which("nmap") or ""
        nmap_ok = bool(nmap)
        nmap_detail = nmap or "nmap not found"
    try:
        from app.scanners.nuclei import NucleiScanner

        nuclei_ok, nuclei_detail = NucleiScanner().available()
        nuclei = nuclei_detail if nuclei_ok else ""
    except Exception:
        import shutil

        nuclei = shutil.which("nuclei") or ""
        nuclei_ok = bool(nuclei)
        nuclei_detail = nuclei or "nuclei not found"
    return {
        "nmap": {"on_path": bool(nmap_ok), "path": nmap, "detail": nmap_detail},
        "nuclei": {"on_path": bool(nuclei_ok), "path": nuclei, "detail": nuclei_detail},
        "zap": {
            "builtin": True,
            "note": "SecuraIQ Web Scanner always available. Optional ZAP API is extra.",
        },
        "demo_ok_without_nmap": True,
        "lab_not_ha": True,
    }


def monday_demo_board() -> dict[str, Any]:
    from app.ai_limits import ai_limits_status
    from app.controls.recompute import tests_for_event_type
    from app.db import current_backend
    from app.jobs import worker_pool_status
    from app.realtime_bus import sse_batch_stats

    pools = worker_pool_status()
    ai = ai_limits_status()
    return {
        "ok": True,
        "goal": "One live loop without demo-visible lag. Do not claim millisecond SLA.",
        "loop": "agent → event → control → evidence → compliance → UI → remediate → verify",
        "p0": {
            "scanner_isolation": {
                "scanner_binaries_are_subprocesses": True,
                "scan_jobs_off_event_loop": bool(pools.get("scan_jobs_off_event_loop")),
                "cpu_parse_normalize_pdf_offloaded": True,
                "nmap_probe_off_request_path": True,
                "scan_concurrency_default": 1,
                "separate_os_workers": False,
            },
            "sse": {
                "finding_batch_ms": 350,
                "critical_immediate": True,
                "high_scan_findings_batched": True,
                "batch": sse_batch_stats(),
            },
            "ai": ai,
            "compliance": {
                "full_recalc_on_dashboard": False,
                "affected_only": True,
                "software_event_tests": list(tests_for_event_type("software.updated")),
            },
            "job_hud": True,
            "sqlite": {"backend": current_backend(), "wal": current_backend() == "sqlite"},
            "scanners": scanner_preflight(),
        },
        "demo_script": [
            "Agent connects → asset LIVE",
            "Control PASS with fresh evidence",
            "Create failure → FAIL + evidence + risk + compliance",
            "Approve remediation → verify → PASS",
            "Stop agent → OFFLINE / UNKNOWN (never stale PASS)",
        ],
        "do_not_claim": [
            "200ms realtime latency unless measured on this host",
            "Celery / Redis job broker / Postgres HA",
            "EV / C3PAO / 100k agents",
        ],
        "disclaimer": (
            "Process-local truth. Show Live · last event ago. "
            "PostgreSQL + Redis workers remain Server ops."
        ),
    }
