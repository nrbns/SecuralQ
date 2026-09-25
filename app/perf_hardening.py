"""Performance-hardening board — Phase 1–2 lab truth, never fake 100k or Postgres HA.

Git already queues scans as jobs. This module reports what is actually isolated
(named in-process pools + SSE batching) versus what remains Server ops.
"""

from __future__ import annotations

from typing import Any


def perf_hardening_board() -> dict[str, Any]:
    from app.db import current_backend, using_postgres
    from app.jobs import worker_pool_status
    from app.metrics import stage_latency_snapshot
    from app.realtime_bus import backend_status, sse_batch_stats

    stages = stage_latency_snapshot()
    pools = worker_pool_status()
    bus = {}
    try:
        bus = backend_status() or {}
    except Exception:
        bus = {}
    batch = sse_batch_stats()
    backend = current_backend()
    pg = using_postgres()

    api = stages.get("api") or {}
    return {
        "ok": True,
        "phase": "1-2",
        "goal": (
            "API/UI stay responsive while scans, evidence, controls, and AI "
            "cannot starve each other. Lab in-process isolation first."
        ),
        "measured": {
            "api_p50_ms": api.get("p50_ms"),
            "api_p95_ms": api.get("p95_ms"),
            "api_samples": api.get("count") or 0,
            "stage_latency": stages,
            "sse": {
                "local_subscribers": bus.get("local_subscribers"),
                "mode": bus.get("mode"),
                "events_per_sec": (bus.get("throughput") or {}).get("events_per_sec"),
                "batch": batch,
            },
            "database": {"backend": backend, "postgres": bool(pg)},
            "redis_configured": bool(bus.get("redis_configured")),
            "workers": pools,
        },
        "git_truth": {
            "scanners_are_jobs": True,
            "scan_kinds": ["scan_execute", "combo_assessment"],
            "named_pools": True,
            "separate_os_workers": False,
            "scan_jobs_off_event_loop": True,
            "sse_finding_batch": True,
            "critical_events_immediate": True,
            "high_scan_findings_batched": True,
            "ai_not_in_scan_path": True,
            "affected_controls_only": True,
        },
        "still_ops": [
            "postgres_ha",
            "redis_as_job_broker",
            "rust_agent",
            "ev_signed_installers",
            "http_5k",
            "agent_100k_sim",
        ],
        "sequence": [
            "phase_1_profile",
            "phase_2_named_pools_and_sse_batch",
            "phase_3_postgres_redis_server",
            "phase_4_sse_backpressure_measured",
            "phase_5_native_agent_contract",
        ],
        "disclaimer": (
            "Process-local meters. SQLite Desktop remains the lab default. "
            "PostgreSQL + Redis workers + 1k/10k/100k load tests are Server ops — not claimed here."
        ),
    }
