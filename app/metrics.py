"""Minimal operational metrics — Prometheus text exposition, no new dependency.

"Monitoring / error reporting" was listed as **Todo** in
docs/commercial-roadmap.md's SaaS readiness checklist. This is the
self-hosted-friendly half of that: an in-memory counter set exposed at
`GET /api/metrics` in the standard Prometheus text format, scrapeable by
Prometheus/Grafana/Datadog/whatever the operator already runs — no vendor
lock-in, no external service required.

Error *reporting* (crash aggregation, stack traces, alerting) is a separate
concern better served by an actual APM — see `app/error_reporting.py` for
the optional Sentry hook, which is additive and inert without SENTRY_DSN.
"""

from __future__ import annotations

import time
from collections import defaultdict
from threading import Lock
from typing import Any

_start_time = time.time()
_lock = Lock()
_counters: dict[str, int] = defaultdict(int)
_status_counters: dict[str, int] = defaultdict(int)
# Process-local stage latency samples (ms) — not a multi-node SLO claim.
_stage_samples: dict[str, list[float]] = defaultdict(list)
_STAGE_MAX = 256
_STAGE_NAMES = frozenset({"ingest", "detect", "risk", "sse"})


def incr(name: str, amount: int = 1) -> None:
    with _lock:
        _counters[name] += amount


def incr_status(status_code: int) -> None:
    bucket = f"{status_code // 100}xx"
    with _lock:
        _status_counters[bucket] += 1


def observe_stage(stage: str, ms: float) -> None:
    """Record one stage latency sample in milliseconds (process-local ring)."""
    name = (stage or "").strip().lower()
    if name not in _STAGE_NAMES:
        return
    try:
        val = float(ms)
    except (TypeError, ValueError):
        return
    if val < 0 or val > 600_000:
        return
    with _lock:
        buf = _stage_samples[name]
        buf.append(val)
        if len(buf) > _STAGE_MAX:
            del buf[: len(buf) - _STAGE_MAX]


def _percentile(sorted_vals: list[float], p: float) -> float | None:
    if not sorted_vals:
        return None
    if len(sorted_vals) == 1:
        return round(sorted_vals[0], 3)
    idx = int(round((len(sorted_vals) - 1) * p))
    idx = max(0, min(len(sorted_vals) - 1, idx))
    return round(sorted_vals[idx], 3)


def stage_latency_snapshot() -> dict[str, Any]:
    """p50/p95/count per stage — lab meters only; targets remain unclaimed until measured."""
    out: dict[str, Any] = {}
    with _lock:
        for name in sorted(_STAGE_NAMES):
            samples = list(_stage_samples.get(name) or [])
            if not samples:
                out[name] = {"count": 0, "p50_ms": None, "p95_ms": None}
                continue
            ordered = sorted(samples)
            out[name] = {
                "count": len(ordered),
                "p50_ms": _percentile(ordered, 0.50),
                "p95_ms": _percentile(ordered, 0.95),
                "last_ms": round(samples[-1], 3),
            }
    out["disclaimer"] = (
        "Process-local stage meters — not HA SLOs. "
        "Targets (<1s ingest / <5s detect / <10s risk / <15s SSE) stay unclaimed until measured."
    )
    return out


def clear_stage_latency_for_tests() -> None:
    with _lock:
        _stage_samples.clear()


def render_prometheus() -> str:
    from app.jobs import list_jobs

    lines: list[str] = []

    lines.append("# HELP securaiq_uptime_seconds Process uptime in seconds.")
    lines.append("# TYPE securaiq_uptime_seconds gauge")
    lines.append(f"securaiq_uptime_seconds {time.time() - _start_time:.2f}")

    with _lock:
        counters_snapshot = dict(_counters)
        status_snapshot = dict(_status_counters)

    lines.append("# HELP securaiq_http_requests_total Total HTTP requests handled.")
    lines.append("# TYPE securaiq_http_requests_total counter")
    for name, value in sorted(counters_snapshot.items()):
        safe_name = name.replace("-", "_").replace(".", "_")
        lines.append(f'securaiq_http_requests_total{{route="{safe_name}"}} {value}')

    lines.append("# HELP securaiq_http_responses_total Total HTTP responses by status class.")
    lines.append("# TYPE securaiq_http_responses_total counter")
    for bucket, value in sorted(status_snapshot.items()):
        lines.append(f'securaiq_http_responses_total{{class="{bucket}"}} {value}')

    try:
        jobs = list_jobs(limit=500)
        by_status: dict[str, int] = defaultdict(int)
        for j in jobs:
            by_status[j.get("status", "unknown")] += 1
        lines.append("# HELP securaiq_jobs_total Background jobs by status (last 500).")
        lines.append("# TYPE securaiq_jobs_total gauge")
        for status, count in sorted(by_status.items()):
            lines.append(f'securaiq_jobs_total{{status="{status}"}} {count}')
    except Exception:
        pass

    # Phase 1 Streams durability gauges (best-effort; nulls omitted when Redis off)
    try:
        from app.event_processor import stream_monitor_snapshot

        snap = stream_monitor_snapshot() or {}
        lines.append("# HELP securaiq_stream_length Redis Streams main event log length (XLEN).")
        lines.append("# TYPE securaiq_stream_length gauge")
        sl = snap.get("stream_length")
        lines.append(f"securaiq_stream_length {int(sl) if sl is not None else -1}")

        lines.append("# HELP securaiq_stream_dlq_length Redis Streams dead-letter queue length.")
        lines.append("# TYPE securaiq_stream_dlq_length gauge")
        dlq = snap.get("dlq_length")
        lines.append(f"securaiq_stream_dlq_length {int(dlq) if dlq is not None else -1}")

        lines.append("# HELP securaiq_stream_pending Redis Streams consumer-group pending count.")
        lines.append("# TYPE securaiq_stream_pending gauge")
        pend = snap.get("pending_count")
        lines.append(f"securaiq_stream_pending {int(pend) if pend is not None else -1}")

        lines.append("# HELP securaiq_stream_consumer_lag Redis Streams consumer-group lag (when available).")
        lines.append("# TYPE securaiq_stream_consumer_lag gauge")
        lag = snap.get("consumer_group_lag")
        lines.append(f"securaiq_stream_consumer_lag {int(lag) if lag is not None else -1}")
    except Exception:
        pass

    try:
        from app.realtime_bus import publish_throughput

        thr = publish_throughput() or {}
        lines.append("# HELP securaiq_realtime_events_per_sec Approximate publish rate (60s window).")
        lines.append("# TYPE securaiq_realtime_events_per_sec gauge")
        lines.append(f"securaiq_realtime_events_per_sec {float(thr.get('events_per_sec') or 0)}")
        lines.append("# HELP securaiq_realtime_published_total Process-local publish count since start.")
        lines.append("# TYPE securaiq_realtime_published_total counter")
        lines.append(f"securaiq_realtime_published_total {int(thr.get('published_total') or 0)}")
        lines.append("# HELP securaiq_realtime_duplicates_dropped Duplicate event_id drops on publish path.")
        lines.append("# TYPE securaiq_realtime_duplicates_dropped counter")
        lines.append(f"securaiq_realtime_duplicates_dropped {int(thr.get('duplicates_dropped') or 0)}")
        lines.append("# HELP securaiq_realtime_backpressure Soft backpressure active (1) when stream near maxlen.")
        lines.append("# TYPE securaiq_realtime_backpressure gauge")
        lines.append(f"securaiq_realtime_backpressure {1 if thr.get('backpressure_active') else 0}")
    except Exception:
        pass

    # Stage latency gauges (process-local; -1 when no samples)
    try:
        stages = stage_latency_snapshot()
        lines.append("# HELP securaiq_stage_latency_p50_ms Process-local stage latency p50 (ms).")
        lines.append("# TYPE securaiq_stage_latency_p50_ms gauge")
        lines.append("# HELP securaiq_stage_latency_p95_ms Process-local stage latency p95 (ms).")
        lines.append("# TYPE securaiq_stage_latency_p95_ms gauge")
        lines.append("# HELP securaiq_stage_latency_samples Stage latency sample count.")
        lines.append("# TYPE securaiq_stage_latency_samples gauge")
        for stage in ("ingest", "detect", "risk", "sse"):
            row = stages.get(stage) if isinstance(stages.get(stage), dict) else {}
            p50 = row.get("p50_ms")
            p95 = row.get("p95_ms")
            cnt = int(row.get("count") or 0)
            lines.append(
                f'securaiq_stage_latency_p50_ms{{stage="{stage}"}} {float(p50) if p50 is not None else -1}'
            )
            lines.append(
                f'securaiq_stage_latency_p95_ms{{stage="{stage}"}} {float(p95) if p95 is not None else -1}'
            )
            lines.append(f'securaiq_stage_latency_samples{{stage="{stage}"}} {cnt}')
    except Exception:
        pass

    # Connected agents (best-effort)
    try:
        from app.agents import list_agents

        agents = list_agents("local", limit=500)
        online = sum(1 for a in agents if (a.get("status") or "").lower() in ("online", "active", "ok"))
        lines.append("# HELP securaiq_agents_total Enrolled agents visible to local/lab scope (last 500).")
        lines.append("# TYPE securaiq_agents_total gauge")
        lines.append(f"securaiq_agents_total {len(agents)}")
        lines.append("# HELP securaiq_agents_online Agents with online/active status.")
        lines.append("# TYPE securaiq_agents_online gauge")
        lines.append(f"securaiq_agents_online {online}")
    except Exception:
        pass

    return "\n".join(lines) + "\n"
