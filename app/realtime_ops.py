"""Realtime pipeline metrics + DLQ inspect helpers (admin / ops)."""

from __future__ import annotations

from typing import Any


def pipeline_metrics() -> dict[str, Any]:
    """Aggregate bus + Streams + processor meters for /api/admin/realtime/metrics."""
    bus: dict[str, Any] = {}
    try:
        from app.realtime_bus import backend_status

        bus = backend_status()
    except Exception as exc:
        bus = {"error": str(exc)[:200]}

    stream = bus.get("stream") if isinstance(bus.get("stream"), dict) else {}
    thr = bus.get("throughput") if isinstance(bus.get("throughput"), dict) else {}
    if not thr and isinstance(stream.get("throughput"), dict):
        thr = stream["throughput"]

    processor: dict[str, Any] = {}
    try:
        from app.event_processor import processor_status, stream_monitor_snapshot

        processor = processor_status()
        mon = stream_monitor_snapshot()
        for key in (
            "stream_length",
            "dlq_length",
            "pending_count",
            "consumer_group_lag",
            "dlq_key",
            "max_deliveries",
            "claim_idle_ms",
        ):
            if mon.get(key) is not None and stream.get(key) is None:
                stream[key] = mon[key]
    except Exception as exc:
        processor = {"error": str(exc)[:200]}

    return {
        "ok": True,
        "mode": bus.get("mode"),
        "redis_configured": bool(bus.get("redis_configured")),
        "ingress": {
            "events_per_sec": thr.get("events_per_sec"),
            "published_total": thr.get("published_total"),
            "duplicates_dropped": thr.get("duplicates_dropped"),
            "backpressure_hits": thr.get("backpressure_hits"),
            "backpressure_active": thr.get("backpressure_active"),
        },
        "stream": {
            "key": stream.get("stream_key"),
            "length": stream.get("stream_length"),
            "pending": stream.get("pending_count"),
            "lag": stream.get("consumer_group_lag"),
            "dlq_length": stream.get("dlq_length"),
            "dlq_key": stream.get("dlq_key"),
            "max_deliveries": stream.get("max_deliveries"),
            "claim_idle_ms": stream.get("claim_idle_ms"),
        },
        "sse": {
            "local_subscribers": bus.get("local_subscribers"),
            "streams_fanout": bus.get("streams_fanout"),
        },
        "processor": processor,
        "hint": bus.get("hint"),
        "disclaimer": (
            "Lab metrics are process-local when REDIS_URL is unset. "
            "DLQ/lag require Redis Streams. Not a commercial HA SLO."
        ),
    }


def get_dlq_entry(entry_id: str) -> dict[str, Any] | None:
    """Inspect one DLQ message by stream id."""
    eid = str(entry_id or "").strip()
    if not eid:
        return None
    try:
        from app.event_processor import list_dlq_entries

        for row in list_dlq_entries(limit=200):
            if str(row.get("id") or "") == eid:
                return row
            if str(row.get("event_id") or "") == eid:
                return row
    except Exception:
        return None
    return None
