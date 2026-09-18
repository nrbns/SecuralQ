"""Phase 1 realtime helpers (Sentinel health, once-only multi-worker proof).

The durable bus remains ``app/realtime_bus.py`` + ``app/event_processor.py``.
This package holds small, testable contracts used by Sprint 1 proofs and CI
release gates — not a second architecture.
"""

from __future__ import annotations

from app.realtime.once_only import (
    OnceOnlyResult,
    prove_consumer_failover_once_only,
    prove_duplicate_delivery_skipped,
)
from app.realtime.sentinel_ops import (
    invalidate_redis_clients,
    ping_master,
    sentinel_ready_report,
)
from app.realtime.fleet_aggregator import (
    fleet_summary,
    maybe_publish_fleet_health,
    record_agent_observation,
)
from app.realtime.partitioner import partition_id, workload_stream_key
from app.realtime.event_registry import event_catalog
from app.realtime.workload_streams import ensure_workload_streams

__all__ = [
    "OnceOnlyResult",
    "event_catalog",
    "ensure_workload_streams",
    "fleet_summary",
    "invalidate_redis_clients",
    "maybe_publish_fleet_health",
    "partition_id",
    "ping_master",
    "prove_consumer_failover_once_only",
    "prove_duplicate_delivery_skipped",
    "record_agent_observation",
    "sentinel_ready_report",
    "workload_stream_key",
]
