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

__all__ = [
    "OnceOnlyResult",
    "invalidate_redis_clients",
    "ping_master",
    "prove_consumer_failover_once_only",
    "prove_duplicate_delivery_skipped",
    "sentinel_ready_report",
]
