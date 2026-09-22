"""Scheduler helpers for Continuous Posture Engine.

The actual asyncio loop lives in ``app.jobs`` so we do not add a second
scheduler. This module documents cadence + jitter for tests and ops.
"""

from __future__ import annotations

import hashlib
from typing import Any

from app.posture.refresh_policy import default_interval_sec, default_jitter_sec


def next_due_offset_sec(*, seed: str = "global") -> int:
    """Deterministic bucket offset in [0, jitter] to avoid thundering herds."""
    jitter = default_jitter_sec()
    if jitter <= 0:
        return 0
    digest = hashlib.sha256(f"posture-sched:{seed}".encode()).hexdigest()
    return int(digest[:8], 16) % (jitter + 1)


def schedule_summary(*, seed: str = "global") -> dict[str, Any]:
    interval = default_interval_sec()
    offset = next_due_offset_sec(seed=seed)
    return {
        "interval_sec": interval,
        "jitter_sec": default_jitter_sec(),
        "bucket_offset_sec": offset,
        "effective_min_sec": max(60, interval - offset),
        "excludes_deep_scans": True,
        "job_kind": "posture_refresh",
    }
