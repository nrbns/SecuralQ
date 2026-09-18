"""Hash partition helpers for multi-worker fleet fan-out.

Lab/default: single stream + consumer group remains fine. At larger fleets,
workers claim a partition set derived from ``hash(org_id:agent_id) % N``.
This module does not create Redis streams — callers pass partition count.
"""

from __future__ import annotations

import hashlib
from typing import Iterable


def partition_id(org_id: str, agent_id: str, *, partitions: int = 16) -> int:
    n = max(1, int(partitions or 1))
    raw = f"{org_id or 'local'}:{agent_id or ''}".encode("utf-8")
    digest = hashlib.sha256(raw).hexdigest()
    return int(digest[:8], 16) % n


def workload_stream_key(workload: str, partition: int | None = None) -> str:
    """Logical stream name for a workload (and optional partition).

    Existing durable bus default remains ``securaiq:events``. These names are
    for optional fan-out as capacity measurement justifies it — not a second bus.
    """
    base = f"securaiq:{str(workload or 'events').strip().lower() or 'events'}"
    if partition is None:
        return base
    return f"{base}:p{int(partition)}"


WORKLOADS: tuple[str, ...] = (
    "events",
    "telemetry",
    "controls",
    "scans",
    "vulnerabilities",
    "remediation",
    "verification",
    "evidence",
    "compliance",
)


def claimable_partitions(worker_index: int, worker_count: int, *, partitions: int = 16) -> list[int]:
    """Return partitions owned by ``worker_index`` in a static range assignment."""
    n_workers = max(1, int(worker_count or 1))
    n_parts = max(1, int(partitions or 1))
    idx = max(0, int(worker_index or 0)) % n_workers
    return [p for p in range(n_parts) if p % n_workers == idx]


def partition_for_keys(keys: Iterable[tuple[str, str]], *, partitions: int = 16) -> dict[int, list[tuple[str, str]]]:
    out: dict[int, list[tuple[str, str]]] = {}
    for org_id, agent_id in keys:
        p = partition_id(org_id, agent_id, partitions=partitions)
        out.setdefault(p, []).append((org_id, agent_id))
    return out
