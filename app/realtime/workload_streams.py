"""Optional Redis Streams fan-out keys for workload separation.

Default path remains the single ``securaiq:events`` bus. These helpers ensure
named streams exist when REDIS_URL is set and operators opt into fan-out —
they do not create a second event architecture.
"""

from __future__ import annotations

import logging
from typing import Any

from app.realtime.partitioner import WORKLOADS, workload_stream_key

_log = logging.getLogger("securaiq.realtime.workload_streams")


def configured_workloads() -> list[str]:
    return list(WORKLOADS)


def ensure_workload_streams(*, partitions: int = 0) -> dict[str, Any]:
    """XGROUP CREATE MKSTREAM for each workload (and optional partitions).

    No-op when Redis is unavailable. Safe to call repeatedly.
    """
    out: dict[str, Any] = {"ok": False, "created": [], "skipped": [], "error": None}
    try:
        from app.redis_client import get_redis

        r = get_redis()
        if r is None:
            out["skipped"].append("redis_unavailable")
            out["ok"] = True
            return out
    except Exception as exc:
        out["error"] = str(exc)
        out["ok"] = True
        return out

    n_parts = max(0, int(partitions or 0))
    keys: list[str] = []
    for w in WORKLOADS:
        keys.append(workload_stream_key(w))
        for p in range(n_parts):
            keys.append(workload_stream_key(w, p))

    for key in keys:
        try:
            # Consumer group name matches workload for clarity
            group = "securaiq-" + key.split(":")[1] if ":" in key else "securaiq-workers"
            try:
                r.xgroup_create(key, group, id="0", mkstream=True)
                out["created"].append({"stream": key, "group": group})
            except Exception as exc:
                msg = str(exc).lower()
                if "busygroup" in msg or "already" in msg:
                    out["skipped"].append(key)
                else:
                    out["skipped"].append(f"{key}:{exc}")
        except Exception as exc:
            _log.debug("ensure stream %s: %s", key, exc)
            out["skipped"].append(f"{key}:{exc}")
    out["ok"] = True
    return out


def publish_to_workload(
    workload: str,
    event: dict[str, Any],
    *,
    org_id: str = "",
    agent_id: str = "",
    partitions: int = 0,
) -> dict[str, Any]:
    """Best-effort XADD to a workload stream (plus default bus publish)."""
    result: dict[str, Any] = {"bus": False, "stream": None, "id": None}
    try:
        from app.realtime_bus import publish

        publish(**{**event, "workload": workload})
        result["bus"] = True
    except Exception:
        pass

    if partitions and org_id and agent_id:
        from app.realtime.partitioner import partition_id

        part = partition_id(org_id, agent_id, partitions=partitions)
        key = workload_stream_key(workload, part)
    else:
        key = workload_stream_key(workload)
    result["stream"] = key

    try:
        from app.redis_client import get_redis
        import json

        r = get_redis()
        if r is None:
            return result
        payload = {k: (json.dumps(v) if isinstance(v, (dict, list)) else str(v)) for k, v in event.items()}
        xid = r.xadd(key, payload, maxlen=10000, approximate=True)
        result["id"] = xid.decode() if isinstance(xid, bytes) else str(xid)
    except Exception as exc:
        result["error"] = str(exc)
    return result
