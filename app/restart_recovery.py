"""Process restart recovery — reclaim jobs + stream pending.

In-process running→pending can be measured. Kill@5k HTTP remains ops.
"""

from __future__ import annotations

import time
from typing import Any


def restart_recovery_status() -> dict[str, Any]:
    from app.db import get_conn

    pending = running = 0
    try:
        c = get_conn()
        pending = int((c.execute("SELECT COUNT(*) AS n FROM jobs WHERE status='pending'").fetchone() or {}).get("n") or 0)
        running = int((c.execute("SELECT COUNT(*) AS n FROM jobs WHERE status='running'").fetchone() or {}).get("n") or 0)
    except Exception:
        pass
    stream_key = ""
    try:
        from app.realtime_bus import tenant_stream_key

        stream_key = tenant_stream_key("")
    except Exception:
        stream_key = "securaiq:events"
    last: dict[str, Any] | None = None
    try:
        from app.measured_ops import restart_reclaim_status

        last = restart_reclaim_status()
    except Exception:
        last = None
    return {
        "ok": True,
        "jobs": {
            "pending": pending,
            "running": running,
            "requeue_on_boot": True,
            "note": "start_background_jobs() flips running→pending and requeues up to 100.",
        },
        "streams": {
            "reclaim": "XAUTOCLAIM when REDIS_URL is set",
            "in_proc_replay": True,
            "stream_key": stream_key,
        },
        "last_reclaim_drill": last,
        "disclaimer": (
            "In-process reclaim is measured when data/ops/restart_reclaim_measurements.jsonl "
            "has a row. Process-kill @5k HTTP remains ops."
        ),
    }


def run_restart_reclaim_drill(*, persist: bool = False) -> dict[str, Any]:
    """Insert a running probe job, reclaim it, delete it, optionally record timings."""
    from app.db import get_conn, new_id, now
    from app.jobs import reclaim_running_jobs

    jid = f"drill-reclaim-{new_id()}"
    c = get_conn()
    c.execute(
        "INSERT INTO jobs (id, kind, status, payload_json, result_json, error, created_at, started_at) "
        "VALUES (?, ?, 'running', '{}', '{}', '', ?, ?)",
        (jid, "restart_reclaim_probe", now(), now()),
    )
    c.commit()
    t0 = time.perf_counter()
    rec = reclaim_running_jobs(enqueue_pending=False, job_id=jid)
    reclaim_ms = round((time.perf_counter() - t0) * 1000, 3)
    row = c.execute("SELECT status FROM jobs WHERE id=?", (jid,)).fetchone()
    status = ""
    if row is not None:
        try:
            status = str(row["status"])
        except (KeyError, TypeError, IndexError):
            status = str(row[0] if row else "")
    c.execute("DELETE FROM jobs WHERE id=?", (jid,))
    c.commit()
    result = {
        "ok": status == "pending",
        "job_id": jid,
        "status_after": status,
        "reclaimed": rec.get("reclaimed"),
        "reclaim_ms": reclaim_ms,
        "disclaimer": (
            "In-process running→pending flip on this host. "
            "Process-kill @5k HTTP remains ops."
        ),
    }
    if persist:
        from app.measured_ops import RESTART_LOG, append_measurement

        result["recorded"] = str(append_measurement(RESTART_LOG, {k: v for k, v in result.items() if k != "job_id"}))
    return result
