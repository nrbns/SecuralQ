"""Register scan_execute job handler with the in-process worker."""

from __future__ import annotations

from typing import Any

from app.jobs import register_job


@register_job("scan_execute")
async def handle_scan_execute(payload: dict[str, Any]) -> dict[str, Any]:
    from app.scan_engine.executor import execute_scan

    scan_id = (payload or {}).get("scan_id")
    if not scan_id:
        raise ValueError("scan_id required")
    sid = str(scan_id)
    try:
        return await execute_scan(sid)
    except Exception as exc:
        # execute_scan already marks the scan row on every *expected* failure
        # path (blocked / target invalid / scanner unavailable / non-zero
        # exit). This is the safety net for anything unexpected — a network
        # timeout, a bug in normalize/report — that would otherwise leave the
        # scan stuck at whatever status it last reached (often 'queued' or
        # 'running') forever. The jobs table would record the real error, but
        # the UI only reads the scans table, so the user would just see a
        # scan that never finishes with no explanation. Always land on a
        # terminal, honest status instead.
        from app.db import now
        from app.scan_engine.models import get_scan, update_scan

        scan = get_scan(sid)
        if scan and scan.get("status") not in ("completed", "failed", "blocked"):
            err = f"{type(exc).__name__}: {exc}"[:2000]
            update_scan(sid, status="failed", error=err, completed_at=now())
            try:
                from app.realtime_bus import publish

                publish(type="scan", id=sid, status="failed", error=err)
            except Exception:
                pass
        raise
