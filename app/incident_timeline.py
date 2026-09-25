"""Incident timeline — clickable events with source + evidence."""

from __future__ import annotations

from typing import Any


def incident_timeline(user_id: str, incident_id: str) -> dict[str, Any] | None:
    from app.db import get_conn
    from app.ops import get_incident

    inc = get_incident(user_id, incident_id)
    if not inc:
        return None
    events: list[dict[str, Any]] = [
        {
            "ts": inc.get("created_at") or inc.get("updated_at"),
            "kind": "opened",
            "source": inc.get("source") or "securaiq",
            "summary": inc.get("title") or "Incident opened",
            "evidence_id": "",
        }
    ]
    try:
        rows = get_conn().execute(
            """
            SELECT id, action, detail, created_at, entry_hash
            FROM audit_log
            WHERE user_id = ? AND (detail LIKE ? OR detail LIKE ?)
            ORDER BY created_at ASC
            LIMIT 80
            """,
            (user_id, f"%{incident_id}%", f"%{inc.get('title') or '___'}%"),
        ).fetchall()
        for r in rows:
            events.append(
                {
                    "ts": r["created_at"],
                    "kind": r["action"] or "audit",
                    "source": "audit_chain",
                    "summary": r["action"] or "audit",
                    "evidence_id": (r["entry_hash"] or "")[:16],
                }
            )
    except Exception:
        pass
    events.sort(key=lambda e: float(e.get("ts") or 0))
    return {
        "ok": True,
        "incident_id": incident_id,
        "title": inc.get("title"),
        "severity": inc.get("severity"),
        "status": inc.get("status"),
        "events": events,
        "isolation": "allowlisted_approved_only",
        "note": "Isolation stays allowlisted + approved. Timeline is audit/source events, not invented detections.",
    }
