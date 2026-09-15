"""Unified agent timeline: commands + control_results + evidence (P1)."""

from __future__ import annotations

import json
from typing import Any


def build_agent_timeline(
    user_id: str,
    agent_id: str,
    *,
    limit: int = 80,
) -> dict[str, Any]:
    """Merge recent commands, control results, and evidence for one agent."""
    limit = max(1, min(int(limit or 80), 200))
    events: list[dict[str, Any]] = []

    try:
        from app.agents import command_lifecycle, get_agent
        from app.db import get_conn, row_to_dict

        if not get_agent(agent_id):
            return {"ok": False, "error": "agent_not_found", "events": []}
        c = get_conn()
        rows = c.execute(
            """
            SELECT * FROM securaiq_agent_commands
            WHERE agent_id = ? AND user_id = ?
            ORDER BY created_at DESC LIMIT ?
            """,
            (agent_id, user_id, limit),
        ).fetchall()
        for row in rows:
            d = row_to_dict(row) or {}
            lc = command_lifecycle(
                str(d.get("status") or ""),
                verification_status=str(d.get("verification_status") or ""),
            )
            events.append(
                {
                    "kind": "command",
                    "ts": d.get("created_at") or d.get("updated_at") or 0,
                    "label": f"Command {d.get('kind') or 'action'}",
                    "detail": f"{d.get('status') or ''} · {lc}",
                    "lifecycle": lc,
                    "status": d.get("status"),
                    "id": d.get("id"),
                    "type": "agent_command",
                }
            )
    except Exception:
        return {"ok": False, "error": "agent_not_found", "events": []}

    try:
        from app.controls.history import list_control_results

        for r in list_control_results(user_id, agent_id=agent_id, limit=limit):
            events.append(
                {
                    "kind": "control",
                    "ts": r.get("observed_at") or r.get("created_at") or 0,
                    "label": (
                        f"Control {(r.get('result') or '').upper()}: "
                        f"{r.get('test_name') or r.get('control_id')}"
                    ),
                    "detail": r.get("summary") or "",
                    "result": r.get("result"),
                    "control_id": r.get("control_id"),
                    "framework_id": r.get("framework_id"),
                    "id": r.get("id"),
                    "type": "control.result",
                }
            )
    except Exception:
        pass

    try:
        from app.services.evidence import list_evidence

        for ev in list_evidence(user_id, limit=min(200, limit * 3)) or []:
            detail = ev.get("detail") if isinstance(ev.get("detail"), dict) else {}
            if not detail:
                try:
                    detail = json.loads(ev.get("detail_json") or "{}")
                except Exception:
                    detail = {}
            aid = str(detail.get("agent_id") or "")
            eid = str(ev.get("entity_id") or "")
            if aid != agent_id and agent_id not in eid:
                continue
            events.append(
                {
                    "kind": "evidence",
                    "ts": ev.get("last_seen") or ev.get("created_at") or 0,
                    "label": "Evidence",
                    "detail": ev.get("summary") or "",
                    "id": ev.get("id"),
                    "type": "evidence.created",
                    "source": ev.get("source"),
                }
            )
    except Exception:
        pass

    events.sort(key=lambda e: float(e.get("ts") or 0), reverse=True)
    events = events[:limit]
    return {
        "ok": True,
        "agent_id": agent_id,
        "count": len(events),
        "events": events,
        "disclaimer": "Merged command + control_results + evidence — SSE still drives live refresh",
    }
