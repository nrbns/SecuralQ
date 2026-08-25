"""TheHive orchestration — sync cases into SecuraIQ incidents."""

from __future__ import annotations

import json
from typing import Any

from app.config import settings
from app.connectors import thehive as th_conn
from app.db import get_conn, now
from app.ops import create_incident, list_incidents


def ensure_schema() -> None:
    c = get_conn()
    c.execute(
        """
        CREATE TABLE IF NOT EXISTS thehive_cases (
            id TEXT PRIMARY KEY,
            case_id TEXT NOT NULL UNIQUE,
            title TEXT NOT NULL DEFAULT '',
            severity TEXT NOT NULL DEFAULT '',
            status TEXT NOT NULL DEFAULT '',
            incident_id TEXT NOT NULL DEFAULT '',
            raw_json TEXT NOT NULL DEFAULT '{}',
            updated_at REAL NOT NULL
        )
        """
    )
    c.commit()


def status() -> dict[str, Any]:
    ensure_schema()
    configured = th_conn.is_configured()
    cached = 0
    try:
        row = get_conn().execute("SELECT COUNT(*) AS n FROM thehive_cases").fetchone()
        cached = int(row["n"] if row else 0)
    except Exception:
        cached = 0
    return {
        "configured": configured,
        "base_url": (settings.thehive_base_url or "").rstrip("/") if configured else "",
        "verify_ssl": bool(settings.thehive_verify_ssl),
        "cases_cached": cached,
    }


async def sync(user_id: str = "local") -> dict[str, Any]:
    ensure_schema()
    if not th_conn.is_configured():
        raise ValueError("TheHive is not configured")
    cases = await th_conn.fetch_cases(limit=80)
    c = get_conn()
    ts = now()
    inserted = 0
    linked = 0
    existing_titles = {
        (i.get("title") or "").strip().lower()
        for i in list_incidents(user_id)
    }
    for item in cases:
        cid = item.get("case_id") or ""
        if not cid:
            continue
        row = c.execute("SELECT incident_id FROM thehive_cases WHERE case_id = ?", (cid,)).fetchone()
        incident_id = (row["incident_id"] if row else "") or ""
        if not incident_id:
            title = f"[TheHive] {item.get('title')}"
            if title.lower() not in existing_titles:
                inc = create_incident(
                    user_id,
                    title=title[:200],
                    severity=item.get("severity") or "medium",
                    status="open" if str(item.get("status")).lower() not in {"resolved", "closed", "deleted"} else "closed",
                    source="thehive",
                    summary=(item.get("description") or "")[:1000],
                )
                incident_id = inc.get("id") or ""
                linked += 1
                existing_titles.add(title.lower())
            inserted += 1
        c.execute(
            """
            INSERT INTO thehive_cases (id, case_id, title, severity, status, incident_id, raw_json, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(case_id) DO UPDATE SET
              title=excluded.title,
              severity=excluded.severity,
              status=excluded.status,
              incident_id=CASE WHEN excluded.incident_id != '' THEN excluded.incident_id ELSE thehive_cases.incident_id END,
              raw_json=excluded.raw_json,
              updated_at=excluded.updated_at
            """,
            (
                cid,
                cid,
                item.get("title") or "",
                item.get("severity") or "",
                item.get("status") or "",
                incident_id,
                json.dumps(item.get("raw") or item)[:8000],
                ts,
            ),
        )
    c.commit()
    out = {"cases": len(cases), "new_or_updated": inserted, "incidents_created": linked}
    try:
        from app.realtime_bus import publish

        publish(type="thehive", **out)
    except Exception:
        pass
    return out


def list_cases(limit: int = 50) -> list[dict[str, Any]]:
    ensure_schema()
    rows = get_conn().execute(
        "SELECT case_id, title, severity, status, incident_id, updated_at FROM thehive_cases ORDER BY updated_at DESC LIMIT ?",
        (max(1, min(limit, 200)),),
    ).fetchall()
    return [dict(r) for r in rows]
