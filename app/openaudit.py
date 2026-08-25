"""Open-AudIT orchestration — sync discovered devices into SecuraIQ assets."""

from __future__ import annotations

import json
from typing import Any

from app.config import settings
from app.connectors import openaudit as oa_conn
from app.db import get_conn, new_id, now
from app.enterprise import create_asset, list_assets


def status() -> dict[str, Any]:
    ensure_schema()
    configured = oa_conn.is_configured()
    cached = 0
    try:
        row = get_conn().execute("SELECT COUNT(*) AS n FROM openaudit_devices").fetchone()
        cached = int(row["n"] if row else 0)
    except Exception:
        cached = 0
    return {
        "configured": configured,
        "live": True,
        "base_url": (settings.openaudit_base_url or "").rstrip("/") if configured else "",
        "api_root": oa_conn.api_root() if configured else "",
        "verify_ssl": bool(settings.openaudit_verify_ssl),
        "devices_cached": cached,
    }


def ensure_schema() -> None:
    c = get_conn()
    c.execute(
        """
        CREATE TABLE IF NOT EXISTS openaudit_devices (
            id TEXT PRIMARY KEY,
            device_id TEXT NOT NULL UNIQUE,
            name TEXT NOT NULL DEFAULT '',
            hostname TEXT NOT NULL DEFAULT '',
            ip TEXT NOT NULL DEFAULT '',
            type TEXT NOT NULL DEFAULT '',
            status TEXT NOT NULL DEFAULT '',
            os TEXT NOT NULL DEFAULT '',
            domain TEXT NOT NULL DEFAULT '',
            description TEXT NOT NULL DEFAULT '',
            asset_id TEXT NOT NULL DEFAULT '',
            raw_json TEXT NOT NULL DEFAULT '{}',
            updated_at REAL NOT NULL
        )
        """
    )
    c.commit()


def _map_asset_type(oa_type: str) -> str:
    from app.asset_categories import infer_asset_category

    return infer_asset_category(oa_type=oa_type, asset_type=oa_type)


def _upsert_device(item: dict[str, Any], user_id: str) -> tuple[bool, str]:
    """Returns (inserted, asset_id)."""
    from app.asset_names import canonical_asset_name
    from app.enterprise import ensure_asset_for_target

    ensure_schema()
    did = str(item.get("device_id") or "")
    if not did:
        return False, ""
    c = get_conn()
    ts = now()
    hostname = (item.get("hostname") or "").strip()
    ip = (item.get("ip") or "").strip()
    name = canonical_asset_name(
        name=(item.get("name") or "").strip() or did,
        ip=ip,
        hostname=hostname,
    )
    notes = json.dumps(
        {
            "openaudit_id": did,
            "ip": ip,
            "hostname": hostname,
            "host": hostname or ip,
            "os": item.get("os") or "",
            "domain": item.get("domain") or "",
            "oa_type": item.get("type") or "",
            "source": "openaudit",
            "description": item.get("description") or "",
        }
    )[:2000]
    existing = c.execute("SELECT id, asset_id FROM openaudit_devices WHERE device_id = ?", (did,)).fetchone()
    asset_id = (existing["asset_id"] if existing else "") or ""

    asset = ensure_asset_for_target(
        user_id,
        name,
        notes=notes,
        asset_type=_map_asset_type(str(item.get("type") or "")),
        criticality="high" if (item.get("status") or "").lower() in {"production", "prod"} else "medium",
    )
    asset_id = (asset or {}).get("id") or asset_id or ""

    fields = (
        name,
        item.get("hostname") or "",
        item.get("ip") or "",
        item.get("type") or "",
        item.get("status") or "",
        item.get("os") or "",
        item.get("domain") or "",
        item.get("description") or "",
        asset_id,
        json.dumps(item.get("raw") or item, default=str),
        ts,
    )
    inserted = False
    if existing:
        c.execute(
            """
            UPDATE openaudit_devices SET name=?, hostname=?, ip=?, type=?, status=?, os=?,
            domain=?, description=?, asset_id=?, raw_json=?, updated_at=? WHERE device_id=?
            """,
            (*fields, did),
        )
    else:
        c.execute(
            """
            INSERT INTO openaudit_devices
            (id, device_id, name, hostname, ip, type, status, os, domain, description, asset_id, raw_json, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (new_id(), did, *fields),
        )
        inserted = True
    c.commit()
    return inserted, asset_id


def ingest_live_device(user_id: str, item: dict[str, Any]) -> dict[str, Any]:
    """Upsert one live/Open-AudIT-style host and publish inventory immediately."""
    ensure_schema()
    ip = str(item.get("ip") or "").strip()
    if ip:
        row = get_conn().execute(
            "SELECT device_id FROM openaudit_devices WHERE ip = ? LIMIT 1",
            (ip,),
        ).fetchone()
        if row and row["device_id"]:
            item = {**item, "device_id": row["device_id"]}
    inserted, asset_id = _upsert_device(item, user_id)
    try:
        from app.realtime_bus import publish

        publish(
            type="inventory",
            source="openaudit",
            action="upsert",
            ip=ip,
            asset_id=asset_id,
            inserted=inserted,
            user_id=user_id,
        )
        publish(type="asset", source="inventory", id=asset_id, user_id=user_id)
    except Exception:
        pass
    return {"ok": True, "inserted": inserted, "asset_id": asset_id, "ip": ip}


def list_devices(limit: int = 100) -> list[dict[str, Any]]:
    ensure_schema()
    rows = get_conn().execute(
        "SELECT * FROM openaudit_devices ORDER BY updated_at DESC LIMIT ?",
        (max(1, min(500, int(limit))),),
    ).fetchall()
    out = []
    for r in rows:
        d = dict(r)
        try:
            d["raw"] = json.loads(d.get("raw_json") or "{}")
        except Exception:
            d["raw"] = {}
        raw = d.get("raw") if isinstance(d.get("raw"), dict) else {}
        d["open_ports"] = raw.get("open_ports") or []
        d["shares"] = raw.get("shares") or []
        d["mac"] = raw.get("mac") or ""
        out.append(d)
    return out


async def sync(user_id: str = "local") -> dict[str, Any]:
    if not oa_conn.is_configured():
        return {"configured": False, "devices_new": 0, "devices_total": 0, "assets_linked": 0, "networks": 0}

    devices = await oa_conn.fetch_devices()
    new_count = 0
    linked = 0
    for item in devices:
        inserted, asset_id = _upsert_device(item, user_id)
        if inserted:
            new_count += 1
        if asset_id:
            linked += 1
    networks = await oa_conn.fetch_networks()
    out = {
        "configured": True,
        "devices_new": new_count,
        "devices_total": len(devices),
        "assets_linked": linked,
        "networks": len(networks),
    }
    try:
        from app.realtime_bus import publish

        publish(type="inventory", source="openaudit", devices_new=new_count, devices_total=len(devices), assets_linked=linked)
        publish(type="asset", source="inventory", count=linked)
    except Exception:
        pass
    return out
