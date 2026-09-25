"""Process / user / config / listener change detection from consecutive check-ins.

Lab-production continuous-posture depth — not a full EDR timeline product.
"""

from __future__ import annotations

import json
from typing import Any

from app.db import get_conn, new_id, now


def ensure_schema() -> None:
    c = get_conn()
    c.execute(
        """
        CREATE TABLE IF NOT EXISTS securaiq_host_changes (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            agent_id TEXT NOT NULL,
            change_json TEXT NOT NULL DEFAULT '{}',
            created_at REAL NOT NULL
        )
        """
    )
    c.execute(
        "CREATE INDEX IF NOT EXISTS idx_host_changes_user ON securaiq_host_changes(user_id, created_at DESC)"
    )
    c.commit()


def _names(blob: Any, *keys: str) -> set[str]:
    if not isinstance(blob, dict):
        return set()
    items = blob.get("items") if isinstance(blob.get("items"), list) else blob
    if not isinstance(items, list):
        return set()
    out: set[str] = set()
    for it in items:
        if isinstance(it, dict):
            for k in keys:
                v = it.get(k)
                if v:
                    out.add(str(v).lower())
        elif it:
            out.add(str(it).lower())
    return out


def _ports(payload: dict[str, Any]) -> set[str]:
    raw = payload.get("listening_ports") or []
    out: set[str] = set()
    if isinstance(raw, list):
        for p in raw:
            if isinstance(p, dict):
                port = p.get("port")
                if port is not None:
                    out.add(str(port))
            elif p is not None:
                out.add(str(p))
    return out


def _cfg_map(payload: dict[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    fw = payload.get("firewall_status") if isinstance(payload.get("firewall_status"), dict) else {}
    de = (
        payload.get("disk_encryption_status")
        if isinstance(payload.get("disk_encryption_status"), dict)
        else {}
    )
    ssh = payload.get("ssh_config") if isinstance(payload.get("ssh_config"), dict) else {}
    mh = payload.get("macos_hardening") if isinstance(payload.get("macos_hardening"), dict) else {}
    out["firewall_enabled"] = fw.get("enabled")
    out["disk_encrypted"] = de.get("encrypted")
    settings = ssh.get("settings") if isinstance(ssh.get("settings"), dict) else {}
    out["ssh_permit_root"] = settings.get("PermitRootLogin")
    out["gatekeeper"] = mh.get("gatekeeper_enabled")
    out["sip"] = mh.get("sip_enabled")
    out["remote_login"] = mh.get("remote_login")
    return out


def diff_host_payload(previous: dict[str, Any] | None, current: dict[str, Any] | None) -> dict[str, Any]:
    prev = previous if isinstance(previous, dict) else {}
    curr = current if isinstance(current, dict) else {}
    users_prev = _names(prev.get("local_users"), "name")
    users_curr = _names(curr.get("local_users"), "name")
    proc_prev = _names(prev.get("processes"), "name", "comm")
    proc_curr = _names(curr.get("processes"), "name", "comm")
    start_prev = _names(prev.get("startup_apps"), "name")
    start_curr = _names(curr.get("startup_apps"), "name")
    ports_prev = _ports(prev)
    ports_curr = _ports(curr)
    cfg_prev = _cfg_map(prev)
    cfg_curr = _cfg_map(curr)
    cfg_changed = {k: {"from": cfg_prev.get(k), "to": cfg_curr.get(k)} for k in cfg_curr if cfg_prev.get(k) != cfg_curr.get(k)}
    changes = {
        "users_added": sorted(users_curr - users_prev),
        "users_removed": sorted(users_prev - users_curr),
        "processes_added": sorted(proc_curr - proc_prev)[:40],
        "processes_removed": sorted(proc_prev - proc_curr)[:40],
        "startup_added": sorted(start_curr - start_prev),
        "startup_removed": sorted(start_prev - start_curr),
        "ports_opened": sorted(ports_curr - ports_prev, key=lambda x: int(x) if x.isdigit() else 0),
        "ports_closed": sorted(ports_prev - ports_curr, key=lambda x: int(x) if x.isdigit() else 0),
        "config_changed": cfg_changed,
    }
    has = any(
        changes[k]
        for k in (
            "users_added",
            "users_removed",
            "startup_added",
            "startup_removed",
            "ports_opened",
            "ports_closed",
            "config_changed",
        )
    ) or bool(changes["processes_added"] or changes["processes_removed"])
    return {"ok": True, "has_changes": has, "changes": changes}


def record_checkin_changes(
    user_id: str,
    agent_id: str,
    previous: dict[str, Any] | None,
    current: dict[str, Any] | None,
) -> dict[str, Any]:
    ensure_schema()
    diff = diff_host_payload(previous, current)
    if not previous or not diff.get("has_changes"):
        return diff
    c = get_conn()
    c.execute(
        "INSERT INTO securaiq_host_changes (id, user_id, agent_id, change_json, created_at) VALUES (?, ?, ?, ?, ?)",
        (new_id(), user_id, agent_id, json.dumps(diff.get("changes") or {}), now()),
    )
    c.commit()
    return diff


def list_host_changes(user_id: str, *, limit: int = 25) -> dict[str, Any]:
    ensure_schema()
    rows = get_conn().execute(
        "SELECT * FROM securaiq_host_changes WHERE user_id = ? ORDER BY created_at DESC LIMIT ?",
        (user_id, max(1, min(limit, 100))),
    ).fetchall()
    items = []
    for r in rows:
        d = dict(r)
        try:
            d["changes"] = json.loads(d.get("change_json") or "{}")
        except Exception:
            d["changes"] = {}
        items.append(d)
    return {
        "ok": True,
        "count": len(items),
        "changes": items,
        "disclaimer": "Derived from consecutive agent check-ins — not a full EDR process tree.",
    }
