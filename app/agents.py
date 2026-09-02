"""SecuraIQ native server agent — real enrollment + telemetry check-in.

Unlike app/wazuh.py (which *pulls* from an external Wazuh manager's REST
API), this is SecuraIQ's own lightweight agent model: a small script
(scripts/securaiq_agent.py) installed on a server that *pushes* real
telemetry (hostname, OS, listening ports, installed packages) to this
backend on an interval, the same shape as Wazuh/CrowdStrike/SentinelOne
agents but install-free and native to the product.

Auth model: each agent gets a random high-entropy key at enrollment time.
Only its SHA-256 hash is ever stored — the raw key is shown once in the
enroll response/install command and cannot be retrieved again (same
discipline as an API key), matching this product's "never surface secret
values in scan output" rule.

Status is computed honestly from `last_checkin` age — an agent that stops
checking in genuinely goes "offline" after missing ~2 check-in intervals,
never held at a stale "online" the way a fake/demo integration would.
"""

from __future__ import annotations

import hashlib
import json
import secrets
from typing import Any

from app.db import get_conn, new_id, now

# An agent is considered offline once this many seconds pass with no
# check-in. Real agents check in every 60s by default (see
# scripts/securaiq_agent.py DEFAULT_INTERVAL_SEC), so 3x that is a
# reasonable, honest "missed heartbeats" threshold rather than an
# arbitrarily generous one that would mask a genuinely dead agent.
OFFLINE_AFTER_SEC = 180


def _hash_key(raw_key: str) -> str:
    return hashlib.sha256(raw_key.encode("utf-8")).hexdigest()


def ensure_schema() -> None:
    from app.db import table_columns

    c = get_conn()
    c.execute(
        """
        CREATE TABLE IF NOT EXISTS securaiq_agents (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL DEFAULT 'local',
            name TEXT NOT NULL DEFAULT '',
            key_hash TEXT NOT NULL,
            hostname TEXT NOT NULL DEFAULT '',
            ip TEXT NOT NULL DEFAULT '',
            os TEXT NOT NULL DEFAULT '',
            os_version TEXT NOT NULL DEFAULT '',
            agent_version TEXT NOT NULL DEFAULT '',
            asset_id TEXT NOT NULL DEFAULT '',
            enrolled_at REAL NOT NULL,
            last_checkin REAL NOT NULL DEFAULT 0,
            checkin_count INTEGER NOT NULL DEFAULT 0,
            last_payload_json TEXT NOT NULL DEFAULT '{}',
            revoked INTEGER NOT NULL DEFAULT 0
        )
        """
    )
    try:
        cols = table_columns(c, "securaiq_agents")
        if "asset_id" not in cols:
            c.execute("ALTER TABLE securaiq_agents ADD COLUMN asset_id TEXT NOT NULL DEFAULT ''")
    except Exception:
        pass
    c.execute(
        """
        CREATE TABLE IF NOT EXISTS securaiq_agent_threats (
            id TEXT PRIMARY KEY,
            fingerprint TEXT NOT NULL,
            agent_id TEXT NOT NULL,
            user_id TEXT NOT NULL DEFAULT 'local',
            asset_id TEXT NOT NULL DEFAULT '',
            severity TEXT NOT NULL DEFAULT 'medium',
            category TEXT NOT NULL DEFAULT 'behavioral',
            title TEXT NOT NULL DEFAULT '',
            detail TEXT NOT NULL DEFAULT '',
            target TEXT NOT NULL DEFAULT '',
            hash TEXT NOT NULL DEFAULT '',
            status TEXT NOT NULL DEFAULT 'active',
            incident_id TEXT NOT NULL DEFAULT '',
            vuln_id TEXT NOT NULL DEFAULT '',
            first_seen REAL NOT NULL,
            last_seen REAL NOT NULL,
            hit_count INTEGER NOT NULL DEFAULT 1
        )
        """
    )
    c.execute(
        "CREATE INDEX IF NOT EXISTS idx_agent_threats_fp ON securaiq_agent_threats(agent_id, fingerprint)"
    )
    c.execute(
        """
        CREATE TABLE IF NOT EXISTS securaiq_agent_commands (
            id TEXT PRIMARY KEY,
            agent_id TEXT NOT NULL,
            user_id TEXT NOT NULL DEFAULT 'local',
            kind TEXT NOT NULL,
            payload_json TEXT NOT NULL DEFAULT '{}',
            status TEXT NOT NULL DEFAULT 'queued',
            requested_by TEXT NOT NULL DEFAULT '',
            created_at REAL NOT NULL,
            sent_at REAL NOT NULL DEFAULT 0,
            completed_at REAL NOT NULL DEFAULT 0,
            result_json TEXT NOT NULL DEFAULT '{}',
            error TEXT NOT NULL DEFAULT ''
        )
        """
    )
    c.execute(
        "CREATE INDEX IF NOT EXISTS idx_agent_commands_agent ON securaiq_agent_commands(agent_id, status)"
    )
    c.commit()


def enroll_agent(user_id: str, *, name: str = "") -> dict[str, Any]:
    """Create a new agent identity. Returns the raw key ONCE — never stored."""
    ensure_schema()
    raw_key = secrets.token_urlsafe(32)
    aid = new_id()
    c = get_conn()
    c.execute(
        """
        INSERT INTO securaiq_agents
        (id, user_id, name, key_hash, enrolled_at, last_checkin, last_payload_json)
        VALUES (?, ?, ?, ?, ?, 0, '{}')
        """,
        (aid, user_id, name or "", _hash_key(raw_key), now()),
    )
    c.commit()
    return {"agent_id": aid, "agent_key": raw_key}


def _row_status(row: dict[str, Any]) -> str:
    if row.get("revoked"):
        return "revoked"
    last = float(row.get("last_checkin") or 0)
    if not last:
        return "pending"  # enrolled, never checked in yet
    return "online" if (now() - last) <= OFFLINE_AFTER_SEC else "offline"


def list_agents(user_id: str, *, limit: int = 200) -> list[dict[str, Any]]:
    ensure_schema()
    rows = get_conn().execute(
        "SELECT * FROM securaiq_agents WHERE user_id = ? ORDER BY enrolled_at DESC LIMIT ?",
        (user_id, max(1, min(limit, 500))),
    ).fetchall()
    out = []
    for r in rows:
        d = dict(r)
        try:
            d["last_payload"] = json.loads(d.get("last_payload_json") or "{}")
        except Exception:
            d["last_payload"] = {}
        d.pop("key_hash", None)  # never return the hash either
        d["status"] = _row_status(d)
        out.append(d)
    return out


def get_agent(agent_id: str) -> dict[str, Any] | None:
    ensure_schema()
    row = get_conn().execute("SELECT * FROM securaiq_agents WHERE id = ?", (agent_id,)).fetchone()
    if not row:
        return None
    d = dict(row)
    try:
        d["last_payload"] = json.loads(d.get("last_payload_json") or "{}")
    except Exception:
        d["last_payload"] = {}
    d["status"] = _row_status(d)
    return d


def authenticate_agent(agent_id: str, raw_key: str) -> dict[str, Any] | None:
    ensure_schema()
    row = get_conn().execute(
        "SELECT * FROM securaiq_agents WHERE id = ? AND revoked = 0", (agent_id,)
    ).fetchone()
    if not row:
        return None
    d = dict(row)
    if not secrets.compare_digest(d.get("key_hash") or "", _hash_key(raw_key or "")):
        return None
    return d


def _link_agent_asset(user_id: str, agent_id: str, payload: dict[str, Any]) -> str:
    from app.asset_categories import infer_asset_category
    from app.asset_names import canonical_asset_name
    from app.enterprise import ensure_asset_for_target, list_assets

    hostname = str(payload.get("hostname") or "").strip()
    ip = str(payload.get("ip") or "").strip()
    os_name = str(payload.get("os") or "").strip()
    display = canonical_asset_name(name=hostname or ip or f"agent-{agent_id[:8]}", ip=ip, hostname=hostname)
    notes = json.dumps(
        {
            "securaiq_agent_id": agent_id,
            "ip": ip,
            "hostname": hostname,
            "host": hostname or ip,
            "os": os_name,
            "os_version": str(payload.get("os_version") or ""),
            "listening_ports": payload.get("listening_ports") or [],
            "packages_count": len(payload.get("packages") or []),
            "source": "securaiq-agent",
        }
    )[:2000]
    asset_id = ""
    for a in list_assets(user_id):
        n = a.get("notes") or ""
        if f'"securaiq_agent_id": "{agent_id}"' in n:
            asset_id = a["id"]
            break
    asset = ensure_asset_for_target(
        user_id,
        display,
        notes=notes,
        asset_type=infer_asset_category(asset_type="server", os=os_name, hostname=hostname, name=display),
        criticality="high",
        resolve_ptr=False,
    )
    if asset and asset.get("id"):
        return str(asset["id"])
    return asset_id


def checkin(agent_id: str, payload: dict[str, Any]) -> dict[str, Any]:
    """Record a real telemetry check-in and (re)link the backing asset."""
    ensure_schema()
    agent = get_agent(agent_id)
    if not agent:
        return {"ok": False, "error": "unknown agent"}
    asset_id = ""
    try:
        asset_id = _link_agent_asset(agent.get("user_id") or "local", agent_id, payload)
    except Exception:
        asset_id = agent.get("asset_id") or ""
    c = get_conn()
    c.execute(
        """
        UPDATE securaiq_agents
        SET hostname=?, ip=?, os=?, os_version=?, agent_version=?, asset_id=?,
            last_checkin=?, checkin_count=checkin_count+1, last_payload_json=?
        WHERE id=?
        """,
        (
            str(payload.get("hostname") or "")[:200],
            str(payload.get("ip") or "")[:64],
            str(payload.get("os") or "")[:64],
            str(payload.get("os_version") or "")[:120],
            str(payload.get("agent_version") or "")[:32],
            asset_id,
            now(),
            json.dumps(payload)[:20000],
            agent_id,
        ),
    )
    c.commit()
    try:
        from app.realtime_bus import publish

        publish(type="agent", id=agent_id, status="online", asset_id=asset_id)
    except Exception:
        pass
    commands = _dispatch_queued_commands(agent_id)
    return {"ok": True, "asset_id": asset_id, "commands": commands}


def _dispatch_queued_commands(agent_id: str, *, limit: int = 5) -> list[dict[str, Any]]:
    """Hand any queued commands to the agent on this check-in (the agent has
    no inbound listener — check-in is the only pull channel — so this is
    where server -> agent commands actually get delivered) and mark them
    'sent' so the same command isn't handed out again on the next check-in
    while the agent is still working on it."""
    c = get_conn()
    rows = c.execute(
        "SELECT * FROM securaiq_agent_commands WHERE agent_id = ? AND status = 'queued' ORDER BY created_at ASC LIMIT ?",
        (agent_id, max(1, limit)),
    ).fetchall()
    out: list[dict[str, Any]] = []
    ts = now()
    for r in rows:
        d = dict(r)
        c.execute(
            "UPDATE securaiq_agent_commands SET status = 'sent', sent_at = ? WHERE id = ?",
            (ts, d["id"]),
        )
        try:
            payload = json.loads(d.get("payload_json") or "{}")
        except Exception:
            payload = {}
        out.append({"id": d["id"], "kind": d["kind"], "payload": payload})
    if rows:
        c.commit()
        try:
            from app.realtime_bus import publish

            publish(type="agent_command", agent_id=agent_id, status="sent", count=len(rows))
        except Exception:
            pass
    return out


# A repeat sighting of the same still-active threat (e.g. a persistent
# miner process) re-alerts at most this often, so a continuous watcher
# doesn't spam an incident/finding on every scan tick while a genuine
# ongoing compromise still surfaces again periodically rather than going
# silent after the first alert.
THREAT_RE_ALERT_SEC = 1800


def _threat_fingerprint(category: str, title: str, target: str) -> str:
    raw = f"{category}|{title}|{target}".strip().lower()
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:32]


def record_threat_detections(agent_id: str, detections: list[dict[str, Any]]) -> dict[str, Any]:
    """Ingest SecuraIQ Sentinel detections from an agent's real-time watcher.

    Each detection creates/updates a `securaiq_agent_threats` row (deduped by
    fingerprint so a persistent threat doesn't spam a new record every scan
    tick), always creates a linked finding (`vulnerabilities` row, so it's
    visible on the asset), and — for critical/high severity — also opens a
    SOC incident. Publishes a realtime push immediately so connected UIs see
    it the moment it's ingested, not on the next poll.
    """
    ensure_schema()
    agent = get_agent(agent_id)
    if not agent:
        return {"ok": False, "error": "unknown agent"}
    user_id = agent.get("user_id") or "local"
    asset_id = agent.get("asset_id") or ""
    hostname = agent.get("hostname") or agent.get("id", "")[:8]
    c = get_conn()
    ts = now()
    created: list[dict[str, Any]] = []
    skipped = 0
    for det in detections or []:
        category = str(det.get("category") or "behavioral")[:32]
        severity = str(det.get("severity") or "medium").lower()
        if severity not in ("critical", "high", "medium", "low"):
            severity = "medium"
        title = str(det.get("title") or "Suspicious activity detected")[:200]
        detail = str(det.get("detail") or "")[:1000]
        target = str(det.get("target") or "")[:500]
        file_hash = str(det.get("hash") or "")[:64]
        fp = _threat_fingerprint(category, title, target)
        existing = c.execute(
            "SELECT * FROM securaiq_agent_threats WHERE agent_id = ? AND fingerprint = ? ORDER BY last_seen DESC LIMIT 1",
            (agent_id, fp),
        ).fetchone()
        if existing:
            ex = dict(existing)
            still_fresh = (ts - float(ex.get("last_seen") or 0)) < THREAT_RE_ALERT_SEC
            c.execute(
                "UPDATE securaiq_agent_threats SET last_seen=?, hit_count=hit_count+1, status='active' WHERE id=?",
                (ts, ex["id"]),
            )
            c.commit()
            if still_fresh:
                skipped += 1
                continue
            tid = ex["id"]
        else:
            tid = new_id()
            c.execute(
                """
                INSERT INTO securaiq_agent_threats
                (id, fingerprint, agent_id, user_id, asset_id, severity, category, title, detail, target, hash,
                 status, first_seen, last_seen, hit_count)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'active', ?, ?, 1)
                """,
                (tid, fp, agent_id, user_id, asset_id, severity, category, title, detail, target, file_hash, ts, ts),
            )
            c.commit()

        # Always create a linked finding so the detection shows up on the asset.
        vuln_id = ""
        try:
            from app.enterprise import create_vulnerability

            vrow = create_vulnerability(
                user_id,
                {
                    "asset_id": asset_id,
                    "asset_name": hostname,
                    "title": f"[Sentinel] {title}",
                    "severity": severity,
                    "status": "open",
                    "source": "agent:sentinel",
                    "raw": {**det, "agent_id": agent_id, "hostname": hostname},
                },
            )
            vuln_id = str((vrow or {}).get("id") or "")
        except Exception:
            pass

        # High-signal detections also open a SOC incident.
        incident_id = ""
        if severity in ("critical", "high"):
            try:
                from app.ops import create_incident

                irow = create_incident(
                    user_id,
                    title=f"[Sentinel] {title} — {hostname}",
                    severity=severity,
                    status="open",
                    source="agent:sentinel",
                    summary=f"Host: {hostname} · Category: {category} · {detail}"[:900],
                )
                incident_id = str((irow or {}).get("id") or "")
            except Exception:
                pass

        c.execute(
            "UPDATE securaiq_agent_threats SET vuln_id=?, incident_id=? WHERE id=?",
            (vuln_id, incident_id, tid),
        )
        c.commit()

        payload = {
            "id": tid,
            "agent_id": agent_id,
            "asset_id": asset_id,
            "hostname": hostname,
            "severity": severity,
            "category": category,
            "title": title,
            "detail": detail,
            "target": target,
            "hash": file_hash,
            "incident_id": incident_id,
            "vuln_id": vuln_id,
        }
        created.append(payload)
        try:
            from app.realtime_bus import publish

            publish(type="agent_threat", **payload)
        except Exception:
            pass

    return {"ok": True, "created": len(created), "skipped": skipped, "detections": created}


def list_threats(user_id: str, *, agent_id: str | None = None, limit: int = 200) -> list[dict[str, Any]]:
    ensure_schema()
    c = get_conn()
    q = "SELECT * FROM securaiq_agent_threats WHERE user_id = ?"
    args: list[Any] = [user_id]
    if agent_id:
        q += " AND agent_id = ?"
        args.append(agent_id)
    q += " ORDER BY last_seen DESC LIMIT ?"
    args.append(max(1, min(limit, 500)))
    rows = c.execute(q, args).fetchall()
    return [dict(r) for r in rows]


def revoke_agent(user_id: str, agent_id: str) -> bool:
    ensure_schema()
    c = get_conn()
    row = c.execute("SELECT id FROM securaiq_agents WHERE id = ? AND user_id = ?", (agent_id, user_id)).fetchone()
    if not row:
        return False
    c.execute("UPDATE securaiq_agents SET revoked = 1 WHERE id = ?", (agent_id,))
    c.commit()
    return True


def delete_agent(user_id: str, agent_id: str) -> bool:
    ensure_schema()
    c = get_conn()
    row = c.execute("SELECT id FROM securaiq_agents WHERE id = ? AND user_id = ?", (agent_id, user_id)).fetchone()
    if not row:
        return False
    c.execute("DELETE FROM securaiq_agents WHERE id = ?", (agent_id,))
    c.commit()
    return True


# ---------------------------------------------------------------------------
# Agent command channel — the patch-execution + verification loop.
#
# The agent has no inbound listener (it only ever calls out to the server),
# so a "command" is not pushed live: it is queued here, then handed to the
# agent as part of its next regular check-in response (see
# _dispatch_queued_commands above), and the agent reports the outcome back
# via report_command_result(). This keeps the transport identical to the
# existing check-in model — no new port, no new protocol — at the cost of
# latency bounded by the agent's --interval (default 60s), which is an
# honest tradeoff spelled out in the API docstrings rather than a silent one.
#
# `kind` is deliberately an allowlist, not free-form shell: the only command
# an agent will currently execute is "patch_package" (an OS package-manager
# upgrade of one named package), never an arbitrary command string. Queuing
# one requires an authenticated user request (see agents_api.py), which is
# this feature's approval gate — there is no autonomous/AI-initiated queuing
# path in this MVP.
# ---------------------------------------------------------------------------

SUPPORTED_COMMAND_KINDS = {"patch_package"}


def queue_command(
    user_id: str, agent_id: str, *, kind: str, payload: dict[str, Any], requested_by: str = ""
) -> dict[str, Any]:
    """Queue a command for delivery on the agent's next check-in. Raises
    ValueError for an unknown agent or an unsupported command kind — callers
    (the API layer) turn that into a 4xx rather than silently no-op'ing."""
    ensure_schema()
    agent = get_agent(agent_id)
    if not agent or agent.get("user_id") != user_id:
        raise ValueError("Agent not found")
    if agent.get("revoked"):
        raise ValueError("Agent is revoked")
    if kind not in SUPPORTED_COMMAND_KINDS:
        raise ValueError(f"Unsupported command kind '{kind}'")
    cid = new_id()
    c = get_conn()
    c.execute(
        """
        INSERT INTO securaiq_agent_commands
        (id, agent_id, user_id, kind, payload_json, status, requested_by, created_at)
        VALUES (?, ?, ?, ?, ?, 'queued', ?, ?)
        """,
        (cid, agent_id, user_id, kind, json.dumps(payload)[:4000], requested_by or user_id, now()),
    )
    c.commit()
    try:
        from app.realtime_bus import publish

        publish(type="agent_command", agent_id=agent_id, id=cid, status="queued", kind=kind)
    except Exception:
        pass
    return {"id": cid, "status": "queued"}


def list_commands(user_id: str, agent_id: str, *, limit: int = 100) -> list[dict[str, Any]]:
    ensure_schema()
    rows = get_conn().execute(
        "SELECT * FROM securaiq_agent_commands WHERE user_id = ? AND agent_id = ? ORDER BY created_at DESC LIMIT ?",
        (user_id, agent_id, max(1, min(limit, 300))),
    ).fetchall()
    out = []
    for r in rows:
        d = dict(r)
        for key in ("payload_json", "result_json"):
            try:
                d[key[: -len("_json")]] = json.loads(d.get(key) or "{}")
            except Exception:
                d[key[: -len("_json")]] = {}
        out.append(d)
    return out


def report_command_result(agent_id: str, command_id: str, *, status: str, result: dict[str, Any]) -> dict[str, Any]:
    """Agent reports the outcome of a command it executed. Also kicks off
    verification: a software-inventory refresh for this agent's asset, so
    the patch-gap dashboard reflects the new version on the very next
    check-in rather than waiting on the periodic sync schedule."""
    ensure_schema()
    c = get_conn()
    row = c.execute(
        "SELECT * FROM securaiq_agent_commands WHERE id = ? AND agent_id = ?", (command_id, agent_id)
    ).fetchone()
    if not row:
        return {"ok": False, "error": "unknown command"}
    status = status if status in ("done", "error") else "error"
    ts = now()
    c.execute(
        "UPDATE securaiq_agent_commands SET status = ?, completed_at = ?, result_json = ?, error = ? WHERE id = ?",
        (
            status,
            ts,
            json.dumps(result)[:8000],
            "" if status == "done" else str(result.get("error") or "")[:500],
            command_id,
        ),
    )
    c.commit()
    agent = get_agent(agent_id)
    asset_id = (agent or {}).get("asset_id") or ""
    try:
        from app.realtime_bus import publish

        publish(
            type="agent_command",
            agent_id=agent_id,
            id=command_id,
            status=status,
            asset_id=asset_id,
        )
    except Exception:
        pass
    if status == "done" and asset_id:
        try:
            from app.jobs import enqueue_job

            enqueue_job(
                "software_advisory_refresh",
                {
                    "user_id": (agent or {}).get("user_id") or "local",
                    "asset_id": asset_id,
                    "reason": "patch_verify",
                    "command_id": command_id,
                },
            )
        except Exception:
            pass
    return {"ok": True, "status": status}
