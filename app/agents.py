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
from datetime import datetime, timezone
from typing import Any

from app.db import audit, get_conn, new_id, now

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
            status TEXT NOT NULL DEFAULT 'pending_approval',
            requested_by TEXT NOT NULL DEFAULT '',
            approved_by TEXT NOT NULL DEFAULT '',
            approved_at REAL NOT NULL DEFAULT 0,
            rejected_reason TEXT NOT NULL DEFAULT '',
            campaign_id TEXT NOT NULL DEFAULT '',
            created_at REAL NOT NULL,
            sent_at REAL NOT NULL DEFAULT 0,
            completed_at REAL NOT NULL DEFAULT 0,
            result_json TEXT NOT NULL DEFAULT '{}',
            error TEXT NOT NULL DEFAULT ''
        )
        """
    )
    try:
        cmd_cols = table_columns(c, "securaiq_agent_commands")
        for col, ddl in (
            ("approved_by", "ALTER TABLE securaiq_agent_commands ADD COLUMN approved_by TEXT NOT NULL DEFAULT ''"),
            ("approved_at", "ALTER TABLE securaiq_agent_commands ADD COLUMN approved_at REAL NOT NULL DEFAULT 0"),
            ("rejected_reason", "ALTER TABLE securaiq_agent_commands ADD COLUMN rejected_reason TEXT NOT NULL DEFAULT ''"),
            ("campaign_id", "ALTER TABLE securaiq_agent_commands ADD COLUMN campaign_id TEXT NOT NULL DEFAULT ''"),
            ("ring_index", "ALTER TABLE securaiq_agent_commands ADD COLUMN ring_index INTEGER NOT NULL DEFAULT 0"),
        ):
            if col not in cmd_cols:
                c.execute(ddl)
    except Exception:
        pass
    c.execute(
        "CREATE INDEX IF NOT EXISTS idx_agent_commands_agent ON securaiq_agent_commands(agent_id, status)"
    )
    c.execute(
        "CREATE INDEX IF NOT EXISTS idx_agent_commands_campaign ON securaiq_agent_commands(campaign_id)"
    )
    c.execute(
        """
        CREATE TABLE IF NOT EXISTS securaiq_patch_campaigns (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL DEFAULT 'local',
            name TEXT NOT NULL DEFAULT '',
            manager TEXT NOT NULL DEFAULT '',
            package TEXT NOT NULL DEFAULT '',
            target_version TEXT NOT NULL DEFAULT '',
            requested_by TEXT NOT NULL DEFAULT '',
            rings_json TEXT NOT NULL DEFAULT '[]',
            window_start_hour INTEGER NOT NULL DEFAULT -1,
            window_end_hour INTEGER NOT NULL DEFAULT -1,
            window_days_json TEXT NOT NULL DEFAULT '[]',
            ring_threshold_pct REAL NOT NULL DEFAULT 100,
            status TEXT NOT NULL DEFAULT 'active',
            created_at REAL NOT NULL
        )
        """
    )
    c.execute(
        "CREATE INDEX IF NOT EXISTS idx_patch_campaigns_user ON securaiq_patch_campaigns(user_id, created_at)"
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
    while the agent is still working on it.

    A command tied to a campaign with a maintenance window is approved and
    queued the same as any other, but is held back here — not delivered —
    until the current time falls inside that campaign's window. It stays
    'queued' and is simply reconsidered on the agent's next check-in."""
    c = get_conn()
    rows = c.execute(
        "SELECT * FROM securaiq_agent_commands WHERE agent_id = ? AND status = 'queued' ORDER BY created_at ASC LIMIT ?",
        (agent_id, max(1, limit * 3)),
    ).fetchall()
    campaign_cache: dict[str, dict[str, Any] | None] = {}
    out: list[dict[str, Any]] = []
    ts = now()
    for r in rows:
        if len(out) >= limit:
            break
        d = dict(r)
        cid = d.get("campaign_id") or ""
        if cid:
            if cid not in campaign_cache:
                crow = c.execute("SELECT * FROM securaiq_patch_campaigns WHERE id = ?", (cid,)).fetchone()
                campaign_cache[cid] = dict(crow) if crow else None
            campaign = campaign_cache[cid]
            if campaign and not _in_maintenance_window(campaign):
                continue  # held for the next check-in, still 'queued'
        c.execute(
            "UPDATE securaiq_agent_commands SET status = 'sent', sent_at = ? WHERE id = ?",
            (ts, d["id"]),
        )
        try:
            payload = json.loads(d.get("payload_json") or "{}")
        except Exception:
            payload = {}
        out.append({"id": d["id"], "kind": d["kind"], "payload": payload})
    if out:
        c.commit()
        try:
            from app.realtime_bus import publish

            publish(type="agent_command", agent_id=agent_id, status="sent", count=len(out))
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
# upgrade of one named package), never an arbitrary command string.
#
# Requesting a command never queues it for delivery directly. It lands in
# 'pending_approval'; a second, distinct actor (an admin, when auth/RBAC is
# turned on) must call approve_command() before it flips to 'queued' and can
# be picked up by _dispatch_queued_commands() on the agent's next check-in.
# In local/lab mode (auth disabled) the synthetic local user is already
# role="admin", so this doesn't block solo usage — but the two-step state
# machine is real and is what a patch campaign's per-item commands ride on.
# ---------------------------------------------------------------------------

SUPPORTED_COMMAND_KINDS = {"patch_package"}
COMMAND_STATUSES = {"pending_approval", "queued", "sent", "done", "error", "rejected"}


def request_command(
    user_id: str,
    agent_id: str,
    *,
    kind: str,
    payload: dict[str, Any],
    requested_by: str = "",
    campaign_id: str = "",
    ring_index: int = 0,
) -> dict[str, Any]:
    """Create a command request in 'pending_approval'. Raises ValueError for
    an unknown agent or an unsupported command kind — callers (the API layer)
    turn that into a 4xx rather than silently no-op'ing. Does NOT queue the
    command for delivery — see approve_command()."""
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
        (id, agent_id, user_id, kind, payload_json, status, requested_by, campaign_id, ring_index, created_at)
        VALUES (?, ?, ?, ?, ?, 'pending_approval', ?, ?, ?, ?)
        """,
        (cid, agent_id, user_id, kind, json.dumps(payload)[:4000], requested_by or user_id, campaign_id, ring_index, now()),
    )
    c.commit()
    try:
        from app.realtime_bus import publish

        publish(type="agent_command", agent_id=agent_id, id=cid, status="pending_approval", kind=kind)
    except Exception:
        pass
    return {"id": cid, "status": "pending_approval"}


# Backwards-compatible alias: older callers/tests may still say "queue_command"
# meaning "request one". It no longer queues for delivery directly — approval
# is required first.
queue_command = request_command


def _get_command_row(user_id: str, agent_id: str, command_id: str):
    c = get_conn()
    row = c.execute(
        "SELECT * FROM securaiq_agent_commands WHERE id = ? AND agent_id = ?", (command_id, agent_id)
    ).fetchone()
    if not row:
        return None
    d = dict(row)
    if d.get("user_id") != user_id:
        return None
    return d


def approve_command(user_id: str, agent_id: str, command_id: str, *, approver_id: str) -> dict[str, Any]:
    """Transition a command from 'pending_approval' to 'queued', making it
    eligible for delivery on the agent's next check-in. Raises ValueError if
    the command doesn't exist, isn't owned by user_id, or isn't currently
    pending approval."""
    ensure_schema()
    row = _get_command_row(user_id, agent_id, command_id)
    if not row:
        raise ValueError("Command not found")
    if row.get("status") != "pending_approval":
        raise ValueError(f"Command is not pending approval (status: {row.get('status')})")
    c = get_conn()
    ts = now()
    c.execute(
        "UPDATE securaiq_agent_commands SET status = 'queued', approved_by = ?, approved_at = ? WHERE id = ?",
        (approver_id, ts, command_id),
    )
    c.commit()
    audit("agent_command_approve", user_id, {"agent_id": agent_id, "command_id": command_id, "approver_id": approver_id})
    try:
        from app.realtime_bus import publish

        publish(type="agent_command", agent_id=agent_id, id=command_id, status="queued")
    except Exception:
        pass
    return {"id": command_id, "status": "queued"}


def reject_command(user_id: str, agent_id: str, command_id: str, *, approver_id: str, reason: str = "") -> dict[str, Any]:
    """Transition a command from 'pending_approval' to 'rejected'. The agent
    never sees a rejected command — it is simply never dispatched."""
    ensure_schema()
    row = _get_command_row(user_id, agent_id, command_id)
    if not row:
        raise ValueError("Command not found")
    if row.get("status") != "pending_approval":
        raise ValueError(f"Command is not pending approval (status: {row.get('status')})")
    c = get_conn()
    ts = now()
    c.execute(
        "UPDATE securaiq_agent_commands SET status = 'rejected', approved_by = ?, approved_at = ?, rejected_reason = ? WHERE id = ?",
        (approver_id, ts, str(reason or "")[:500], command_id),
    )
    c.commit()
    audit("agent_command_reject", user_id, {"agent_id": agent_id, "command_id": command_id, "approver_id": approver_id, "reason": reason})
    try:
        from app.realtime_bus import publish

        publish(type="agent_command", agent_id=agent_id, id=command_id, status="rejected")
    except Exception:
        pass
    return {"id": command_id, "status": "rejected"}


def list_pending_commands(user_id: str, *, limit: int = 200) -> list[dict[str, Any]]:
    """All commands awaiting approval across all of this user's agents —
    backs the approvals UI/queue view."""
    ensure_schema()
    rows = get_conn().execute(
        "SELECT * FROM securaiq_agent_commands WHERE user_id = ? AND status = 'pending_approval' ORDER BY created_at ASC LIMIT ?",
        (user_id, max(1, min(limit, 500))),
    ).fetchall()
    out = []
    for r in rows:
        d = dict(r)
        try:
            d["payload"] = json.loads(d.get("payload_json") or "{}")
        except Exception:
            d["payload"] = {}
        out.append(d)
    return out


# ---------------------------------------------------------------------------
# Patch campaigns — target the same package+manager upgrade at many agents
# at once. A campaign is a thin grouping layer: it stores the shared intent
# (name/manager/package/target_version) and stamps one securaiq_agent_commands
# row per targeted agent with the same campaign_id, so every existing
# per-command mechanic (approval, delivery, result reporting, verification)
# is reused unchanged rather than duplicated. Rings/maintenance-windows
# (ring_index, window_* columns) are plumbed into the schema now but not yet
# enforced by dispatch — that's the next layer built on top of this one.
# ---------------------------------------------------------------------------


def create_campaign(
    user_id: str,
    *,
    name: str,
    manager: str,
    package: str,
    target_version: str = "",
    agent_ids: list[str] | None = None,
    rings: list[list[str]] | None = None,
    window_start_hour: int = -1,
    window_end_hour: int = -1,
    window_days: list[int] | None = None,
    ring_threshold_pct: float = 100,
    requested_by: str = "",
) -> dict[str, Any]:
    """Create a campaign and request one patch_package command per targeted
    agent in the FIRST ring only (each lands in 'pending_approval', same as
    a single ad-hoc patch request). Later rings are not created yet — they
    are held in rings_json and only materialized once the prior ring clears
    ring_threshold_pct (see _maybe_advance_campaign_ring, called from
    report_command_result). A flat `agent_ids` list (no rings) behaves as a
    single-ring campaign — identical to the pre-rings behavior. Raises
    ValueError if no valid, owned, non-revoked agents were given in the
    first ring — a campaign with zero real targets is refused rather than
    silently created empty."""
    ensure_schema()
    ring_list: list[list[str]] = [list(r) for r in rings] if rings else ([list(agent_ids)] if agent_ids else [])
    if not ring_list or not ring_list[0]:
        raise ValueError("At least one target agent is required")
    if window_start_hour != -1 and not (0 <= window_start_hour <= 23):
        raise ValueError("window_start_hour must be 0-23 (or -1 for no window)")
    if window_end_hour != -1 and not (0 <= window_end_hour <= 23):
        raise ValueError("window_end_hour must be 0-23 (or -1 for no window)")
    cid = new_id()
    ts = now()
    c = get_conn()
    c.execute(
        """
        INSERT INTO securaiq_patch_campaigns
        (id, user_id, name, manager, package, target_version, requested_by,
         rings_json, window_start_hour, window_end_hour, window_days_json, ring_threshold_pct, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            cid, user_id, name or f"{manager} upgrade {package}", manager, package, target_version, requested_by or user_id,
            json.dumps(ring_list), window_start_hour, window_end_hour, json.dumps(window_days or []),
            max(0.0, min(100.0, ring_threshold_pct)), ts,
        ),
    )
    c.commit()
    items: list[dict[str, Any]] = []
    errors: list[dict[str, str]] = []
    for agent_id in ring_list[0]:
        try:
            result = request_command(
                user_id,
                agent_id,
                kind="patch_package",
                payload={"manager": manager, "package": package, "target_version": target_version},
                requested_by=requested_by or user_id,
                campaign_id=cid,
                ring_index=0,
            )
            items.append({"agent_id": agent_id, **result})
        except ValueError as exc:
            errors.append({"agent_id": agent_id, "error": str(exc)})
    if not items:
        # every target was invalid (unowned/unknown/revoked) — refuse the
        # whole campaign rather than leaving an empty, useless row behind.
        c.execute("DELETE FROM securaiq_patch_campaigns WHERE id = ?", (cid,))
        c.commit()
        raise ValueError(f"No valid targets: {errors}")
    audit(
        "patch_campaign_create",
        user_id,
        {
            "campaign_id": cid, "name": name, "manager": manager, "package": package,
            "rings": len(ring_list), "ring0_targets": len(ring_list[0]), "created": len(items),
        },
    )
    return {"id": cid, "status": "active", "requested": len(items), "failed_targets": errors, "rings": len(ring_list)}


def _in_maintenance_window(campaign: dict[str, Any]) -> bool:
    """No window configured (window_start_hour == -1) means always eligible
    — maintenance windows are opt-in, not a default restriction. Hours are
    UTC; window_days uses Python's Monday=0..Sunday=6, empty = every day.
    A window that wraps midnight (start > end) is supported."""
    start_h = campaign.get("window_start_hour", -1)
    end_h = campaign.get("window_end_hour", -1)
    if start_h == -1 or end_h == -1:
        return True
    try:
        days = json.loads(campaign.get("window_days_json") or "[]")
    except Exception:
        days = []
    nowdt = datetime.now(timezone.utc)
    if days and nowdt.weekday() not in days:
        return False
    h = nowdt.hour
    if start_h == end_h:
        return True  # equal start/end reads as "all day", not a zero-width window
    if start_h < end_h:
        return start_h <= h < end_h
    return h >= start_h or h < end_h  # wraps past midnight


def _maybe_advance_campaign_ring(campaign_id: str, user_id: str) -> None:
    """Called after a command's result is reported. If that command was the
    last unresolved item in its ring, decide whether to auto-stop the
    campaign (ring failed below threshold) or materialize the next ring's
    commands (ring passed). No-op for campaigns with no further rings, or
    if the ring still has unresolved (pending/queued/sent) items."""
    c = get_conn()
    campaign = c.execute(
        "SELECT * FROM securaiq_patch_campaigns WHERE id = ?", (campaign_id,)
    ).fetchone()
    if not campaign:
        return
    campaign = dict(campaign)
    if campaign.get("status") not in ("active",):
        return
    try:
        ring_list = json.loads(campaign.get("rings_json") or "[]")
    except Exception:
        ring_list = []
    ring_rows = c.execute(
        "SELECT ring_index, status FROM securaiq_agent_commands WHERE campaign_id = ?", (campaign_id,)
    ).fetchall()
    if not ring_rows:
        return
    max_created_ring = max(r["ring_index"] for r in ring_rows)
    current_ring_rows = [r for r in ring_rows if r["ring_index"] == max_created_ring]
    unresolved = {"pending_approval", "queued", "sent"}
    if any(r["status"] in unresolved for r in current_ring_rows):
        return  # current ring still in flight
    total = len(current_ring_rows)
    done = sum(1 for r in current_ring_rows if r["status"] == "done")
    success_pct = (done / total * 100) if total else 0
    threshold = campaign.get("ring_threshold_pct", 100)
    next_ring_index = max_created_ring + 1
    if success_pct < threshold:
        c.execute(
            "UPDATE securaiq_patch_campaigns SET status = 'halted' WHERE id = ?", (campaign_id,)
        )
        c.commit()
        audit(
            "patch_campaign_ring_halted", user_id,
            {"campaign_id": campaign_id, "ring": max_created_ring, "success_pct": success_pct, "threshold": threshold},
        )
        return
    if next_ring_index >= len(ring_list):
        c.execute(
            "UPDATE securaiq_patch_campaigns SET status = 'completed' WHERE id = ?", (campaign_id,)
        )
        c.commit()
        audit("patch_campaign_completed", user_id, {"campaign_id": campaign_id, "rings": len(ring_list)})
        return
    # ring passed and there's a next ring — materialize it (pending_approval,
    # same as ring 0; a human still approves each ring's dispatch).
    next_targets = ring_list[next_ring_index] or []
    manager, package, target_version = campaign.get("manager", ""), campaign.get("package", ""), campaign.get("target_version", "")
    created = 0
    for agent_id in next_targets:
        try:
            request_command(
                campaign.get("user_id") or user_id,
                agent_id,
                kind="patch_package",
                payload={"manager": manager, "package": package, "target_version": target_version},
                requested_by=campaign.get("requested_by") or user_id,
                campaign_id=campaign_id,
                ring_index=next_ring_index,
            )
            created += 1
        except ValueError:
            continue
    audit(
        "patch_campaign_ring_advanced", user_id,
        {"campaign_id": campaign_id, "ring": next_ring_index, "targets": len(next_targets), "created": created},
    )


def _campaign_summary(user_id: str, campaign_id: str) -> dict[str, Any]:
    rows = get_conn().execute(
        "SELECT status, COUNT(*) as n FROM securaiq_agent_commands WHERE user_id = ? AND campaign_id = ? GROUP BY status",
        (user_id, campaign_id),
    ).fetchall()
    counts = {r["status"]: r["n"] for r in rows}
    total = sum(counts.values())
    return {
        "total": total,
        "pending_approval": counts.get("pending_approval", 0),
        "queued": counts.get("queued", 0),
        "sent": counts.get("sent", 0),
        "done": counts.get("done", 0),
        "error": counts.get("error", 0),
        "rejected": counts.get("rejected", 0),
    }


def list_campaigns(user_id: str, *, limit: int = 100) -> list[dict[str, Any]]:
    ensure_schema()
    rows = get_conn().execute(
        "SELECT * FROM securaiq_patch_campaigns WHERE user_id = ? ORDER BY created_at DESC LIMIT ?",
        (user_id, max(1, min(limit, 300))),
    ).fetchall()
    out = []
    for r in rows:
        d = dict(r)
        d["summary"] = _campaign_summary(user_id, d["id"])
        out.append(d)
    return out


def get_campaign(user_id: str, campaign_id: str) -> dict[str, Any] | None:
    ensure_schema()
    row = get_conn().execute(
        "SELECT * FROM securaiq_patch_campaigns WHERE id = ? AND user_id = ?", (campaign_id, user_id)
    ).fetchone()
    if not row:
        return None
    d = dict(row)
    d["summary"] = _campaign_summary(user_id, campaign_id)
    item_rows = get_conn().execute(
        "SELECT * FROM securaiq_agent_commands WHERE campaign_id = ? AND user_id = ? ORDER BY created_at ASC",
        (campaign_id, user_id),
    ).fetchall()
    items = []
    for r in item_rows:
        item = dict(r)
        try:
            item["payload"] = json.loads(item.get("payload_json") or "{}")
            item["result"] = json.loads(item.get("result_json") or "{}")
        except Exception:
            item["payload"], item["result"] = {}, {}
        items.append(item)
    d["items"] = items
    return d


def approve_campaign(user_id: str, campaign_id: str, *, approver_id: str) -> dict[str, Any]:
    """Approve every still-pending item in a campaign. Individual items that
    already moved on (queued/sent/done/etc.) are left untouched — this is
    additive, not a reset."""
    ensure_schema()
    row = get_conn().execute(
        "SELECT id FROM securaiq_patch_campaigns WHERE id = ? AND user_id = ?", (campaign_id, user_id)
    ).fetchone()
    if not row:
        raise ValueError("Campaign not found")
    pending = get_conn().execute(
        "SELECT id, agent_id FROM securaiq_agent_commands WHERE campaign_id = ? AND user_id = ? AND status = 'pending_approval'",
        (campaign_id, user_id),
    ).fetchall()
    approved, failed = 0, 0
    for r in pending:
        try:
            approve_command(user_id, r["agent_id"], r["id"], approver_id=approver_id)
            approved += 1
        except ValueError:
            failed += 1
    audit("patch_campaign_approve", user_id, {"campaign_id": campaign_id, "approved": approved, "failed": failed})
    return {"id": campaign_id, "approved": approved, "failed": failed}


def reject_campaign(user_id: str, campaign_id: str, *, approver_id: str, reason: str = "") -> dict[str, Any]:
    """Reject every still-pending item in a campaign and mark the campaign
    itself canceled."""
    ensure_schema()
    row = get_conn().execute(
        "SELECT id FROM securaiq_patch_campaigns WHERE id = ? AND user_id = ?", (campaign_id, user_id)
    ).fetchone()
    if not row:
        raise ValueError("Campaign not found")
    pending = get_conn().execute(
        "SELECT id, agent_id FROM securaiq_agent_commands WHERE campaign_id = ? AND user_id = ? AND status = 'pending_approval'",
        (campaign_id, user_id),
    ).fetchall()
    rejected, failed = 0, 0
    for r in pending:
        try:
            reject_command(user_id, r["agent_id"], r["id"], approver_id=approver_id, reason=reason)
            rejected += 1
        except ValueError:
            failed += 1
    c = get_conn()
    c.execute("UPDATE securaiq_patch_campaigns SET status = 'canceled' WHERE id = ?", (campaign_id,))
    c.commit()
    audit("patch_campaign_reject", user_id, {"campaign_id": campaign_id, "rejected": rejected, "failed": failed, "reason": reason})
    return {"id": campaign_id, "rejected": rejected, "failed": failed}


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
    campaign_id = dict(row).get("campaign_id") or ""
    if campaign_id:
        try:
            _maybe_advance_campaign_ring(campaign_id, (agent or {}).get("user_id") or "local")
        except Exception:
            pass
    return {"ok": True, "status": status}
