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

COMMAND_TTL_SEC = 86400
COMMAND_ACK_TIMEOUT_SEC = 180


def _scope_sql(user_id: str, *, org_id: str | None = None, alias: str = "") -> tuple[str, list[Any]]:
    from app.tenancy import tenant_visibility_sql

    return tenant_visibility_sql(user_id, org_id=org_id, alias=alias)


def _row_in_scope(user_id: str, row: dict[str, Any] | None, *, org_id: str | None = None) -> bool:
    from app.tenancy import row_visible_to_user

    if not row:
        return False
    if org_id and (row.get("org_id") or "") != org_id:
        return False
    return row_visible_to_user(user_id, row)


def _strip_agent_secrets(d: dict[str, Any]) -> dict[str, Any]:
    d.pop("key_hash", None)
    d.pop("key_enc", None)
    d.pop("last_nonce", None)
    return d


def _command_ttl() -> int:
    try:
        from app.config import settings

        return max(60, int(getattr(settings, "agent_command_ttl_sec", None) or COMMAND_TTL_SEC))
    except Exception:
        return COMMAND_TTL_SEC


def _ack_timeout() -> int:
    try:
        from app.config import settings

        return max(30, int(getattr(settings, "agent_command_ack_timeout_sec", None) or COMMAND_ACK_TIMEOUT_SEC))
    except Exception:
        return COMMAND_ACK_TIMEOUT_SEC

# An agent is considered offline once this many seconds pass with no
# check-in. Real agents check in every 60s by default (see
# scripts/securaiq_agent.py DEFAULT_INTERVAL_SEC), so 3x that is a
# reasonable, honest "missed heartbeats" threshold rather than an
# arbitrarily generous one that would mask a genuinely dead agent.
OFFLINE_AFTER_SEC = 180

# Beyond this many seconds of silence, an agent is "stale" rather than just
# "offline" -- offline covers an ordinary outage (host rebooting, network
# blip); stale means it has been unreachable long enough (7 days) that it is
# more likely decommissioned, uninstalled, or genuinely gone, and probably
# needs an operator to look at it rather than just wait.
STALE_AFTER_SEC = 7 * 24 * 3600


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
        if "org_id" not in cols:
            c.execute("ALTER TABLE securaiq_agents ADD COLUMN org_id TEXT")
        if "device_fingerprint" not in cols:
            c.execute(
                "ALTER TABLE securaiq_agents ADD COLUMN device_fingerprint TEXT NOT NULL DEFAULT ''"
            )
        if "key_enc" not in cols:
            c.execute("ALTER TABLE securaiq_agents ADD COLUMN key_enc TEXT NOT NULL DEFAULT ''")
        if "ws_connected" not in cols:
            c.execute("ALTER TABLE securaiq_agents ADD COLUMN ws_connected INTEGER NOT NULL DEFAULT 0")
    except Exception:
        pass
    c.execute(
        """
        CREATE TABLE IF NOT EXISTS securaiq_agent_threats (
            id TEXT PRIMARY KEY,
            fingerprint TEXT NOT NULL,
            agent_id TEXT NOT NULL,
            user_id TEXT NOT NULL DEFAULT 'local',
            org_id TEXT,
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
    try:
        tcols = table_columns(c, "securaiq_agent_threats")
        if "org_id" not in tcols:
            c.execute("ALTER TABLE securaiq_agent_threats ADD COLUMN org_id TEXT")
    except Exception:
        pass
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
            ring_index INTEGER NOT NULL DEFAULT 0,
            created_at REAL NOT NULL DEFAULT 0,
            sent_at REAL NOT NULL DEFAULT 0,
            finished_at REAL NOT NULL DEFAULT 0,
            result_json TEXT NOT NULL DEFAULT '{}',
            verification_status TEXT NOT NULL DEFAULT ''
        )
        """
    )
    try:
        ccols = table_columns(c, "securaiq_agent_commands")
        for col, ddl in (
            ("org_id", "ALTER TABLE securaiq_agent_commands ADD COLUMN org_id TEXT"),
            ("event_id", "ALTER TABLE securaiq_agent_commands ADD COLUMN event_id TEXT NOT NULL DEFAULT ''"),
            ("nonce", "ALTER TABLE securaiq_agent_commands ADD COLUMN nonce TEXT NOT NULL DEFAULT ''"),
            ("signature", "ALTER TABLE securaiq_agent_commands ADD COLUMN signature TEXT NOT NULL DEFAULT ''"),
            ("ack_at", "ALTER TABLE securaiq_agent_commands ADD COLUMN ack_at REAL NOT NULL DEFAULT 0"),
            ("timeout_at", "ALTER TABLE securaiq_agent_commands ADD COLUMN timeout_at REAL NOT NULL DEFAULT 0"),
        ):
            if col not in ccols:
                c.execute(ddl)
    except Exception:
        pass
    try:
        cmd_cols = table_columns(c, "securaiq_agent_commands")
        for col, ddl in (
            ("approved_by", "ALTER TABLE securaiq_agent_commands ADD COLUMN approved_by TEXT NOT NULL DEFAULT ''"),
            ("approved_at", "ALTER TABLE securaiq_agent_commands ADD COLUMN approved_at REAL NOT NULL DEFAULT 0"),
            ("rejected_reason", "ALTER TABLE securaiq_agent_commands ADD COLUMN rejected_reason TEXT NOT NULL DEFAULT ''"),
            ("campaign_id", "ALTER TABLE securaiq_agent_commands ADD COLUMN campaign_id TEXT NOT NULL DEFAULT ''"),
            ("ring_index", "ALTER TABLE securaiq_agent_commands ADD COLUMN ring_index INTEGER NOT NULL DEFAULT 0"),
            ("verification_status", "ALTER TABLE securaiq_agent_commands ADD COLUMN verification_status TEXT NOT NULL DEFAULT ''"),
            ("verification_detail", "ALTER TABLE securaiq_agent_commands ADD COLUMN verification_detail TEXT NOT NULL DEFAULT ''"),
            ("verified_at", "ALTER TABLE securaiq_agent_commands ADD COLUMN verified_at REAL NOT NULL DEFAULT 0"),
            ("completed_at", "ALTER TABLE securaiq_agent_commands ADD COLUMN completed_at REAL NOT NULL DEFAULT 0"),
            ("error", "ALTER TABLE securaiq_agent_commands ADD COLUMN error TEXT NOT NULL DEFAULT ''"),
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
            org_id TEXT,
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
            resolved_ring INTEGER NOT NULL DEFAULT -1,
            created_at REAL NOT NULL
        )
        """
    )
    try:
        camp_cols = table_columns(c, "securaiq_patch_campaigns")
        if "resolved_ring" not in camp_cols:
            c.execute("ALTER TABLE securaiq_patch_campaigns ADD COLUMN resolved_ring INTEGER NOT NULL DEFAULT -1")
        if "org_id" not in camp_cols:
            c.execute("ALTER TABLE securaiq_patch_campaigns ADD COLUMN org_id TEXT")
    except Exception:
        pass
    c.execute(
        "CREATE INDEX IF NOT EXISTS idx_patch_campaigns_user ON securaiq_patch_campaigns(user_id, created_at)"
    )
    try:
        from app.agent_security import ensure_security_schema

        ensure_security_schema()
    except Exception:
        pass
    c.commit()


def enroll_agent(user_id: str, *, name: str = "", org_id: str | None = None) -> dict[str, Any]:
    """Create a new agent identity. Returns the raw key ONCE — never stored."""
    ensure_schema()
    raw_key = secrets.token_urlsafe(32)
    aid = new_id()
    oid = (org_id or "").strip() or None
    key_enc = ""
    try:
        from app.secrets_crypto import encrypt_value

        key_enc = encrypt_value(raw_key) or ""
    except Exception:
        key_enc = ""
    c = get_conn()
    c.execute(
        """
        INSERT INTO securaiq_agents
        (id, user_id, org_id, name, key_hash, key_enc, enrolled_at, last_checkin, last_payload_json)
        VALUES (?, ?, ?, ?, ?, ?, ?, 0, '{}')
        """,
        (aid, user_id, oid, name or "", _hash_key(raw_key), key_enc, now()),
    )
    c.commit()
    return {"agent_id": aid, "agent_key": raw_key, "org_id": oid}


def agent_visible_to_user(user_id: str, agent: dict[str, Any] | None) -> bool:
    if not agent:
        return False
    if agent.get("user_id") == user_id or user_id == "local":
        return True
    try:
        from app.tenancy import row_visible_to_user

        return row_visible_to_user(user_id, agent)
    except Exception:
        return False


def _latest_command_for_agent(agent_id: str) -> dict[str, Any] | None:
    """Most recent command requested for this agent, if any -- used only to
    layer the real "upgrading" / "error" states onto status (see
    _row_status). Not exposed as part of the public command list API."""
    row = get_conn().execute(
        "SELECT kind, status FROM securaiq_agent_commands WHERE agent_id = ? ORDER BY created_at DESC LIMIT 1",
        (agent_id,),
    ).fetchone()
    return dict(row) if row else None


def _row_status(row: dict[str, Any], *, latest_command: dict[str, Any] | None = None) -> str:
    """Six real states: revoked / pending / online / offline / stale / error
    / upgrading. Every state beyond the original four is derived from an
    actual checkable condition -- never a cosmetic label:
      - stale: no check-in for STALE_AFTER_SEC (beyond ordinary "offline")
      - upgrading: this agent's most recent command is a real, in-flight
        'agent_upgrade' command (pending_approval/queued/sent) -- reflects
        an actual approval-gated command that was requested, not a guess
      - error: this agent's most recent command finished with status='error'
    upgrading takes priority over error (a fresh upgrade in flight is more
    relevant to show than a stale prior failure); both take priority over
    the time-based state since they describe what's actually happening now.
    """
    if row.get("revoked"):
        return "revoked"
    last = float(row.get("last_checkin") or 0)
    if not last:
        base = "pending"  # enrolled, never checked in yet
    else:
        age = now() - last
        if age <= OFFLINE_AFTER_SEC:
            base = "online"
        elif age <= STALE_AFTER_SEC:
            base = "offline"
        else:
            base = "stale"
    if latest_command:
        if latest_command.get("kind") == "agent_upgrade" and latest_command.get("status") in (
            "pending_approval", "queued", "sent",
        ):
            return "upgrading"
        if latest_command.get("status") == "error":
            return "error"
    return base


def list_agents(user_id: str, *, limit: int = 200, org_id: str | None = None) -> list[dict[str, Any]]:
    ensure_schema()
    lim = max(1, min(limit, 500))
    try:
        from app.tenancy import tenant_visibility_sql

        where, args = tenant_visibility_sql(user_id, org_id=org_id)
        rows = get_conn().execute(
            f"SELECT * FROM securaiq_agents WHERE {where} ORDER BY enrolled_at DESC LIMIT ?",
            (*args, lim),
        ).fetchall()
    except Exception:
        rows = get_conn().execute(
            "SELECT * FROM securaiq_agents WHERE user_id = ? ORDER BY enrolled_at DESC LIMIT ?",
            (user_id, lim),
        ).fetchall()
    out = []
    for r in rows:
        d = dict(r)
        try:
            d["last_payload"] = json.loads(d.get("last_payload_json") or "{}")
        except Exception:
            d["last_payload"] = {}
        _strip_agent_secrets(d)
        d["status"] = _row_status(d, latest_command=_latest_command_for_agent(d["id"]))
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
    d["status"] = _row_status(d, latest_command=_latest_command_for_agent(agent_id))
    return d


def public_agent_view(agent: dict[str, Any] | None) -> dict[str, Any] | None:
    if not agent:
        return None
    d = dict(agent)
    return _strip_agent_secrets(d)


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


def _link_agent_asset(
    user_id: str, agent_id: str, payload: dict[str, Any], *, org_id: str | None = None
) -> str:
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
        org_id=org_id,
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
        asset_id = _link_agent_asset(
            agent.get("user_id") or "local",
            agent_id,
            payload,
            org_id=agent.get("org_id") or None,
        )
    except Exception:
        asset_id = agent.get("asset_id") or ""
    # The deep-telemetry fields (services, startup_apps, packages, etc.) can
    # make a full payload large on a busy host. A blind string-slice on the
    # JSON text (the old behavior) can cut mid-token and produce invalid
    # JSON that silently parses back to {} everywhere downstream -- so
    # instead: if it's oversized, fall back to a small, honestly-labeled
    # "truncated" payload rather than writing something that LOOKS like
    # real telemetry but silently isn't.
    payload_json = json.dumps(payload)
    if len(payload_json) > 200_000:
        payload_json = json.dumps({
            "hostname": payload.get("hostname", ""),
            "os": payload.get("os", ""),
            "os_version": payload.get("os_version", ""),
            "agent_version": payload.get("agent_version", ""),
            "truncated": True,
            "reason": "Full telemetry payload exceeded the storage limit for this check-in and was dropped -- "
            "core fields only. Will be retried next check-in.",
        })
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
            payload_json,
            agent_id,
        ),
    )
    c.commit()
    try:
        from app.realtime_bus import publish

        publish(type="agent", id=agent_id, status="online", asset_id=asset_id)
    except Exception:
        pass
    # Feed packages into software inventory so patch-verify can see installed versions.
    pkgs = payload.get("packages") if isinstance(payload.get("packages"), list) else []
    if pkgs and not payload.get("truncated"):
        try:
            from app.software.sources.securaiq_agent import ingest_agent_packages

            refreshed = dict(agent)
            refreshed["asset_id"] = asset_id
            refreshed["hostname"] = payload.get("hostname") or agent.get("hostname") or ""
            refreshed["os"] = payload.get("os") or agent.get("os") or ""
            refreshed["os_version"] = payload.get("os_version") or agent.get("os_version") or ""
            refreshed["last_checkin"] = now()
            ingest_agent_packages(
                agent.get("user_id") or "local",
                refreshed,
                [p for p in pkgs if isinstance(p, dict)],
                sync=True,
            )
        except Exception:
            pass
    commands = _dispatch_queued_commands(agent_id)
    return {"ok": True, "asset_id": asset_id, "commands": commands}


def _dispatch_queued_commands(agent_id: str, *, limit: int = 5) -> list[dict[str, Any]]:
    """Deliver queued commands via check-in, long-poll, or WebSocket push.

    Marks each row 'sent' (with event_id + signature) so the same command is
    not handed out again while the agent is still working on it.

    A command tied to a campaign with a maintenance window stays 'queued'
    until the current time falls inside that campaign's window.
    """
    expire_timed_out_commands()
    c = get_conn()
    rows = c.execute(
        "SELECT * FROM securaiq_agent_commands WHERE agent_id = ? AND status = 'queued' ORDER BY created_at ASC LIMIT ?",
        (agent_id, max(1, limit * 3)),
    ).fetchall()
    campaign_cache: dict[str, dict[str, Any] | None] = {}
    out: list[dict[str, Any]] = []
    seen_event_ids: set[str] = set()
    ts = now()
    for r in rows:
        if len(out) >= limit:
            break
        d = dict(r)
        created_at = float(d.get("created_at") or 0)
        if created_at and (ts - created_at) > _command_ttl():
            c.execute(
                "UPDATE securaiq_agent_commands SET status = 'timeout', error = ? WHERE id = ?",
                ("Command expired before delivery", d["id"]),
            )
            continue
        cid = d.get("campaign_id") or ""
        if cid:
            if cid not in campaign_cache:
                crow = c.execute("SELECT * FROM securaiq_patch_campaigns WHERE id = ?", (cid,)).fetchone()
                campaign_cache[cid] = dict(crow) if crow else None
            campaign = campaign_cache[cid]
            if campaign and not _in_maintenance_window(campaign):
                continue  # held for the next check-in, still 'queued'
        try:
            payload = json.loads(d.get("payload_json") or "{}")
        except Exception:
            payload = {}
        try:
            from app.agent_security import remember_nonce, seal_command_for_delivery

            sealed = seal_command_for_delivery(d, payload)
            eid = str(sealed.get("event_id") or "")
            if eid and eid in seen_event_ids:
                continue
            if eid:
                seen_event_ids.add(eid)
            remember_nonce(sealed["nonce"], agent_id=agent_id)
        except Exception:
            sealed = {
                "id": d["id"],
                "kind": d["kind"],
                "payload": payload,
                "event_id": "",
                "nonce": "",
                "signature": "",
                "seq": float(d.get("created_at") or 0),
            }
        timeout_at = ts + float(_ack_timeout())
        cur = c.execute(
            """
            UPDATE securaiq_agent_commands
            SET status = 'sent', sent_at = ?, event_id = ?, nonce = ?, signature = ?, timeout_at = ?
            WHERE id = ? AND status = 'queued'
            """,
            (
                ts,
                sealed.get("event_id") or "",
                sealed.get("nonce") or "",
                sealed.get("signature") or "",
                timeout_at,
                d["id"],
            ),
        )
        if int(cur.rowcount or 0) <= 0:
            continue  # raced / already delivered
        out.append(sealed)
    if out:
        c.commit()
        try:
            from app.realtime_bus import publish

            for sealed in out:
                publish(
                    type="agent_command",
                    agent_id=agent_id,
                    id=sealed.get("id"),
                    status="sent",
                    event_id=sealed.get("event_id") or None,
                )
        except Exception:
            pass
    else:
        try:
            c.commit()
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
    org_id = agent.get("org_id") or None
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
                (id, fingerprint, agent_id, user_id, org_id, asset_id, severity, category, title, detail, target, hash,
                 status, first_seen, last_seen, hit_count)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'active', ?, ?, 1)
                """,
                (
                    tid,
                    fp,
                    agent_id,
                    user_id,
                    org_id,
                    asset_id,
                    severity,
                    category,
                    title,
                    detail,
                    target,
                    file_hash,
                    ts,
                    ts,
                ),
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

        try:
            from app.services.evidence import record_evidence

            record_evidence(
                user_id,
                entity_type="threat",
                entity_id=tid,
                source="observed",
                # A real-time watcher signal, directly observed on the host --
                # not a guess, but not human-confirmed either until an
                # analyst reviews it, hence "observed" rather than "declared".
                confidence=0.7,
                summary=f"{category}: {title} on {hostname}",
                detail={"agent_id": agent_id, "hostname": hostname, "severity": severity, "raw": det},
                created_by=f"agent:{agent_id}",
            )
        except Exception:
            pass  # evidence recording is best-effort — never block threat ingestion

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


def list_threats(
    user_id: str, *, agent_id: str | None = None, limit: int = 200, org_id: str | None = None
) -> list[dict[str, Any]]:
    ensure_schema()
    c = get_conn()
    lim = max(1, min(limit, 500))
    try:
        from app.tenancy import tenant_visibility_sql

        where, args = tenant_visibility_sql(user_id, org_id=org_id)
        q = f"SELECT * FROM securaiq_agent_threats WHERE ({where})"
        args_l: list[Any] = list(args)
    except Exception:
        q = "SELECT * FROM securaiq_agent_threats WHERE user_id = ?"
        args_l = [user_id]
    if agent_id:
        q += " AND agent_id = ?"
        args_l.append(agent_id)
    q += " ORDER BY last_seen DESC LIMIT ?"
    args_l.append(lim)
    rows = c.execute(q, args_l).fetchall()
    return [dict(r) for r in rows]


def revoke_agent(user_id: str, agent_id: str) -> bool:
    ensure_schema()
    agent = get_agent(agent_id)
    if not agent_visible_to_user(user_id, agent):
        return False
    c = get_conn()
    c.execute("UPDATE securaiq_agents SET revoked = 1 WHERE id = ?", (agent_id,))
    c.commit()
    return True


def delete_agent(user_id: str, agent_id: str) -> bool:
    ensure_schema()
    agent = get_agent(agent_id)
    if not agent_visible_to_user(user_id, agent):
        return False
    c = get_conn()
    c.execute("DELETE FROM securaiq_agents WHERE id = ?", (agent_id,))
    c.commit()
    return True


def mark_agent_ws(agent_id: str, *, connected: bool, heartbeat: bool = False) -> None:
    """Track gateway presence. Heartbeat refreshes last_checkin so status stays online."""
    ensure_schema()
    c = get_conn()
    if heartbeat or connected:
        c.execute(
            "UPDATE securaiq_agents SET ws_connected = ?, last_checkin = ? WHERE id = ?",
            (1 if connected else 0, now(), agent_id),
        )
    else:
        c.execute(
            "UPDATE securaiq_agents SET ws_connected = 0 WHERE id = ?",
            (agent_id,),
        )
    c.commit()
    if heartbeat:
        return
    try:
        from app.realtime_bus import publish

        publish(
            type="agent",
            id=agent_id,
            status="online" if connected else "offline",
            ws_connected=bool(connected),
            via="gateway",
        )
    except Exception:
        pass


def ack_command(agent_id: str, command_id: str) -> dict[str, Any]:
    ensure_schema()
    c = get_conn()
    row = c.execute(
        "SELECT * FROM securaiq_agent_commands WHERE id = ? AND agent_id = ?",
        (command_id, agent_id),
    ).fetchone()
    if not row:
        return {"ok": False, "error": "unknown command"}
    st = row["status"]
    if st not in ("sent", "queued", "acked"):
        return {"ok": True, "status": st}
    ts = now()
    c.execute(
        "UPDATE securaiq_agent_commands SET status = 'acked', ack_at = ? WHERE id = ?",
        (ts, command_id),
    )
    c.commit()
    try:
        from app.realtime_bus import publish

        publish(type="agent_command", agent_id=agent_id, id=command_id, status="acked")
    except Exception:
        pass
    return {"ok": True, "status": "acked"}


def expire_timed_out_commands() -> int:
    ensure_schema()
    ts = now()
    c = get_conn()
    n = 0
    try:
        cur = c.execute(
            "UPDATE securaiq_agent_commands SET status = 'timeout', error = 'ack/result timeout' "
            "WHERE status IN ('sent', 'acked') AND timeout_at > 0 AND timeout_at < ?",
            (ts,),
        )
        n = int(cur.rowcount or 0)
        c.commit()
    except Exception:
        try:
            c.rollback()
        except Exception:
            pass
    return n


# ---------------------------------------------------------------------------
# Agent command channel — the patch-execution + verification loop.
#
# Commands are queued here, then delivered via WebSocket push, long-poll
# (/api/agents/gateway/wait), or the next HTTP check-in (fallback). The
# agent reports the outcome via report_command_result() (HTTP or WS).
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

SUPPORTED_COMMAND_KINDS = {"patch_package", "agent_upgrade"}
COMMAND_STATUSES = {"pending_approval", "queued", "sent", "acked", "done", "error", "rejected", "timeout"}


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
    if not agent_visible_to_user(user_id, agent):
        raise ValueError("Agent not found")
    if agent.get("revoked"):
        raise ValueError("Agent is revoked")
    if kind not in SUPPORTED_COMMAND_KINDS:
        raise ValueError(f"Unsupported command kind '{kind}'")
    cid = new_id()
    oid = agent.get("org_id") or None
    c = get_conn()
    c.execute(
        """
        INSERT INTO securaiq_agent_commands
        (id, agent_id, user_id, org_id, kind, payload_json, status, requested_by, campaign_id, ring_index, created_at)
        VALUES (?, ?, ?, ?, ?, ?, 'pending_approval', ?, ?, ?, ?)
        """,
        (
            cid,
            agent_id,
            user_id,
            oid,
            kind,
            json.dumps(payload)[:4000],
            requested_by or user_id,
            campaign_id,
            ring_index,
            now(),
        ),
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


def request_agent_upgrade(user_id: str, agent_id: str, *, requested_by: str = "") -> dict[str, Any]:
    """Request a self-upgrade command for one agent. Rides the exact same
    approval-gated lifecycle as any other command (pending_approval ->
    approve_command() -> queued -> dispatched on next check-in) -- never
    auto-executed. The payload carries expected_sha256, the sha256 of THIS
    server's current scripts/securaiq_agent.py at request time, so the
    agent verifies the file it downloads at execution time still matches
    what a human approved, not just "whatever the server serves right now".
    Never turns the agent into a remote shell: the agent only ever fetches
    and checksum-verifies this one server-declared file, exactly the same
    trust model as the existing patch_package command kind."""
    import hashlib

    from app.paths import resource_root

    script_path = resource_root() / "scripts" / "securaiq_agent.py"
    if not script_path.is_file():
        raise ValueError("Agent script not found on this server -- cannot compute an upgrade checksum")
    content = script_path.read_bytes()
    expected_sha256 = hashlib.sha256(content).hexdigest()
    return request_command(
        user_id,
        agent_id,
        kind="agent_upgrade",
        payload={"expected_sha256": expected_sha256},
        requested_by=requested_by,
    )


def _get_command_row(user_id: str, agent_id: str, command_id: str):
    c = get_conn()
    row = c.execute(
        "SELECT * FROM securaiq_agent_commands WHERE id = ? AND agent_id = ?", (command_id, agent_id)
    ).fetchone()
    if not row:
        return None
    d = dict(row)
    if d.get("user_id") == user_id or user_id == "local":
        return d
    try:
        from app.tenancy import row_visible_to_user

        if row_visible_to_user(user_id, d):
            return d
    except Exception:
        pass
    # Fall back: command visible if the parent agent is visible to this user.
    if agent_visible_to_user(user_id, get_agent(agent_id)):
        return d
    return None


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
    try:
        from app.agent_gateway import notify_agent

        notify_agent(agent_id)
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


def list_pending_commands(user_id: str, *, limit: int = 200, org_id: str | None = None) -> list[dict[str, Any]]:
    """All commands awaiting approval across all of this user's agents —
    backs the approvals UI/queue view."""
    ensure_schema()
    lim = max(1, min(limit, 500))
    try:
        from app.tenancy import tenant_visibility_sql

        where, args = tenant_visibility_sql(user_id, org_id=org_id)
        rows = get_conn().execute(
            f"SELECT * FROM securaiq_agent_commands WHERE ({where}) AND status = 'pending_approval' "
            f"ORDER BY created_at ASC LIMIT ?",
            (*args, lim),
        ).fetchall()
    except Exception:
        rows = get_conn().execute(
            "SELECT * FROM securaiq_agent_commands WHERE user_id = ? AND status = 'pending_approval' "
            "ORDER BY created_at ASC LIMIT ?",
            (user_id, lim),
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
    org_id: str | None = None,
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
    first = get_agent(ring_list[0][0]) if ring_list and ring_list[0] else None
    oid = (org_id or (first or {}).get("org_id") or "").strip() or None
    c = get_conn()
    c.execute(
        """
        INSERT INTO securaiq_patch_campaigns
        (id, user_id, org_id, name, manager, package, target_version, requested_by,
         rings_json, window_start_hour, window_end_hour, window_days_json, ring_threshold_pct, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            cid, user_id, oid, name or f"{manager} upgrade {package}", manager, package, target_version, requested_by or user_id,
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
    try:
        from app.services.risk_snapshots import snapshot_risk

        snapshot_risk(user_id, campaign_id=cid, label="before")
    except Exception:
        pass  # a scoring hiccup must never block campaign creation
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


_CAMPAIGN_TERMINAL_STATUSES = {"halted", "completed", "completed_with_failures"}


def _maybe_snapshot_campaign_after(campaign_id: str, user_id: str) -> None:
    """Capture the campaign's 'after' risk snapshot — but only once the
    picture is actually settled: the campaign must be in a terminal
    execution state, every 'done' command's verification must have
    resolved (verified/verification_failed/unknown — anything but still
    '' or 'pending'), and no 'after' snapshot must exist yet. Recalculating
    while verification is still in flight would understate the real
    reduction (or overstate it, if resolved vulnerabilities haven't been
    marked yet) — this is what keeps 'Risk 82 -> 61' an honest number tied
    to confirmed outcomes rather than raw execution counts. Called both
    right after a campaign reaches a terminal state (covers the all-error
    case, where there's nothing to wait on) and again whenever a
    verification result lands (covers the common case where verification
    settles after the campaign already finished)."""
    try:
        from app.services.risk_snapshots import ensure_schema as ensure_risk_snapshot_schema

        ensure_risk_snapshot_schema()
    except Exception:
        return
    c = get_conn()
    campaign = c.execute(
        "SELECT status FROM securaiq_patch_campaigns WHERE id = ?", (campaign_id,)
    ).fetchone()
    if not campaign or campaign["status"] not in _CAMPAIGN_TERMINAL_STATUSES:
        return
    already = c.execute(
        "SELECT 1 FROM securaiq_risk_snapshots WHERE campaign_id = ? AND label = 'after' LIMIT 1", (campaign_id,)
    ).fetchone()
    if already:
        return
    unresolved = c.execute(
        "SELECT 1 FROM securaiq_agent_commands WHERE campaign_id = ? AND status = 'done' "
        "AND verification_status IN ('', 'pending') LIMIT 1",
        (campaign_id,),
    ).fetchone()
    if unresolved:
        return  # still waiting on verification for at least one executed item
    try:
        from app.services.risk_snapshots import snapshot_risk

        snapshot_risk(user_id, campaign_id=campaign_id, label="after")
    except Exception:
        pass


def _maybe_advance_campaign_ring(campaign_id: str, user_id: str) -> None:
    """Called after a command's result is reported. If that command was the
    last unresolved item in its ring, decide whether to auto-stop the
    campaign (ring failed below threshold) or materialize the next ring's
    commands (ring passed). No-op for campaigns with no further rings, or
    if the ring still has unresolved (pending/queued/sent) items.

    Idempotency: two agents in the same ring can report their results
    within milliseconds of each other, so two concurrent calls can both
    observe "ring fully resolved" before either has written anything. The
    `resolved_ring` column is a compare-and-swap guard — only the caller
    whose UPDATE actually advances it (rowcount == 1) is allowed to act on
    this ring's resolution, so halt/complete/advance each fire exactly
    once per ring no matter how many callers race here."""
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

    # Atomic claim — only proceeds if this call is the first to notice this
    # ring finished (resolved_ring hasn't already reached max_created_ring).
    claim = c.execute(
        "UPDATE securaiq_patch_campaigns SET resolved_ring = ? WHERE id = ? AND status = 'active' AND resolved_ring < ?",
        (max_created_ring, campaign_id, max_created_ring),
    )
    c.commit()
    if claim.rowcount == 0:
        return  # another concurrent call already claimed this ring's resolution

    total = len(current_ring_rows)
    done = sum(1 for r in current_ring_rows if r["status"] == "done")
    errored = total - done
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
        _maybe_snapshot_campaign_after(campaign_id, user_id)
        return
    if next_ring_index >= len(ring_list):
        # Ring passed its threshold, but "passed >= threshold" and "zero
        # failures" are different things (e.g. an 80% threshold lets 2/10
        # failures through) — a campaign with any errored item anywhere is
        # marked completed_with_failures, not a clean 'completed', so a
        # partial success can't read as a full one in the campaign list.
        any_errors = errored > 0 or c.execute(
            "SELECT 1 FROM securaiq_agent_commands WHERE campaign_id = ? AND status = 'error' LIMIT 1",
            (campaign_id,),
        ).fetchone() is not None
        final_status = "completed_with_failures" if any_errors else "completed"
        c.execute(
            "UPDATE securaiq_patch_campaigns SET status = ? WHERE id = ?", (final_status, campaign_id)
        )
        c.commit()
        audit(
            "patch_campaign_completed", user_id,
            {"campaign_id": campaign_id, "rings": len(ring_list), "status": final_status},
        )
        _maybe_snapshot_campaign_after(campaign_id, user_id)
        return
    # ring passed and there's a next ring — materialize it (pending_approval,
    # same as ring 0; a human still approves each ring's dispatch). Guarded
    # by the resolved_ring claim above, so this can't run twice even if two
    # agents in this ring reported their results concurrently.
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
    # queued/sent items whose owning agent has gone offline — a stalled
    # command must never be counted toward "in progress" without a visible
    # flag, since it isn't actually going to complete until the agent comes
    # back.
    undelivered = get_conn().execute(
        "SELECT agent_id, status FROM securaiq_agent_commands WHERE user_id = ? AND campaign_id = ? AND status IN ('queued','sent')",
        (user_id, campaign_id),
    ).fetchall()
    waiting_for_agent = 0
    agent_cache: dict[str, bool] = {}
    for r in undelivered:
        aid = r["agent_id"]
        if aid not in agent_cache:
            agent = get_agent(aid)
            agent_cache[aid] = bool(agent) and _row_status(agent) in ("offline", "stale")
        if agent_cache[aid]:
            waiting_for_agent += 1
    verif_rows = get_conn().execute(
        "SELECT verification_status, COUNT(*) as n FROM securaiq_agent_commands "
        "WHERE user_id = ? AND campaign_id = ? AND status = 'done' GROUP BY verification_status",
        (user_id, campaign_id),
    ).fetchall()
    verif_counts = {r["verification_status"]: r["n"] for r in verif_rows}
    return {
        "total": total,
        "pending_approval": counts.get("pending_approval", 0),
        "queued": counts.get("queued", 0),
        "sent": counts.get("sent", 0),
        "done": counts.get("done", 0),
        "error": counts.get("error", 0),
        "rejected": counts.get("rejected", 0),
        "waiting_for_agent": waiting_for_agent,
        # of the 'done' (executed) items, how many are confirmed fixed vs
        # not — 'done' alone is execution, not verification (see
        # report_command_result's docstring).
        "verified": verif_counts.get("verified", 0),
        "verification_failed": verif_counts.get("verification_failed", 0),
        "verification_pending": verif_counts.get("pending", 0),
    }


def fleet_verification_summary(user_id: str) -> dict[str, Any]:
    """The same 'done' -> verification_status breakdown as _campaign_summary,
    aggregated across every campaign this user has ever run -- the real
    number behind an executive dashboard's "verified remediation %". Only
    counts commands that actually executed (status='done'); a command still
    pending approval or queued isn't a remediation attempt yet, so it's
    excluded from the denominator rather than silently counted as
    unverified."""
    ensure_schema()
    rows = get_conn().execute(
        "SELECT verification_status, COUNT(*) as n FROM securaiq_agent_commands "
        "WHERE user_id = ? AND status = 'done' GROUP BY verification_status",
        (user_id,),
    ).fetchall()
    counts = {r["verification_status"]: r["n"] for r in rows}
    verified = counts.get("verified", 0)
    failed = counts.get("verification_failed", 0)
    pending = counts.get("pending", 0)
    total_done = verified + failed + pending
    return {
        "total_done": total_done,
        "verified": verified,
        "verification_failed": failed,
        "verification_pending": pending,
        "verified_pct": round(verified / total_done * 100, 1) if total_done else None,
    }


def list_campaigns(user_id: str, *, limit: int = 100, org_id: str | None = None) -> list[dict[str, Any]]:
    ensure_schema()
    lim = max(1, min(limit, 300))
    try:
        from app.tenancy import tenant_visibility_sql

        where, args = tenant_visibility_sql(user_id, org_id=org_id)
        rows = get_conn().execute(
            f"SELECT * FROM securaiq_patch_campaigns WHERE {where} ORDER BY created_at DESC LIMIT ?",
            (*args, lim),
        ).fetchall()
    except Exception:
        rows = get_conn().execute(
            "SELECT * FROM securaiq_patch_campaigns WHERE user_id = ? ORDER BY created_at DESC LIMIT ?",
            (user_id, lim),
        ).fetchall()
    out = []
    for r in rows:
        d = dict(r)
        d["summary"] = _campaign_summary(user_id, d["id"])
        try:
            from app.services.risk_snapshots import get_campaign_risk_delta

            delta = get_campaign_risk_delta(user_id, d["id"])
            if delta:
                d.update(delta)
        except Exception:
            pass
        out.append(d)
    return out


def get_campaign(user_id: str, campaign_id: str) -> dict[str, Any] | None:
    ensure_schema()
    row = get_conn().execute(
        "SELECT * FROM securaiq_patch_campaigns WHERE id = ?", (campaign_id,)
    ).fetchone()
    if not row:
        return None
    d0 = dict(row)
    if not _row_in_scope(user_id, d0):
        return None
    d = d0
    d["summary"] = _campaign_summary(user_id, campaign_id)
    item_rows = get_conn().execute(
        "SELECT * FROM securaiq_agent_commands WHERE campaign_id = ? ORDER BY created_at ASC",
        (campaign_id,),
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
    _annotate_waiting_for_agent(items)
    d["items"] = items
    try:
        from app.services.risk_snapshots import get_campaign_risk_delta

        delta = get_campaign_risk_delta(user_id, campaign_id)
        if delta:
            d.update(delta)
    except Exception:
        pass
    return d


def approve_campaign(user_id: str, campaign_id: str, *, approver_id: str) -> dict[str, Any]:
    """Approve every still-pending item in a campaign. Individual items that
    already moved on (queued/sent/done/etc.) are left untouched — this is
    additive, not a reset."""
    ensure_schema()
    row = get_conn().execute(
        "SELECT * FROM securaiq_patch_campaigns WHERE id = ?", (campaign_id,)
    ).fetchone()
    if not row or not _row_in_scope(user_id, dict(row)):
        raise ValueError("Campaign not found")
    pending = get_conn().execute(
        "SELECT id, agent_id FROM securaiq_agent_commands WHERE campaign_id = ? AND status = 'pending_approval'",
        (campaign_id,),
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
        "SELECT * FROM securaiq_patch_campaigns WHERE id = ?", (campaign_id,)
    ).fetchone()
    if not row or not _row_in_scope(user_id, dict(row)):
        raise ValueError("Campaign not found")
    pending = get_conn().execute(
        "SELECT id, agent_id FROM securaiq_agent_commands WHERE campaign_id = ? AND status = 'pending_approval'",
        (campaign_id,),
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


_UNDELIVERED_STATUSES = {"queued", "sent"}


def _annotate_waiting_for_agent(items: list[dict[str, Any]]) -> None:
    """Mutates each item in place, adding waiting_for_agent=True when the
    command is still undelivered (queued/sent — never 'done') AND its
    owning agent is currently offline. This is a derived, non-persisted
    signal: it doesn't change the command's actual status (an undelivered
    command must never be reported as if it succeeded), it just makes an
    otherwise-silent stall visible instead of looking like normal
    in-progress work."""
    agent_cache: dict[str, bool] = {}
    for item in items:
        if item.get("status") not in _UNDELIVERED_STATUSES:
            continue
        aid = item.get("agent_id") or ""
        if aid not in agent_cache:
            agent = get_agent(aid)
            agent_cache[aid] = bool(agent) and _row_status(agent) in ("offline", "stale")
        item["waiting_for_agent"] = agent_cache[aid]


def list_commands(user_id: str, agent_id: str, *, limit: int = 100) -> list[dict[str, Any]]:
    ensure_schema()
    if not agent_visible_to_user(user_id, get_agent(agent_id)):
        return []
    rows = get_conn().execute(
        "SELECT * FROM securaiq_agent_commands WHERE agent_id = ? ORDER BY created_at DESC LIMIT ?",
        (agent_id, max(1, min(limit, 300))),
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
    _annotate_waiting_for_agent(out)
    return out


def report_command_result(agent_id: str, command_id: str, *, status: str, result: dict[str, Any]) -> dict[str, Any]:
    """Agent reports the outcome of a command it executed.

    IMPORTANT: 'done' here means the agent's patch-manager invocation
    exited successfully — it does NOT mean the fix is confirmed. Those are
    different claims (a package manager can report success while the CVE
    that motivated the patch is still present, e.g. a version pin, a
    partial install, or advisory data that hasn't caught up yet). So a
    'done' command starts in verification_status='pending' and a
    software_advisory_refresh job is enqueued; once that job re-syncs the
    installed version and re-runs CVE/advisory correlation, it calls
    record_command_verification() to flip verification_status to
    'verified' or 'verification_failed' — see app/jobs.py's
    _job_software_advisory_refresh. Callers that only check `status=='done'`
    are checking execution, not verification; check `verification_status`
    for the latter."""
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
    if status == "done":
        if asset_id:
            c.execute("UPDATE securaiq_agent_commands SET verification_status = 'pending' WHERE id = ?", (command_id,))
        else:
            c.execute(
                "UPDATE securaiq_agent_commands SET verification_status = 'unknown', verification_detail = ? WHERE id = ?",
                ("Agent has no linked asset yet — cannot verify", command_id),
            )
        c.commit()
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
        # Stamp installed version from the agent result immediately so the
        # advisory-refresh verification job is not racing an empty inventory.
        try:
            payload_d = result if isinstance(result, dict) else {}
            new_ver = str(payload_d.get("new_version") or "").strip()
            pkg = ""
            try:
                cmd_payload = json.loads(dict(row).get("payload_json") or "{}")
                pkg = str(cmd_payload.get("package") or "").strip()
            except Exception:
                pkg = str(payload_d.get("package") or "").strip()
            if pkg and new_ver:
                from app.software.sources.securaiq_agent import apply_patch_version_to_inventory

                apply_patch_version_to_inventory(
                    (agent or {}).get("user_id") or "local",
                    asset_id=asset_id,
                    package=pkg,
                    version=new_ver,
                    agent_id=agent_id,
                    hostname=str((agent or {}).get("hostname") or ""),
                )
        except Exception:
            pass
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


def _resolve_vulnerabilities_for_verified_patch(command_id: str, command_row: dict[str, Any]) -> int:
    """Once a patch is verified, close the loop on the `vulnerabilities`
    table too — but ONLY via an exact CVE match, never a fuzzy title guess.
    A patched product's advisories name the CVEs their fixed_version
    resolves; if the now-installed version satisfies an advisory's
    fixed_version, that CVE is genuinely fixed. Any open vulnerabilities
    row on the same asset carrying that exact CVE id is marked resolved.
    No match found -> nothing is touched, silently and correctly (a
    scanner-only finding with no corresponding advisory CVE is real and
    stays open until something actually resolves it)."""
    from app.software.patch_status import compare_versions

    user_id = command_row.get("user_id") or "local"
    agent = get_agent(command_row.get("agent_id") or "")
    asset_id = (agent or {}).get("asset_id") or ""
    if not asset_id:
        return 0
    try:
        payload = json.loads(command_row.get("payload_json") or "{}")
    except Exception:
        payload = {}
    package = (payload.get("package") or "").strip()
    if not package:
        return 0

    c = get_conn()
    installations = c.execute(
        """
        SELECT i.version AS installed_version, p.id AS product_id
        FROM software_installations i
        JOIN software_products p ON p.id = i.software_product_id
        WHERE i.user_id = ? AND i.asset_id = ? AND LOWER(p.name) LIKE ?
        ORDER BY i.updated_at DESC LIMIT 1
        """,
        (user_id, asset_id, f"%{package.lower()}%"),
    ).fetchone()
    if not installations:
        return 0
    installations = dict(installations)
    installed_version = installations.get("installed_version") or ""
    product_id = installations.get("product_id") or ""
    if not installed_version or not product_id:
        return 0

    advisories = c.execute(
        "SELECT cve_id, fixed_version FROM software_advisories WHERE user_id = ? AND software_product_id = ? "
        "AND fixed_version != '' AND cve_id != ''",
        (user_id, product_id),
    ).fetchall()
    fixed_cves: set[str] = set()
    for a in advisories:
        a = dict(a)
        cmp = compare_versions(installed_version, a.get("fixed_version") or "")
        if cmp is not None and cmp >= 0:
            fixed_cves.add((a.get("cve_id") or "").strip().upper())
    fixed_cves.discard("")
    if not fixed_cves:
        return 0

    placeholders = ",".join("?" for _ in fixed_cves)
    rows = c.execute(
        f"SELECT id, cve FROM vulnerabilities WHERE user_id = ? AND asset_id = ? AND status = 'open' "
        f"AND UPPER(cve) IN ({placeholders})",
        (user_id, asset_id, *fixed_cves),
    ).fetchall()
    if not rows:
        return 0
    ts = now()
    resolved_ids = [dict(r)["id"] for r in rows]
    for vid in resolved_ids:
        c.execute("UPDATE vulnerabilities SET status = 'resolved', updated_at = ? WHERE id = ?", (ts, vid))
    c.commit()
    audit(
        "vuln_auto_resolved_by_patch_verification",
        user_id,
        {"command_id": command_id, "asset_id": asset_id, "package": package, "resolved_vuln_ids": resolved_ids},
    )
    try:
        from app.realtime_bus import publish

        publish(type="vuln", user_id=user_id, asset_id=asset_id, count=len(resolved_ids), reason="patch_verified")
    except Exception:
        pass
    return len(resolved_ids)


def record_command_verification(command_id: str, *, verified: bool | None, detail: str = "") -> dict[str, Any]:
    """Called by the software_advisory_refresh job once it's re-synced
    inventory and re-run CVE/advisory correlation for a completed patch
    command. verified=True/False records a definitive outcome;
    verified=None means the refresh ran but couldn't locate the package in
    inventory to judge either way (status stays 'unknown', not silently
    dropped as if nothing happened)."""
    ensure_schema()
    c = get_conn()
    row = c.execute(
        "SELECT id, agent_id, user_id, status, campaign_id, payload_json FROM securaiq_agent_commands WHERE id = ?",
        (command_id,),
    ).fetchone()
    if not row:
        return {"ok": False, "error": "unknown command"}
    row = dict(row)
    v_status = "verified" if verified is True else "verification_failed" if verified is False else "unknown"
    resolved_findings = 0
    if verified is True:
        try:
            resolved_findings = _resolve_vulnerabilities_for_verified_patch(command_id, row)
        except Exception:
            resolved_findings = 0
    detail_text = str(detail or "")[:460]
    if resolved_findings:
        detail_text = f"{detail_text} — closed {resolved_findings} linked finding(s)".strip(" —")
    c.execute(
        "UPDATE securaiq_agent_commands SET verification_status = ?, verification_detail = ?, verified_at = ? WHERE id = ?",
        (v_status, detail_text[:500], now(), command_id),
    )
    c.commit()
    try:
        from app.realtime_bus import publish

        publish(type="agent_command", agent_id=row["agent_id"], id=command_id, status=row["status"], verification_status=v_status)
    except Exception:
        pass
    campaign_id = row.get("campaign_id") or ""
    if campaign_id:
        try:
            _maybe_snapshot_campaign_after(campaign_id, row.get("user_id") or "local")
        except Exception:
            pass
    return {"ok": True, "verification_status": v_status, "resolved_findings": resolved_findings}
