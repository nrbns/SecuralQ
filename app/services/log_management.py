"""Log management + SIEM: unified log ingestion, search, and simple
correlation-to-incident rules.

This does not reinvent what already exists — it connects it:

  * `xdr_events` (app/db.py) already unifies Wazuh SIEM alerts and every
    XDR/EDR vendor's detections in one table with vendor/severity/host/kind.
    That's real telemetry already flowing in whenever those connectors are
    configured and synced.
  * `audit_log` already captures every authenticated action SecuraIQ itself
    takes (app.db.audit()).
  * This module adds the piece that was missing: a real ingestion path for
    everything else (native agents' OS-level events, a syslog/HTTP forwarder,
    a manual API push) into a new `ingested_logs` table, plus one search
    endpoint that unions all three into a single time-ordered, source-labeled
    result set. Sources are never blended into one synthetic "log" identity —
    every row keeps its real source, vendor/kind, and original fields.

Correlation is intentionally narrow and literal: a small number of concrete,
auditable threshold rules (e.g. N auth failures for the same actor within a
window) that create a real incident via app.ops.create_incident when they
fire. No ML, no "AI detected an anomaly" framing -- if we can't show the exact
count and window that triggered it, we don't call it detection.
"""

from __future__ import annotations

import json
from typing import Any

from app.db import get_conn, new_id, now, row_to_dict

SEVERITIES = ("info", "low", "medium", "high", "critical")
LOG_SOURCES = ("agent", "syslog", "manual", "api")

# Event types that count as an authentication failure for the correlation
# rule below. Kept as an explicit allowlist rather than a substring match on
# free text, so the rule only fires on events that actually assert failure.
_AUTH_FAILURE_EVENT_TYPES = ("auth_failure", "login_failed", "ssh_auth_failure", "failed_login")
_AUTH_FAILURE_AUDIT_ACTIONS = ("login_failed", "login_failure", "mfa_failed")

# Threshold rule: this many auth failures for the same actor inside this many
# seconds creates one incident. Deliberately simple and named so the incident
# text can say exactly what fired it.
_AUTH_FAILURE_THRESHOLD = 5
_AUTH_FAILURE_WINDOW_SEC = 600


def ensure_log_schema() -> None:
    c = get_conn()
    c.executescript(
        """
        CREATE TABLE IF NOT EXISTS ingested_logs (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            source TEXT NOT NULL DEFAULT 'manual',
            source_id TEXT NOT NULL DEFAULT '',
            host TEXT NOT NULL DEFAULT '',
            actor TEXT NOT NULL DEFAULT '',
            severity TEXT NOT NULL DEFAULT 'info',
            event_type TEXT NOT NULL DEFAULT '',
            message TEXT NOT NULL DEFAULT '',
            raw_json TEXT NOT NULL DEFAULT '{}',
            received_at REAL NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_ingested_logs_user_time
            ON ingested_logs(user_id, received_at DESC);
        CREATE INDEX IF NOT EXISTS idx_ingested_logs_actor
            ON ingested_logs(user_id, actor, event_type, received_at DESC);
        """
    )
    c.commit()


def _clean_severity(sev: str) -> str:
    sev = (sev or "info").lower().strip()
    return sev if sev in SEVERITIES else "info"


def ingest_log(
    user_id: str,
    *,
    source: str = "manual",
    source_id: str = "",
    host: str = "",
    actor: str = "",
    severity: str = "info",
    event_type: str = "",
    message: str = "",
    raw: dict[str, Any] | None = None,
) -> dict[str, Any]:
    ensure_log_schema()
    lid = new_id()
    ts = now()
    src = source if source in LOG_SOURCES else "manual"
    c = get_conn()
    c.execute(
        """
        INSERT INTO ingested_logs
        (id, user_id, source, source_id, host, actor, severity, event_type, message, raw_json, received_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            lid,
            user_id,
            src,
            (source_id or "")[:120],
            (host or "")[:200],
            (actor or "")[:200],
            _clean_severity(severity),
            (event_type or "")[:80],
            (message or "")[:4000],
            json.dumps(raw or {}, default=str)[:8000],
            ts,
        ),
    )
    c.commit()
    return {
        "id": lid,
        "source": src,
        "received_at": ts,
    }


def ingest_logs_bulk(user_id: str, *, source: str, source_id: str, events: list[dict[str, Any]]) -> dict[str, Any]:
    """Batch entry point for agent/syslog pushes. Runs the correlation check
    once at the end (not per event) so a burst of N events in one batch is
    evaluated the same as N events arriving one at a time."""
    ids = []
    for ev in events[:500]:  # hard cap per batch -- ingestion, not a data dump endpoint
        r = ingest_log(
            user_id,
            source=source,
            source_id=source_id,
            host=ev.get("host", ""),
            actor=ev.get("actor", ""),
            severity=ev.get("severity", "info"),
            event_type=ev.get("event_type", ""),
            message=ev.get("message", ""),
            raw=ev.get("raw"),
        )
        ids.append(r["id"])
    incidents = run_auth_failure_correlation(user_id)
    return {"ingested": len(ids), "ids": ids, "incidents_created": incidents}


def run_auth_failure_correlation(user_id: str) -> list[dict[str, Any]]:
    """Real threshold correlation: >= _AUTH_FAILURE_THRESHOLD auth-failure
    events for the same actor within _AUTH_FAILURE_WINDOW_SEC seconds. Scans
    both ingested_logs and audit_log (SecuraIQ's own login failures) so an
    attacker hammering SecuraIQ's own login form is caught the same way as
    one hammering a monitored host. Idempotent: won't create a second
    incident for the same actor while an equivalent one is still open."""
    ensure_log_schema()
    c = get_conn()
    cutoff = now() - _AUTH_FAILURE_WINDOW_SEC

    rows = c.execute(
        """
        SELECT actor AS who, received_at AS ts FROM ingested_logs
        WHERE user_id = ? AND event_type IN ({}) AND received_at >= ? AND actor != ''
        """.format(",".join(["?"] * len(_AUTH_FAILURE_EVENT_TYPES))),
        (user_id, *_AUTH_FAILURE_EVENT_TYPES, cutoff),
    ).fetchall()
    audit_rows = c.execute(
        """
        SELECT user_id AS who, created_at AS ts FROM audit_log
        WHERE action IN ({}) AND created_at >= ?
        """.format(",".join(["?"] * len(_AUTH_FAILURE_AUDIT_ACTIONS))),
        (*_AUTH_FAILURE_AUDIT_ACTIONS, cutoff),
    ).fetchall()

    counts: dict[str, int] = {}
    for r in list(rows) + list(audit_rows):
        d = row_to_dict(r) or {}
        who = str(d.get("who") or "").strip()
        if who:
            counts[who] = counts.get(who, 0) + 1

    created: list[dict[str, Any]] = []
    for who, n in counts.items():
        if n < _AUTH_FAILURE_THRESHOLD:
            continue
        # `who` is a real user_id (uuid hex) for a known account, or the
        # synthetic "unknown:<username>" tag app.auth records for an
        # attempted login against a username that doesn't exist. Resolve the
        # former to a real username for a readable incident title; leave the
        # latter as-is since there's no account to look up.
        label = who
        if not who.startswith("unknown:"):
            urow = c.execute("SELECT username FROM users WHERE id = ?", (who,)).fetchone()
            if urow and urow["username"]:
                label = urow["username"]
        title = f"Repeated authentication failures: {label}"
        existing = c.execute(
            """
            SELECT id FROM incidents
            WHERE user_id = ? AND title = ? AND status = 'open'
            """,
            (user_id, title),
        ).fetchone()
        if existing:
            continue
        from app.ops import create_incident

        inc = create_incident(
            user_id,
            title=title,
            severity="high" if n >= _AUTH_FAILURE_THRESHOLD * 2 else "medium",
            source="log_correlation",
            summary=(
                f"{n} authentication-failure events for '{label}' within "
                f"{_AUTH_FAILURE_WINDOW_SEC // 60} minutes (threshold: {_AUTH_FAILURE_THRESHOLD}). "
                "Rule: repeated-auth-failure, evaluated over ingested logs and SecuraIQ's own audit log."
            ),
        )
        created.append(inc)
    return created


def search_logs(
    user_id: str,
    *,
    q: str = "",
    source: str = "",
    severity: str = "",
    limit: int = 200,
) -> list[dict[str, Any]]:
    """Unified, time-ordered search across ingested_logs, xdr_events (Wazuh +
    XDR/EDR), and audit_log. Every row keeps an honest `source` tag; nothing
    here is relabeled to look like it came from somewhere it didn't."""
    ensure_log_schema()
    c = get_conn()
    limit = max(1, min(int(limit or 200), 500))
    out: list[dict[str, Any]] = []

    if not source or source == "ingested":
        rows = c.execute(
            "SELECT * FROM ingested_logs WHERE user_id = ? ORDER BY received_at DESC LIMIT ?",
            (user_id, limit),
        ).fetchall()
        for r in rows:
            d = row_to_dict(r) or {}
            out.append(
                {
                    "id": d.get("id"),
                    "source": d.get("source") or "manual",
                    "ts": d.get("received_at"),
                    "severity": d.get("severity"),
                    "host": d.get("host"),
                    "actor": d.get("actor"),
                    "event_type": d.get("event_type"),
                    "message": d.get("message"),
                }
            )

    if not source or source in ("wazuh", "xdr"):
        rows = c.execute(
            "SELECT * FROM xdr_events WHERE user_id = ? ORDER BY created_at DESC LIMIT ?",
            (user_id, limit),
        ).fetchall()
        for r in rows:
            d = row_to_dict(r) or {}
            vendor = d.get("vendor") or ""
            if source == "wazuh" and vendor != "wazuh":
                continue
            if source == "xdr" and vendor == "wazuh":
                continue
            out.append(
                {
                    "id": d.get("id"),
                    "source": "wazuh" if vendor == "wazuh" else "xdr",
                    "vendor": vendor,
                    "ts": d.get("created_at"),
                    "severity": d.get("severity"),
                    "host": d.get("host"),
                    "event_type": d.get("kind"),
                    "message": d.get("title"),
                    "status": d.get("status"),
                }
            )

    if not source or source == "audit":
        rows = c.execute(
            "SELECT * FROM audit_log WHERE user_id = ? ORDER BY created_at DESC LIMIT ?",
            (user_id, limit),
        ).fetchall()
        for r in rows:
            d = row_to_dict(r) or {}
            out.append(
                {
                    "id": d.get("id"),
                    "source": "audit",
                    "ts": d.get("created_at"),
                    "severity": "info",
                    "host": "",
                    "actor": d.get("user_id"),
                    "event_type": d.get("action"),
                    "message": d.get("action"),
                }
            )

    if severity:
        out = [e for e in out if (e.get("severity") or "").lower() == severity.lower()]
    if q:
        ql = q.lower()
        out = [
            e
            for e in out
            if ql in (e.get("message") or "").lower()
            or ql in (e.get("host") or "").lower()
            or ql in (e.get("actor") or "").lower()
            or ql in (e.get("event_type") or "").lower()
        ]

    out.sort(key=lambda e: e.get("ts") or 0, reverse=True)
    return out[:limit]


def log_stats(user_id: str) -> dict[str, Any]:
    ensure_log_schema()
    c = get_conn()
    ingested_count = c.execute(
        "SELECT COUNT(*) AS n FROM ingested_logs WHERE user_id = ?", (user_id,)
    ).fetchone()["n"]
    xdr_count = c.execute(
        "SELECT COUNT(*) AS n FROM xdr_events WHERE user_id = ?", (user_id,)
    ).fetchone()["n"]
    wazuh_count = c.execute(
        "SELECT COUNT(*) AS n FROM xdr_events WHERE user_id = ? AND vendor = 'wazuh'", (user_id,)
    ).fetchone()["n"]
    audit_count = c.execute(
        "SELECT COUNT(*) AS n FROM audit_log WHERE user_id = ?", (user_id,)
    ).fetchone()["n"]
    by_severity_rows = c.execute(
        "SELECT severity, COUNT(*) AS n FROM ingested_logs WHERE user_id = ? GROUP BY severity", (user_id,)
    ).fetchall()
    by_severity = {row_to_dict(r)["severity"]: row_to_dict(r)["n"] for r in by_severity_rows}
    return {
        "ingested_count": ingested_count,
        "xdr_count": xdr_count - wazuh_count,
        "wazuh_count": wazuh_count,
        "audit_count": audit_count,
        "total": ingested_count + xdr_count + audit_count,
        "by_severity": by_severity,
        "correlation_rule": {
            "name": "repeated-auth-failure",
            "threshold": _AUTH_FAILURE_THRESHOLD,
            "window_sec": _AUTH_FAILURE_WINDOW_SEC,
            "disclaimer": "Simple threshold rule over real event counts -- not ML/AI anomaly detection.",
        },
    }
