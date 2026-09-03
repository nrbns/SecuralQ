"""The Evidence Store — a shared, additive "why" layer for every module that
makes a claim about the environment.

This generalizes a pattern that already existed in one place only: the
attack-path graph's per-edge evidence contract (source / confidence /
verified / first_seen / last_seen / evidence — see
app.services.attack_graph._edge_meta). That contract stays exactly as it
is — attack-graph edges are deterministic, computed live from real tables
on every request, so there is nothing to persist there. What this module
adds is a place for everything ELSE that makes a claim (a confirmed asset
connection, a remediation plan's risk narration, an agent threat detection,
eventually a detection-engine finding or an AI investigation conclusion) to
record the same shape of evidence, so a later "why did SecuraIQ say that?"
question has one shared table to answer from instead of nothing.

Same evidence vocabulary throughout the product:
  source      "declared"  -- a human said so directly
              "derived"   -- computed from real inventory/telemetry data
              "inferred"  -- a same-tenant heuristic guess, low confidence
              "observed"  -- a live signal from an agent/scanner/integration
  confidence  0.0-1.0
  verified    True only for "declared" (a human vouched for it) or an
              "observed"/"derived" record a human has since confirmed via
              confirm_evidence() -- never upgraded silently just because
              confidence happens to be high.

This is additive only: nothing that already renders evidence inline (the
attack graph, remediation-plan explanations) is required to move to this
table. Modules record here IN ADDITION, when they want their claim to be
independently queryable/auditable later.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

from app.db import get_conn, new_id, now

VALID_SOURCES = {"declared", "derived", "inferred", "observed"}


def ensure_schema() -> None:
    c = get_conn()
    c.execute(
        """
        CREATE TABLE IF NOT EXISTS securaiq_evidence (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL DEFAULT 'local',
            fingerprint TEXT NOT NULL DEFAULT '',
            entity_type TEXT NOT NULL DEFAULT '',
            entity_id TEXT NOT NULL DEFAULT '',
            source TEXT NOT NULL DEFAULT 'derived',
            confidence REAL NOT NULL DEFAULT 0,
            verified INTEGER NOT NULL DEFAULT 0,
            summary TEXT NOT NULL DEFAULT '',
            detail_json TEXT NOT NULL DEFAULT '{}',
            created_by TEXT NOT NULL DEFAULT 'system',
            first_seen REAL NOT NULL,
            last_seen REAL NOT NULL,
            hit_count INTEGER NOT NULL DEFAULT 1,
            created_at REAL NOT NULL
        )
        """
    )
    c.execute(
        "CREATE INDEX IF NOT EXISTS idx_evidence_entity ON securaiq_evidence(user_id, entity_type, entity_id)"
    )
    c.execute(
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_evidence_fingerprint ON securaiq_evidence(user_id, fingerprint)"
    )
    c.commit()


def _fingerprint(entity_type: str, entity_id: str, source: str, summary: str) -> str:
    """Same (entity, source, summary) recorded again is the same fact
    re-observed, not a new fact -- fold it into hit_count/last_seen instead
    of growing the table unboundedly on every recompute."""
    raw = f"{entity_type}\x1f{entity_id}\x1f{source}\x1f{summary}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def record_evidence(
    user_id: str,
    *,
    entity_type: str,
    entity_id: str,
    source: str,
    summary: str,
    confidence: float | None = None,
    detail: dict[str, Any] | None = None,
    verified: bool | None = None,
    created_by: str = "system",
) -> dict[str, Any]:
    """Record one piece of evidence backing a claim made elsewhere in the
    product. Idempotent on (entity_type, entity_id, source, summary) within
    a tenant -- a re-observation bumps last_seen/hit_count rather than
    creating a duplicate row.

    `verified` defaults to True only for source="declared" (matching the
    attack-graph convention that a human declaration is inherently
    verified); every other source defaults to False and must be explicitly
    confirmed later via confirm_evidence() -- never inferred from a high
    confidence value, which would misrepresent a guess as a fact."""
    if source not in VALID_SOURCES:
        raise ValueError(f"Unknown evidence source '{source}'. Must be one of {sorted(VALID_SOURCES)}")
    if not entity_type or not entity_id:
        raise ValueError("entity_type and entity_id are required")
    ensure_schema()
    conf = 0.0 if confidence is None else max(0.0, min(1.0, float(confidence)))
    is_verified = (source == "declared") if verified is None else bool(verified)
    fp = _fingerprint(entity_type, entity_id, source, summary)
    ts = now()
    c = get_conn()
    existing = c.execute(
        "SELECT id FROM securaiq_evidence WHERE user_id = ? AND fingerprint = ?", (user_id, fp)
    ).fetchone()
    if existing:
        c.execute(
            """
            UPDATE securaiq_evidence
            SET last_seen = ?, hit_count = hit_count + 1, confidence = ?, verified = ?, detail_json = ?
            WHERE id = ?
            """,
            (ts, conf, 1 if is_verified else 0, json.dumps(detail or {})[:8000], existing["id"]),
        )
        c.commit()
        return get_evidence(user_id, existing["id"])
    eid = new_id()
    c.execute(
        """
        INSERT INTO securaiq_evidence
        (id, user_id, fingerprint, entity_type, entity_id, source, confidence, verified,
         summary, detail_json, created_by, first_seen, last_seen, hit_count, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?)
        """,
        (
            eid, user_id, fp, entity_type, entity_id, source, conf, 1 if is_verified else 0,
            summary[:500], json.dumps(detail or {})[:8000], created_by, ts, ts, ts,
        ),
    )
    c.commit()
    return get_evidence(user_id, eid)


def confirm_evidence(user_id: str, evidence_id: str, *, confirmed_by: str) -> dict[str, Any] | None:
    """A human vouches for a non-declared piece of evidence (e.g. an
    inferred/observed record). This is the only way verified flips to True
    outside of source='declared' -- never automatic, always an explicit
    human action, same discipline as the attack graph's confirm-connection
    flow."""
    ensure_schema()
    c = get_conn()
    row = c.execute(
        "SELECT * FROM securaiq_evidence WHERE id = ? AND user_id = ?", (evidence_id, user_id)
    ).fetchone()
    if not row:
        return None
    c.execute(
        "UPDATE securaiq_evidence SET verified = 1, last_seen = ? WHERE id = ?", (now(), evidence_id)
    )
    c.commit()
    try:
        from app.db import audit

        audit("evidence_confirm", user_id, {"evidence_id": evidence_id, "confirmed_by": confirmed_by})
    except Exception:
        pass
    return get_evidence(user_id, evidence_id)


def get_evidence(user_id: str, evidence_id: str) -> dict[str, Any] | None:
    ensure_schema()
    row = get_conn().execute(
        "SELECT * FROM securaiq_evidence WHERE id = ? AND user_id = ?", (evidence_id, user_id)
    ).fetchone()
    if not row:
        return None
    return _row_to_dict(row)


def get_evidence_for(user_id: str, *, entity_type: str, entity_id: str, limit: int = 100) -> list[dict[str, Any]]:
    """The full evidence trail for one entity -- what a "why did SecuraIQ
    say that?" answer should read from."""
    ensure_schema()
    rows = get_conn().execute(
        "SELECT * FROM securaiq_evidence WHERE user_id = ? AND entity_type = ? AND entity_id = ? "
        "ORDER BY last_seen DESC LIMIT ?",
        (user_id, entity_type, entity_id, max(1, min(limit, 500))),
    ).fetchall()
    return [_row_to_dict(r) for r in rows]


def list_evidence(user_id: str, *, entity_type: str = "", source: str = "", verified: bool | None = None, limit: int = 200) -> list[dict[str, Any]]:
    ensure_schema()
    q = "SELECT * FROM securaiq_evidence WHERE user_id = ?"
    args: list[Any] = [user_id]
    if entity_type:
        q += " AND entity_type = ?"
        args.append(entity_type)
    if source:
        q += " AND source = ?"
        args.append(source)
    if verified is not None:
        q += " AND verified = ?"
        args.append(1 if verified else 0)
    q += " ORDER BY last_seen DESC LIMIT ?"
    args.append(max(1, min(limit, 1000)))
    rows = get_conn().execute(q, args).fetchall()
    return [_row_to_dict(r) for r in rows]


def _row_to_dict(row: Any) -> dict[str, Any]:
    d = dict(row)
    try:
        d["detail"] = json.loads(d.get("detail_json") or "{}")
    except Exception:
        d["detail"] = {}
    d["verified"] = bool(d.get("verified"))
    return d
