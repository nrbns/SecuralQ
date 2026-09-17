"""Tamper-evident audit log hash chain (#239).

Each audit_log row gets prev_hash + entry_hash. Verification walks the
chain chronologically. Soft-enable: missing columns are migrated on first use.
Does not break existing callers of app.db.audit().
"""

from __future__ import annotations

import hashlib
import json
import logging
from typing import Any

from app.db import get_conn, new_id, now, table_columns

_log = logging.getLogger("securaiq.audit_chain")
GENESIS = "0" * 64


def ensure_audit_chain_schema() -> None:
    c = get_conn()
    cols = table_columns(c, "audit_log")
    if not cols:
        return
    if "prev_hash" not in cols:
        c.execute("ALTER TABLE audit_log ADD COLUMN prev_hash TEXT NOT NULL DEFAULT ''")
    if "entry_hash" not in cols:
        c.execute("ALTER TABLE audit_log ADD COLUMN entry_hash TEXT NOT NULL DEFAULT ''")
    c.commit()


def _canonical(action: str, user_id: str | None, detail: dict[str, Any], created_at: float, prev: str) -> str:
    blob = json.dumps(
        {
            "action": action,
            "user_id": user_id or "",
            "detail": detail or {},
            "created_at": created_at,
            "prev_hash": prev,
        },
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    )
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


def _last_entry_hash(c) -> str:
    row = c.execute(
        "SELECT entry_hash FROM audit_log WHERE entry_hash != '' ORDER BY created_at DESC, id DESC LIMIT 1"
    ).fetchone()
    if row and row["entry_hash"]:
        return str(row["entry_hash"])
    return GENESIS


def append_chained(
    action: str,
    user_id: str | None = None,
    detail: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Insert audit row with hash chain fields. Prefer this for security-sensitive events."""
    ensure_audit_chain_schema()
    c = get_conn()
    rid = new_id()
    ts = now()
    prev = _last_entry_hash(c)
    entry = _canonical(action, user_id, detail or {}, ts, prev)
    c.execute(
        "INSERT INTO audit_log (id, user_id, action, detail, created_at, prev_hash, entry_hash) "
        "VALUES (?, ?, ?, ?, ?, ?, ?)",
        (rid, user_id, action, json.dumps(detail or {}), ts, prev, entry),
    )
    c.commit()
    try:
        from app.siem import log_security_event

        log_security_event(action, user_id, detail)
    except Exception:
        pass
    return {"id": rid, "prev_hash": prev, "entry_hash": entry, "created_at": ts}


def verify_chain(*, limit: int = 10_000) -> dict[str, Any]:
    """Walk newest-first-stored rows in chronological order; report first break."""
    ensure_audit_chain_schema()
    c = get_conn()
    rows = c.execute(
        "SELECT id, user_id, action, detail, created_at, prev_hash, entry_hash "
        "FROM audit_log ORDER BY created_at ASC, id ASC LIMIT ?",
        (max(1, limit),),
    ).fetchall()
    expected_prev = GENESIS
    checked = 0
    skipped_legacy = 0
    for r in rows:
        eh = (r["entry_hash"] or "").strip()
        ph = (r["prev_hash"] or "").strip()
        if not eh:
            skipped_legacy += 1
            continue
        try:
            detail = json.loads(r["detail"] or "{}")
        except json.JSONDecodeError:
            detail = {}
        want = _canonical(r["action"], r["user_id"], detail, float(r["created_at"]), ph or GENESIS)
        if eh != want:
            return {
                "ok": False,
                "broken_at": r["id"],
                "checked": checked,
                "skipped_legacy": skipped_legacy,
                "reason": "entry_hash mismatch",
            }
        if checked > 0 and ph and ph != expected_prev and expected_prev != GENESIS:
            # Allow first chained row after legacy rows to start from GENESIS
            if ph != GENESIS:
                return {
                    "ok": False,
                    "broken_at": r["id"],
                    "checked": checked,
                    "skipped_legacy": skipped_legacy,
                    "reason": "prev_hash discontinuity",
                    "expected_prev": expected_prev,
                    "got_prev": ph,
                }
        expected_prev = eh
        checked += 1
    return {
        "ok": True,
        "checked": checked,
        "skipped_legacy": skipped_legacy,
        "tip": expected_prev if checked else GENESIS,
    }
