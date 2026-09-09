"""RT-06 — durable-ish processed-event ledger for processor side-effects.

Stores ``event_id`` after a successful ``process_event`` handler so retries /
duplicate Stream deliveries skip notify / evidence / risk republish.

Writers (``realtime_bus.publish``) are never gated by this table. Failures to
read/write the ledger are swallowed so the processor stays best-effort.
"""

from __future__ import annotations

import logging
import time
from typing import Any

_log = logging.getLogger("securaiq.event_idempotency")

_TABLE = "securaiq_processed_events"
_DEFAULT_PRUNE_DAYS = 7
_ensured = False


def _prune_days() -> int:
    try:
        from app.config import settings

        n = int(getattr(settings, "event_idempotency_prune_days", _DEFAULT_PRUNE_DAYS) or _DEFAULT_PRUNE_DAYS)
        return max(1, n)
    except Exception:
        return _DEFAULT_PRUNE_DAYS


def ensure_processed_events_schema(conn: Any | None = None) -> None:
    """Create ``securaiq_processed_events`` if missing (idempotent)."""
    global _ensured
    try:
        from app.db import get_conn

        c = conn or get_conn()
        c.execute(
            f"""
            CREATE TABLE IF NOT EXISTS {_TABLE} (
                event_id TEXT PRIMARY KEY,
                processed_at REAL NOT NULL
            )
            """
        )
        try:
            c.commit()
        except Exception:
            pass
        _ensured = True
    except Exception as exc:
        _log.debug("processed_events schema skipped: %s", exc)


def already_processed(event_id: str | None) -> bool:
    """Return True if ``event_id`` was marked processed. False on blank / errors."""
    eid = str(event_id or "").strip()
    if not eid:
        return False
    try:
        from app.db import get_conn

        if not _ensured:
            ensure_processed_events_schema()
        row = get_conn().execute(
            f"SELECT 1 AS ok FROM {_TABLE} WHERE event_id = ?",
            (eid,),
        ).fetchone()
        return bool(row)
    except Exception as exc:
        _log.debug("already_processed check skipped: %s", exc)
        return False


def mark_processed(event_id: str | None) -> None:
    """Record successful processing. Never raises to callers."""
    eid = str(event_id or "").strip()
    if not eid:
        return
    try:
        from app.db import get_conn

        if not _ensured:
            ensure_processed_events_schema()
        c = get_conn()
        now = time.time()
        try:
            c.execute(
                f"INSERT OR IGNORE INTO {_TABLE} (event_id, processed_at) VALUES (?, ?)",
                (eid, now),
            )
        except Exception:
            # Postgres / drivers without OR IGNORE — try ON CONFLICT
            try:
                c.execute(
                    f"INSERT INTO {_TABLE} (event_id, processed_at) VALUES (?, ?) "
                    "ON CONFLICT (event_id) DO NOTHING",
                    (eid, now),
                )
            except Exception as exc:
                _log.debug("mark_processed insert skipped: %s", exc)
                return
        try:
            c.commit()
        except Exception:
            pass
        # Occasional prune (cheap: every mark is fine at lab scale)
        prune_older_than(days=_prune_days())
    except Exception as exc:
        _log.debug("mark_processed skipped: %s", exc)


def prune_older_than(*, days: int | None = None) -> int:
    """Delete rows older than ``days``. Returns deleted count (best-effort)."""
    cutoff_days = max(1, int(days if days is not None else _prune_days()))
    cutoff = time.time() - (cutoff_days * 86400)
    try:
        from app.db import get_conn

        if not _ensured:
            ensure_processed_events_schema()
        c = get_conn()
        cur = c.execute(
            f"DELETE FROM {_TABLE} WHERE processed_at < ?",
            (cutoff,),
        )
        try:
            c.commit()
        except Exception:
            pass
        return int(getattr(cur, "rowcount", 0) or 0)
    except Exception as exc:
        _log.debug("prune_older_than skipped: %s", exc)
        return 0


def clear_processed_for_tests() -> None:
    """Test helper — wipe ledger rows."""
    global _ensured
    try:
        from app.db import get_conn

        ensure_processed_events_schema()
        c = get_conn()
        c.execute(f"DELETE FROM {_TABLE}")
        try:
            c.commit()
        except Exception:
            pass
    except Exception:
        pass
    _ensured = False
