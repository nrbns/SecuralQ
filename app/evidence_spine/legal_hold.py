"""Legal hold — blocks retention purge for listed evidence. Not a court order."""

from __future__ import annotations

from typing import Any

from app.db import get_conn, new_id, now


def ensure_legal_hold_schema() -> None:
    c = get_conn()
    c.execute(
        """
        CREATE TABLE IF NOT EXISTS evidence_legal_holds (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            evidence_id TEXT NOT NULL,
            reason TEXT NOT NULL DEFAULT '',
            created_at REAL NOT NULL
        )
        """
    )
    c.execute(
        "CREATE INDEX IF NOT EXISTS idx_legal_hold_user ON evidence_legal_holds(user_id, evidence_id)"
    )
    c.commit()


def place_legal_hold(user_id: str, evidence_id: str, *, reason: str = "") -> dict[str, Any]:
    ensure_legal_hold_schema()
    hid = new_id()
    get_conn().execute(
        "INSERT INTO evidence_legal_holds (id, user_id, evidence_id, reason, created_at) VALUES (?, ?, ?, ?, ?)",
        (hid, user_id, evidence_id, (reason or "")[:240], now()),
    )
    get_conn().commit()
    return {"ok": True, "hold_id": hid, "evidence_id": evidence_id}


def is_on_legal_hold(user_id: str, evidence_id: str) -> bool:
    ensure_legal_hold_schema()
    row = get_conn().execute(
        "SELECT id FROM evidence_legal_holds WHERE user_id = ? AND evidence_id = ? LIMIT 1",
        (user_id, evidence_id),
    ).fetchone()
    return bool(row)


def list_legal_holds(user_id: str) -> dict[str, Any]:
    ensure_legal_hold_schema()
    rows = get_conn().execute(
        "SELECT * FROM evidence_legal_holds WHERE user_id = ? ORDER BY created_at DESC LIMIT 100",
        (user_id,),
    ).fetchall()
    return {"ok": True, "holds": [dict(r) for r in rows]}
