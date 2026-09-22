"""WORM / Object Lock hooks for Evidence Vault.

Honesty: this module records intent and verifies local hash immutability
markers. Actual cloud object-lock requires a configured object store
(S3 Object Lock / Azure immutability). Without that backend, status is
``not_configured`` — never claim WORM storage is active.
"""

from __future__ import annotations

import hashlib
import json
import os
from typing import Any

from app.db import get_conn, new_id, now, row_to_dict


def ensure_worm_schema() -> None:
    c = get_conn()
    c.executescript(
        """
        CREATE TABLE IF NOT EXISTS evidence_worm_locks (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            org_id TEXT,
            vault_id TEXT NOT NULL DEFAULT '',
            evidence_id TEXT NOT NULL DEFAULT '',
            content_hash TEXT NOT NULL DEFAULT '',
            retention_until REAL,
            lock_mode TEXT NOT NULL DEFAULT 'compliance',
            backend TEXT NOT NULL DEFAULT 'none',
            backend_ref TEXT NOT NULL DEFAULT '',
            status TEXT NOT NULL DEFAULT 'recorded',
            meta_json TEXT NOT NULL DEFAULT '{}',
            created_at REAL NOT NULL,
            updated_at REAL NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_worm_user
            ON evidence_worm_locks(user_id, created_at DESC);
        CREATE INDEX IF NOT EXISTS idx_worm_vault
            ON evidence_worm_locks(vault_id);
        """
    )
    c.commit()


def worm_backend_status() -> dict[str, Any]:
    """Report whether a real object-lock backend is configured."""
    endpoint = (os.environ.get("SECURAIQ_OBJECT_STORE_ENDPOINT") or "").strip()
    bucket = (os.environ.get("SECURAIQ_OBJECT_STORE_BUCKET") or "").strip()
    lock = (os.environ.get("SECURAIQ_OBJECT_LOCK_ENABLED") or "").strip().lower() in {
        "1",
        "true",
        "yes",
    }
    if endpoint and bucket and lock:
        return {
            "configured": True,
            "backend": "object_store",
            "endpoint_set": True,
            "bucket": bucket,
            "object_lock_enabled": True,
            "note": "Object store Object Lock configured — verify with provider console.",
        }
    return {
        "configured": False,
        "backend": "none",
        "endpoint_set": bool(endpoint),
        "bucket": bucket or None,
        "object_lock_enabled": False,
        "note": (
            "WORM/object-lock not active. Set SECURAIQ_OBJECT_STORE_ENDPOINT, "
            "SECURAIQ_OBJECT_STORE_BUCKET, and SECURAIQ_OBJECT_LOCK_ENABLED=true "
            "when an immutable object store is available. Local hash locks are "
            "audit markers only — not cloud WORM."
        ),
    }


def record_worm_lock(
    user_id: str,
    *,
    content_hash: str,
    vault_id: str = "",
    evidence_id: str = "",
    retention_days: int = 365,
    lock_mode: str = "compliance",
    org_id: str | None = None,
    meta: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Record an immutability lock intent (+ optional backend attempt)."""
    ensure_worm_schema()
    from app.tenancy import primary_org_id

    if not (content_hash or "").strip():
        raise ValueError("content_hash is required")
    backend = worm_backend_status()
    oid = org_id or primary_org_id(user_id)
    t = now()
    retention_until = t + float(max(1, retention_days)) * 86400.0
    rid = new_id()
    status = "locked" if backend.get("configured") else "local_marker"
    backend_ref = ""
    if backend.get("configured"):
        # Placeholder for provider SDK call — do not fake success without API
        backend_ref = f"pending:{backend.get('bucket')}:{content_hash[:16]}"
        status = "pending_object_store"
    get_conn().execute(
        """
        INSERT INTO evidence_worm_locks
        (id, user_id, org_id, vault_id, evidence_id, content_hash, retention_until,
         lock_mode, backend, backend_ref, status, meta_json, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            rid,
            user_id,
            oid,
            vault_id or "",
            evidence_id or "",
            content_hash[:128],
            retention_until,
            (lock_mode or "compliance")[:40],
            backend.get("backend") or "none",
            backend_ref[:500],
            status,
            json.dumps(meta or {})[:4000],
            t,
            t,
        ),
    )
    get_conn().commit()
    row = get_conn().execute(
        "SELECT * FROM evidence_worm_locks WHERE id = ?", (rid,)
    ).fetchone()
    out = row_to_dict(row) if row else {"id": rid, "status": status}
    out["backend_status"] = backend
    out["disclaimer"] = (
        "Local marker records hash + retention intent. "
        "Cloud WORM requires a configured object store with Object Lock."
    )
    return out


def verify_content_hash(content: bytes | str, expected_hash: str) -> bool:
    raw = content if isinstance(content, bytes) else content.encode("utf-8")
    digest = hashlib.sha256(raw).hexdigest()
    return digest.lower() == (expected_hash or "").strip().lower()


def list_worm_locks(user_id: str, *, limit: int = 50) -> list[dict[str, Any]]:
    ensure_worm_schema()
    from app.tenancy import tenant_visibility_sql

    where, args = tenant_visibility_sql(user_id)
    rows = get_conn().execute(
        f"""
        SELECT * FROM evidence_worm_locks WHERE {where}
        ORDER BY created_at DESC LIMIT ?
        """,
        [*args, max(1, min(limit, 200))],
    ).fetchall()
    return [row_to_dict(r) for r in rows]
