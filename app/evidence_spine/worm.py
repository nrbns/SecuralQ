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


def _local_worm_root():
    from pathlib import Path

    from app.config import settings

    root = Path(settings.data_dir) / "worm"
    root.mkdir(parents=True, exist_ok=True)
    return root


def worm_backend_status() -> dict[str, Any]:
    """Report whether a real object-lock backend is configured.

    Local FS immutable markers are always available under data/worm/ and are
    **not** cloud Object Lock.
    """
    endpoint = (os.environ.get("SECURAIQ_OBJECT_STORE_ENDPOINT") or "").strip()
    bucket = (os.environ.get("SECURAIQ_OBJECT_STORE_BUCKET") or "").strip()
    lock = (os.environ.get("SECURAIQ_OBJECT_LOCK_ENABLED") or "").strip().lower() in {
        "1",
        "true",
        "yes",
    }
    local_root = _local_worm_root()
    local_count = 0
    try:
        local_count = sum(1 for _ in local_root.glob("*.bin")) if local_root.is_dir() else 0
    except Exception:
        local_count = 0
    if endpoint and bucket and lock:
        return {
            "configured": True,
            "backend": "object_store",
            "endpoint_set": True,
            "bucket": bucket,
            "object_lock_enabled": True,
            "local_fs_worm_root": str(local_root),
            "local_fs_marker_count": local_count,
            "note": "Object store Object Lock configured — verify with provider console.",
        }
    return {
        "configured": False,
        "backend": "local_fs",
        "endpoint_set": bool(endpoint),
        "bucket": bucket or None,
        "object_lock_enabled": False,
        "local_fs_worm_root": str(local_root),
        "local_fs_marker_count": local_count,
        "note": (
            "Cloud WORM/object-lock not active. Local FS immutable markers under "
            "data/worm/ are lab-grade hash+readonly locks — not S3 Object Lock. "
            "Set SECURAIQ_OBJECT_STORE_ENDPOINT, SECURAIQ_OBJECT_STORE_BUCKET, and "
            "SECURAIQ_OBJECT_LOCK_ENABLED=true for cloud Object Lock."
        ),
    }


def apply_local_fs_worm(content_hash: str, content: bytes | None = None) -> dict[str, Any]:
    """Write a lab-grade immutable marker file and set it read-only.

    Honesty: OS readonly bit / ACL is not cloud Object Lock. Operators can still
    clear the bit with admin rights. Never claim this as commercial WORM.
    """
    digest = (content_hash or "").strip().lower()
    if len(digest) < 16:
        raise ValueError("content_hash required")
    root = _local_worm_root()
    path = root / f"{digest}.bin"
    meta_path = root / f"{digest}.json"
    payload = content if content is not None else digest.encode("utf-8")
    if not path.exists():
        path.write_bytes(payload)
    # Verify hash if real content provided
    if content is not None:
        actual = hashlib.sha256(content).hexdigest()
        if actual != digest:
            raise ValueError("content does not match content_hash")
    meta = {
        "content_hash": digest,
        "bytes": path.stat().st_size,
        "path": str(path),
        "readonly": False,
        "disclaimer": "local_fs readonly marker — not cloud Object Lock",
    }
    try:
        # Windows + POSIX: clear write bit
        mode = path.stat().st_mode
        path.chmod(mode & ~0o222)
        meta["readonly"] = not bool(path.stat().st_mode & 0o222)
    except Exception as exc:
        meta["readonly_error"] = str(exc)[:160]
    try:
        if meta_path.exists():
            try:
                meta_path.chmod(meta_path.stat().st_mode | 0o222)
            except Exception:
                pass
        meta_path.write_text(json.dumps(meta, indent=2), encoding="utf-8")
        try:
            meta_path.chmod(meta_path.stat().st_mode & ~0o222)
        except Exception:
            pass
    except Exception as exc:
        meta["meta_write_error"] = str(exc)[:160]
    return meta


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
    content: bytes | None = None,
) -> dict[str, Any]:
    """Record an immutability lock intent (+ local FS marker / optional cloud)."""
    ensure_worm_schema()
    from app.tenancy import primary_org_id

    if not (content_hash or "").strip():
        raise ValueError("content_hash is required")
    backend = worm_backend_status()
    oid = org_id or primary_org_id(user_id)
    t = now()
    retention_until = t + float(max(1, retention_days)) * 86400.0
    rid = new_id()
    status = "local_fs_immutable"
    backend_ref = ""
    local_fs: dict[str, Any] = {}
    try:
        local_fs = apply_local_fs_worm(content_hash, content=content)
        backend_ref = str(local_fs.get("path") or "")[:500]
        status = "local_fs_immutable" if local_fs.get("readonly") else "local_marker"
    except Exception as exc:
        local_fs = {"error": str(exc)[:200]}
        status = "local_marker"
    if backend.get("configured"):
        # Placeholder for provider SDK call — do not fake success without API
        backend_ref = f"pending:{backend.get('bucket')}:{content_hash[:16]}"
        status = "pending_object_store"
    merged_meta = dict(meta or {})
    merged_meta["local_fs"] = local_fs
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
            "local_fs" if not backend.get("configured") else (backend.get("backend") or "object_store"),
            backend_ref[:500],
            status,
            json.dumps(merged_meta)[:4000],
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
    out["local_fs"] = local_fs
    out["disclaimer"] = (
        "Local FS readonly marker records hash + retention intent. "
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
