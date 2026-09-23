"""First-class service accounts (named API keys with scopes).

Lab identity for automation — not a cloud IAM / IdP replacement.
"""

from __future__ import annotations

import secrets
from typing import Any

from app.auth import hash_token
from app.db import audit, get_conn, new_id, now, table_columns

ALLOWED_SCOPES = frozenset(
    {
        "read:assets",
        "read:agents",
        "read:evidence",
        "read:risk",
        "write:agents",
        "write:evidence",
    }
)


def ensure_service_account_schema() -> None:
    c = get_conn()
    cols = table_columns(c, "api_keys")
    alters = [
        ("kind", "TEXT NOT NULL DEFAULT 'api_key'"),
        ("scopes", "TEXT NOT NULL DEFAULT ''"),
        ("last_used_at", "REAL"),
        ("revoked_at", "REAL"),
        ("rotated_from", "TEXT NOT NULL DEFAULT ''"),
    ]
    for name, decl in alters:
        if name not in cols:
            c.execute(f"ALTER TABLE api_keys ADD COLUMN {name} {decl}")
    c.commit()


def _normalize_scopes(scopes: list[str] | str | None) -> str:
    if not scopes:
        return "read:assets,read:risk"
    raw = scopes if isinstance(scopes, list) else str(scopes).split(",")
    cleaned = []
    for s in raw:
        item = str(s).strip().lower()
        if item in ALLOWED_SCOPES and item not in cleaned:
            cleaned.append(item)
    return ",".join(cleaned) or "read:assets,read:risk"


def create_service_account(
    user_id: str,
    name: str,
    scopes: list[str] | str | None = None,
) -> tuple[str, dict[str, Any]]:
    ensure_service_account_schema()
    raw = "sa_" + secrets.token_urlsafe(28)
    kid = new_id()
    scope_txt = _normalize_scopes(scopes)
    c = get_conn()
    c.execute(
        """
        INSERT INTO api_keys
        (id, user_id, name, key_prefix, key_hash, created_at, kind, scopes)
        VALUES (?, ?, ?, ?, ?, ?, 'service_account', ?)
        """,
        (kid, user_id, (name or "service").strip()[:80], raw[:10], hash_token(raw), now(), scope_txt),
    )
    c.commit()
    audit("service_account_create", user_id, {"id": kid, "name": name, "scopes": scope_txt})
    return raw, {
        "id": kid,
        "name": name,
        "kind": "service_account",
        "key_prefix": raw[:10],
        "scopes": scope_txt.split(","),
        "disclaimer": "Lab service account — not cloud IAM / IdP",
    }


def list_service_accounts(user_id: str) -> list[dict[str, Any]]:
    ensure_service_account_schema()
    rows = get_conn().execute(
        """
        SELECT id, name, key_prefix, created_at, kind, scopes, last_used_at, revoked_at
        FROM api_keys
        WHERE user_id = ? AND kind = 'service_account'
        ORDER BY created_at DESC
        """,
        (user_id,),
    ).fetchall()
    out = []
    for r in rows:
        d = dict(r)
        d["scopes"] = [s for s in str(d.get("scopes") or "").split(",") if s]
        d["active"] = not d.get("revoked_at")
        out.append(d)
    return out


def revoke_service_account(user_id: str, key_id: str) -> bool:
    ensure_service_account_schema()
    cur = get_conn().execute(
        """
        UPDATE api_keys SET revoked_at = ?
        WHERE id = ? AND user_id = ? AND kind = 'service_account' AND revoked_at IS NULL
        """,
        (now(), key_id, user_id),
    )
    get_conn().commit()
    if cur.rowcount:
        audit("service_account_revoke", user_id, {"id": key_id})
        return True
    return False


def rotate_service_account(user_id: str, key_id: str) -> tuple[str, dict[str, Any]] | None:
    ensure_service_account_schema()
    row = get_conn().execute(
        "SELECT name, scopes FROM api_keys WHERE id = ? AND user_id = ? AND kind = 'service_account'",
        (key_id, user_id),
    ).fetchone()
    if not row:
        return None
    if not revoke_service_account(user_id, key_id):
        # already revoked — still allow minting a replacement
        pass
    raw, meta = create_service_account(user_id, row["name"], row["scopes"])
    get_conn().execute(
        "UPDATE api_keys SET rotated_from = ? WHERE id = ?",
        (key_id, meta["id"]),
    )
    get_conn().commit()
    meta["rotated_from"] = key_id
    return raw, meta
