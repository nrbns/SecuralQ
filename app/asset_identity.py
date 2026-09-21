"""Asset Identity / Entity Resolution Engine.

Multiple observations of the same machine must collapse to one canonical asset:

  AWS i-123 --+
  Agent AG-1 -+--> Canonical Asset
  EDR ABC123 -+
  IP 10.0.0.21+

Without this, 100K systems create duplicate assets and incorrect risk.

Honesty: this is correlation by stable identifiers -- not inventing ownership.
Conflicts (same alias -> two assets) are recorded, not silently overwritten.
"""

from __future__ import annotations

from typing import Any

from app.db import get_conn, new_id, now, row_to_dict

VALID_KINDS = {
    "hostname",
    "ip",
    "mac",
    "securaiq_agent_id",
    "siem_agent_id",
    "aws_instance_id",
    "azure_vm_id",
    "gcp_instance_id",
    "edr_id",
    "openaudit_id",
    "vm_id",
    "cloud_resource_id",
}


def ensure_identity_schema() -> None:
    c = get_conn()
    c.executescript(
        """
        CREATE TABLE IF NOT EXISTS asset_aliases (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            org_id TEXT,
            asset_id TEXT NOT NULL,
            kind TEXT NOT NULL,
            value TEXT NOT NULL,
            source TEXT NOT NULL DEFAULT '',
            confidence REAL NOT NULL DEFAULT 1.0,
            created_at REAL NOT NULL,
            updated_at REAL NOT NULL,
            UNIQUE(user_id, kind, value)
        );
        CREATE INDEX IF NOT EXISTS idx_alias_asset
            ON asset_aliases(user_id, asset_id);
        CREATE INDEX IF NOT EXISTS idx_alias_lookup
            ON asset_aliases(user_id, kind, value);

        CREATE TABLE IF NOT EXISTS asset_identity_conflicts (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            org_id TEXT,
            kind TEXT NOT NULL,
            value TEXT NOT NULL,
            existing_asset_id TEXT NOT NULL,
            attempted_asset_id TEXT NOT NULL,
            note TEXT NOT NULL DEFAULT '',
            created_at REAL NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_alias_conflict_user
            ON asset_identity_conflicts(user_id, created_at DESC);
        """
    )
    c.commit()


def normalize_alias(kind: str, value: str) -> tuple[str, str]:
    k = (kind or "").strip().lower()
    v = (value or "").strip()
    if k not in VALID_KINDS:
        raise ValueError(f"invalid alias kind: {kind}")
    if not v:
        raise ValueError("alias value required")
    if k in {"hostname", "ip", "mac"}:
        v = v.lower().rstrip(".")
    if k in {"ip", "hostname"}:
        try:
            from app.asset_names import host_correlation_key

            v = host_correlation_key(v) or v
        except Exception:
            pass
    if k == "mac":
        v = v.replace("-", ":").lower()
    return k, v[:240]


def resolve_by_alias(
    user_id: str,
    *,
    kind: str,
    value: str,
) -> dict[str, Any] | None:
    """Return alias row if known."""
    ensure_identity_schema()
    try:
        k, v = normalize_alias(kind, value)
    except ValueError:
        return None
    row = get_conn().execute(
        """
        SELECT * FROM asset_aliases
        WHERE user_id = ? AND kind = ? AND value = ?
        """,
        (user_id, k, v),
    ).fetchone()
    return row_to_dict(row) if row else None


def resolve_canonical(
    user_id: str,
    *,
    aliases: dict[str, str] | None = None,
    ip: str = "",
    hostname: str = "",
    agent_id: str = "",
    aws_instance_id: str = "",
    edr_id: str = "",
) -> dict[str, Any] | None:
    """Try identifiers in priority order -> first matching canonical asset_id."""
    ensure_identity_schema()
    extra = dict(aliases or {})
    ordered = [
        ("securaiq_agent_id", agent_id or extra.get("securaiq_agent_id", "")),
        ("aws_instance_id", aws_instance_id or extra.get("aws_instance_id", "")),
        ("edr_id", edr_id or extra.get("edr_id", "")),
        ("azure_vm_id", extra.get("azure_vm_id", "")),
        ("gcp_instance_id", extra.get("gcp_instance_id", "")),
        ("openaudit_id", extra.get("openaudit_id", "")),
        ("vm_id", extra.get("vm_id", "")),
        ("mac", extra.get("mac", "")),
        ("ip", ip or extra.get("ip", "")),
        ("hostname", hostname or extra.get("hostname", "") or extra.get("host", "")),
        ("siem_agent_id", extra.get("siem_agent_id", "")),
        ("cloud_resource_id", extra.get("cloud_resource_id", "")),
    ]
    for kind, val in ordered:
        if not val:
            continue
        hit = resolve_by_alias(user_id, kind=kind, value=str(val))
        if hit:
            return {
                "asset_id": hit["asset_id"],
                "matched_kind": hit["kind"],
                "matched_value": hit["value"],
                "alias": hit,
            }
    return None


def register_alias(
    user_id: str,
    asset_id: str,
    *,
    kind: str,
    value: str,
    source: str = "",
    confidence: float = 1.0,
    org_id: str | None = None,
) -> dict[str, Any]:
    """Attach an identifier to a canonical asset. Conflicts are recorded."""
    ensure_identity_schema()
    from app.tenancy import primary_org_id

    k, v = normalize_alias(kind, value)
    aid = (asset_id or "").strip()
    if not aid:
        raise ValueError("asset_id required")
    oid = org_id or primary_org_id(user_id)
    existing = resolve_by_alias(user_id, kind=k, value=v)
    t = now()
    if existing:
        if existing.get("asset_id") == aid:
            get_conn().execute(
                """
                UPDATE asset_aliases
                SET source = CASE WHEN ? != '' THEN ? ELSE source END,
                    confidence = ?, updated_at = ?
                WHERE id = ?
                """,
                (source, source, max(0.0, min(1.0, float(confidence))), t, existing["id"]),
            )
            get_conn().commit()
            return resolve_by_alias(user_id, kind=k, value=v) or existing
        get_conn().execute(
            """
            INSERT INTO asset_identity_conflicts
            (id, user_id, org_id, kind, value, existing_asset_id, attempted_asset_id,
             note, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                new_id(),
                user_id,
                oid,
                k,
                v,
                existing["asset_id"],
                aid,
                "Alias already bound to another asset",
                t,
            ),
        )
        get_conn().commit()
        return {
            "ok": False,
            "conflict": True,
            "existing_asset_id": existing["asset_id"],
            "attempted_asset_id": aid,
            "kind": k,
            "value": v,
        }
    rid = new_id()
    get_conn().execute(
        """
        INSERT INTO asset_aliases
        (id, user_id, org_id, asset_id, kind, value, source, confidence, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            rid,
            user_id,
            oid,
            aid,
            k,
            v,
            (source or "")[:80],
            max(0.0, min(1.0, float(confidence))),
            t,
            t,
        ),
    )
    get_conn().commit()
    return row_to_dict(
        get_conn().execute("SELECT * FROM asset_aliases WHERE id = ?", (rid,)).fetchone()
    )  # type: ignore[return-value]


def register_aliases_from_meta(
    user_id: str,
    asset_id: str,
    meta: dict[str, Any] | None,
    *,
    source: str = "",
    org_id: str | None = None,
) -> list[dict[str, Any]]:
    """Register every recognizable identifier from asset notes / check-in meta."""
    if not meta:
        return []
    mapping = [
        ("securaiq_agent_id", meta.get("securaiq_agent_id")),
        ("siem_agent_id", meta.get("siem_agent_id")),
        ("aws_instance_id", meta.get("aws_instance_id") or meta.get("instance_id")),
        ("azure_vm_id", meta.get("azure_vm_id")),
        ("gcp_instance_id", meta.get("gcp_instance_id")),
        ("edr_id", meta.get("edr_id")),
        ("openaudit_id", meta.get("openaudit_id")),
        ("vm_id", meta.get("vm_id")),
        ("mac", meta.get("mac")),
        ("ip", meta.get("ip")),
        ("hostname", meta.get("hostname") or meta.get("host")),
        ("cloud_resource_id", meta.get("cloud_resource_id")),
    ]
    out: list[dict[str, Any]] = []
    for kind, val in mapping:
        if not val:
            continue
        try:
            out.append(
                register_alias(
                    user_id,
                    asset_id,
                    kind=kind,
                    value=str(val),
                    source=source,
                    org_id=org_id,
                )
            )
        except Exception:
            pass
    return out


def list_aliases(
    user_id: str,
    asset_id: str,
    *,
    org_id: str | None = None,
) -> list[dict[str, Any]]:
    ensure_identity_schema()
    from app.tenancy import tenant_visibility_sql

    where, args = tenant_visibility_sql(user_id, org_id=org_id)
    rows = get_conn().execute(
        f"""
        SELECT * FROM asset_aliases
        WHERE {where} AND asset_id = ?
        ORDER BY kind, value
        """,
        (*args, asset_id),
    ).fetchall()
    return [row_to_dict(r) for r in rows]


def list_conflicts(user_id: str, *, limit: int = 50) -> list[dict[str, Any]]:
    ensure_identity_schema()
    rows = get_conn().execute(
        """
        SELECT * FROM asset_identity_conflicts
        WHERE user_id = ?
        ORDER BY created_at DESC
        LIMIT ?
        """,
        (user_id, max(1, min(limit, 200))),
    ).fetchall()
    return [row_to_dict(r) for r in rows]


def aliases_from_notes(notes: str) -> dict[str, str]:
    from app.asset_names import parse_notes_meta

    meta = parse_notes_meta(notes or "")
    out: dict[str, str] = {}
    for key in (
        "securaiq_agent_id",
        "siem_agent_id",
        "aws_instance_id",
        "instance_id",
        "azure_vm_id",
        "gcp_instance_id",
        "edr_id",
        "openaudit_id",
        "vm_id",
        "mac",
        "ip",
        "hostname",
        "host",
        "cloud_resource_id",
    ):
        val = meta.get(key)
        if val:
            out_key = "aws_instance_id" if key == "instance_id" else key
            out[out_key] = str(val)
            if key == "host" and "hostname" not in out:
                out["hostname"] = str(val)
    return out
