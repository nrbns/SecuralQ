"""Version intelligence — resolve, cache, and apply authoritative latest versions."""

from __future__ import annotations

from typing import Any

import httpx

from app.db import get_conn, new_id, now
from app.software.ecosystems import ecosystem_for, upstream_for
from app.software.models import ensure_schema
from app.software.patch_status import compute_patch_status
from app.software.sources.vendor import resolve_upstream_latest

VERSION_CACHE_TTL_SEC = 6 * 3600  # don't hammer registries
REFRESH_BATCH_SIZE = 25


def _scalar(row: Any, key: str, default: Any = None):
    if row is None:
        return default
    try:
        return row[key]
    except (TypeError, KeyError, IndexError):
        try:
            return dict(row).get(key, default)
        except Exception:
            return default


def get_cached_latest(user_id: str, product_id: str) -> dict[str, Any] | None:
    ensure_schema()
    c = get_conn()
    row = c.execute(
        """
        SELECT version, source, checked_at, release_date
        FROM software_versions
        WHERE user_id=? AND software_product_id=? AND is_latest=1
        ORDER BY checked_at DESC LIMIT 1
        """,
        (user_id, product_id),
    ).fetchone()
    if not row:
        return None
    ts = float(_scalar(row, "checked_at", 0) or 0)
    if ts and (now() - ts) > VERSION_CACHE_TTL_SEC:
        return None
    ver = str(_scalar(row, "version", "") or "").strip()
    if not ver:
        return None
    return {
        "latest": ver,
        "source": str(_scalar(row, "source", "") or ""),
        "checked_at": ts,
        "release_date": str(_scalar(row, "release_date", "") or ""),
    }


def upsert_version_record(
    user_id: str,
    product_id: str,
    *,
    version: str,
    source: str,
    release_date: str = "",
) -> None:
    ensure_schema()
    c = get_conn()
    ts = now()
    c.execute(
        "UPDATE software_versions SET is_latest=0 WHERE user_id=? AND software_product_id=?",
        (user_id, product_id),
    )
    c.execute(
        """
        INSERT INTO software_versions
        (id, user_id, software_product_id, version, release_date, is_latest, source, checked_at)
        VALUES (?,?,?,?,?,1,?,?)
        """,
        (new_id(), user_id, product_id, version[:80], release_date[:40], source[:32], ts),
    )
    c.execute(
        "UPDATE software_products SET package_ecosystem=?, updated_at=? WHERE id=? AND user_id=?",
        (source[:32], ts, product_id, user_id),
    )


def resolve_latest_for_product(
    *,
    canonical_id: str,
    name: str,
    source_hint: str = "",
    client: httpx.Client | None = None,
) -> dict[str, Any]:
    """Resolve latest version from upstream when mapped — else return empty latest."""
    upstream = upstream_for(canonical_id, name)
    if not upstream or upstream.get("source") in {"vendor"}:
        return {"latest": None, "source": None, "ecosystem": ecosystem_for(canonical_id, name, source_hint)}
    hit = resolve_upstream_latest(upstream, client=client)
    hit["ecosystem"] = upstream.get("ecosystem") or ecosystem_for(canonical_id, name, source_hint)
    return hit


def products_needing_refresh(user_id: str, *, limit: int = REFRESH_BATCH_SIZE) -> list[dict[str, Any]]:
    ensure_schema()
    c = get_conn()
    cutoff = now() - VERSION_CACHE_TTL_SEC
    rows = c.execute(
        """
        SELECT p.id, p.name, p.canonical_id, p.normalized_name,
               MAX(v.checked_at) AS last_checked
        FROM software_products p
        LEFT JOIN software_versions v ON v.software_product_id = p.id AND v.user_id = p.user_id AND v.is_latest = 1
        WHERE p.user_id=?
        GROUP BY p.id
        HAVING last_checked IS NULL OR last_checked < ?
        ORDER BY (last_checked IS NULL) DESC, last_checked ASC
        LIMIT ?
        """,
        (user_id, cutoff, max(1, min(limit, 100))),
    ).fetchall()
    return [dict(r) for r in rows]


def refresh_versions_for_user(user_id: str, *, limit: int = REFRESH_BATCH_SIZE) -> dict[str, Any]:
    """Batch-resolve stale product versions and recompute patch_status for installations."""
    ensure_schema()
    products = products_needing_refresh(user_id, limit=limit)
    resolved = 0
    skipped = 0
    errors = 0

    with httpx.Client(timeout=10.0, follow_redirects=True) as client:
        for prod in products:
            pid = str(prod.get("id") or "")
            if not pid:
                continue
            try:
                hit = resolve_latest_for_product(
                    canonical_id=str(prod.get("canonical_id") or ""),
                    name=str(prod.get("name") or prod.get("normalized_name") or ""),
                    client=client,
                )
                latest = hit.get("latest")
                src = hit.get("source")
                if latest and src:
                    upsert_version_record(user_id, pid, version=str(latest), source=str(src))
                    _reapply_patch_status_for_product(user_id, pid, str(latest), str(src))
                    resolved += 1
                else:
                    skipped += 1
            except Exception:
                errors += 1

    c = get_conn()
    c.commit()
    return {
        "checked": len(products),
        "resolved": resolved,
        "skipped": skipped,
        "errors": errors,
    }


def _reapply_patch_status_for_product(
    user_id: str, product_id: str, latest: str, source: str
) -> None:
    c = get_conn()
    ts = now()
    rows = c.execute(
        """
        SELECT i.id, i.asset_id, i.version, i.status, i.severity, i.cve, i.detail
        FROM software_installations i
        WHERE i.user_id=? AND i.software_product_id=?
        """,
        (user_id, product_id),
    ).fetchall()
    for r in rows:
        iid = str(_scalar(r, "id", ""))
        installed = str(_scalar(r, "version", "") or "")
        raw_status = str(_scalar(r, "status", "") or "")
        severity = str(_scalar(r, "severity", "") or "")
        cve = str(_scalar(r, "cve", "") or "")
        patch_st, target, reason = compute_patch_status(
            installed=installed,
            latest=latest,
            latest_source=source,
            raw_status=raw_status,
            severity=severity,
            cve=cve,
        )
        existing = c.execute(
            "SELECT id FROM patch_status WHERE user_id=? AND software_installation_id=? LIMIT 1",
            (user_id, iid),
        ).fetchone()
        if existing:
            c.execute(
                """
                UPDATE patch_status SET current_version=?, target_version=?, status=?, reason=?, version_source=?, checked_at=?
                WHERE software_installation_id=? AND user_id=?
                """,
                (installed, target or latest, patch_st, reason[:500], source[:32], ts, iid, user_id),
            )
        else:
            c.execute(
                """
                INSERT INTO patch_status
                (id, user_id, asset_id, software_installation_id, current_version, target_version, status, reason, version_source, checked_at)
                VALUES (?,?,?,?,?,?,?,?,?,?)
                """,
                (
                    new_id(),
                    user_id,
                    str(_scalar(r, "asset_id", "") or ""),
                    iid,
                    installed,
                    target or latest,
                    patch_st,
                    reason[:500],
                    source[:32],
                    ts,
                ),
            )


def version_intelligence_status(user_id: str) -> dict[str, Any]:
    ensure_schema()
    c = get_conn()
    total = int(_scalar(c.execute("SELECT COUNT(*) AS n FROM software_products WHERE user_id=?", (user_id,)).fetchone(), "n", 0))
    with_latest = int(
        _scalar(
            c.execute(
                "SELECT COUNT(DISTINCT software_product_id) AS n FROM software_versions WHERE user_id=? AND is_latest=1",
                (user_id,),
            ).fetchone(),
            "n",
            0,
        )
    )
    last = _scalar(
        c.execute("SELECT MAX(checked_at) AS ts FROM software_versions WHERE user_id=?", (user_id,)).fetchone(),
        "ts",
        None,
    )
    stale = len(products_needing_refresh(user_id, limit=500))
    return {
        "status": "ok",
        "products_total": total,
        "products_with_latest": with_latest,
        "products_stale": stale,
        "last_checked": float(last) if last else None,
        "cache_ttl_sec": VERSION_CACHE_TTL_SEC,
    }
