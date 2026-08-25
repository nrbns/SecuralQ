"""Inventory engine orchestration — sync sources, normalize, patch posture, realtime."""

from __future__ import annotations

from typing import Any

from app.db import get_conn, new_id, now
from app.software.models import (
    PATCH_LABELS,
    ensure_schema,
)
from app.software.normalization import normalize_product
from app.software.patch_status import compute_patch_status
from app.software.sources.base import all_sources


def _scalar(row: Any, key: str, default: int | float = 0):
    if row is None:
        return default
    try:
        return row[key]
    except (TypeError, KeyError, IndexError):
        try:
            return dict(row).get(key, default)
        except Exception:
            return default


def _upsert_product(user_id: str, rec_norm: dict[str, str]) -> str:
    c = get_conn()
    ts = now()
    norm = rec_norm["normalized_name"]
    existing = c.execute(
        "SELECT id FROM software_products WHERE user_id=? AND normalized_name=? LIMIT 1",
        (user_id, norm),
    ).fetchone()
    if existing:
        pid = str(_scalar(existing, "id", ""))
        c.execute(
            """
            UPDATE software_products SET name=?, canonical_id=?, publisher=?, vendor=?, updated_at=?
            WHERE id=?
            """,
            (
                rec_norm["name"],
                rec_norm["canonical_id"],
                rec_norm["publisher"],
                rec_norm["vendor"],
                ts,
                pid,
            ),
        )
        return pid
    pid = new_id()
    c.execute(
        """
        INSERT INTO software_products
        (id, user_id, name, normalized_name, canonical_id, publisher, vendor, category, package_ecosystem, created_at, updated_at)
        VALUES (?,?,?,?,?,?,?,?,?,?,?)
        """,
        (
            pid,
            user_id,
            rec_norm["name"],
            norm,
            rec_norm["canonical_id"],
            rec_norm["publisher"],
            rec_norm["vendor"],
            "",
            "",
            ts,
            ts,
        ),
    )
    return pid


def _upsert_installation(user_id: str, product_id: str, rec: Any) -> str:
    c = get_conn()
    ts = now()
    last = float(rec.last_seen or ts)
    source_id = (rec.source_id or rec.source or "")[:120]
    existing = c.execute(
        """
        SELECT id FROM software_installations
        WHERE user_id=? AND asset_id=? AND software_product_id=? AND source=? AND source_id=?
        LIMIT 1
        """,
        (user_id, rec.asset_id or "", product_id, rec.source or "", source_id),
    ).fetchone()
    if existing:
        iid = str(_scalar(existing, "id", ""))
        c.execute(
            """
            UPDATE software_installations SET asset_name=?, version=?, architecture=?, install_path=?,
            install_date=?, last_seen=?, status=?, severity=?, cve=?, detail=?, port=?, updated_at=?
            WHERE id=?
            """,
            (
                rec.asset_name[:200],
                rec.version[:80],
                (rec.architecture or "")[:32],
                (rec.install_path or "")[:200],
                (rec.install_date or "")[:40],
                last,
                (rec.raw_status or "unknown")[:32],
                (rec.severity or "info")[:16],
                (rec.cve or "")[:64],
                (rec.detail or "")[:500],
                rec.port,
                ts,
                iid,
            ),
        )
        return iid
    iid = new_id()
    c.execute(
        """
        INSERT INTO software_installations
        (id, user_id, asset_id, asset_name, software_product_id, version, architecture, install_path,
         install_date, source, source_id, first_seen, last_seen, status, severity, cve, detail, port, updated_at)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
        """,
        (
            iid,
            user_id,
            rec.asset_id or "",
            rec.asset_name[:200],
            product_id,
            rec.version[:80],
            (rec.architecture or "")[:32],
            (rec.install_path or "")[:200],
            (rec.install_date or "")[:40],
            rec.source[:32],
            source_id,
            last,
            last,
            (rec.raw_status or "unknown")[:32],
            (rec.severity or "info")[:16],
            (rec.cve or "")[:64],
            (rec.detail or "")[:500],
            rec.port,
            ts,
        ),
    )
    return iid


def _upsert_patch_status(
    user_id: str,
    installation_id: str,
    rec: Any,
    *,
    status: str,
    target: str,
    reason: str,
) -> None:
    c = get_conn()
    ts = now()
    existing = c.execute(
        "SELECT id FROM patch_status WHERE user_id=? AND software_installation_id=? LIMIT 1",
        (user_id, installation_id),
    ).fetchone()
    fields = (
        rec.asset_id or "",
        rec.version or "",
        target or "",
        status,
        reason[:500],
        (rec.latest_version_source or "")[:32],
        ts,
    )
    if existing:
        c.execute(
            """
            UPDATE patch_status SET asset_id=?, current_version=?, target_version=?, status=?, reason=?, version_source=?, checked_at=?
            WHERE software_installation_id=? AND user_id=?
            """,
            (*fields, installation_id, user_id),
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
                rec.asset_id or "",
                installation_id,
                rec.version or "",
                target or "",
                status,
                reason[:500],
                (rec.latest_version_source or "")[:32],
                ts,
            ),
        )


def _record_source_sync(
    user_id: str,
    key: str,
    label: str,
    *,
    healthy: bool,
    items: int,
    error: str = "",
) -> None:
    c = get_conn()
    ts = now()
    existing = c.execute(
        "SELECT id FROM inventory_sources WHERE user_id=? AND source_key=?",
        (user_id, key),
    ).fetchone()
    if existing:
        c.execute(
            """
            UPDATE inventory_sources SET label=?, healthy=?, last_sync=?, last_error=?, items_synced=?, updated_at=?
            WHERE user_id=? AND source_key=?
            """,
            (label, 1 if healthy else 0, ts, error[:300], items, ts, user_id, key),
        )
    else:
        c.execute(
            """
            INSERT INTO inventory_sources
            (id, user_id, source_key, label, healthy, last_sync, last_error, items_synced, updated_at)
            VALUES (?,?,?,?,?,?,?,?,?)
            """,
            (new_id(), user_id, key, label, 1 if healthy else 0, ts, error[:300], items, ts),
        )


def sync_inventory(user_id: str, *, publish: bool = True) -> dict[str, Any]:
    """Run all inventory sources → normalized tables → patch_status."""
    ensure_schema()
    ensure_syscollector_schema()
    totals = {"products": 0, "installations": 0, "sources": {}}
    changed_assets: set[str] = set()

    for source in all_sources():
        key = source.key
        label = source.label
        health = source.health(user_id)
        try:
            records = source.collect(user_id)
            n = 0
            for rec in records:
                if not (rec.product or "").strip():
                    continue
                norm = normalize_product(rec.product, rec.vendor, rec.publisher)
                pid = _upsert_product(user_id, norm)
                cached = _cached_latest_for_product(user_id, pid)
                if cached and not rec.latest_version:
                    rec.latest_version = cached.get("latest")
                    rec.latest_version_source = cached.get("source")
                iid = _upsert_installation(user_id, pid, rec)
                patch_st, target, reason = compute_patch_status(
                    installed=rec.version,
                    latest=rec.latest_version,
                    latest_source=rec.latest_version_source,
                    raw_status=rec.raw_status,
                    severity=rec.severity,
                    cve=rec.cve,
                )
                if not rec.patch_status or rec.patch_status == "unknown":
                    rec.patch_status = patch_st
                _upsert_patch_status(user_id, iid, rec, status=patch_st, target=target, reason=reason)
                n += 1
                if rec.asset_id:
                    changed_assets.add(rec.asset_id)
            _record_source_sync(user_id, key, label, healthy=True, items=n, error="")
            totals["sources"][key] = n
            totals["installations"] += n
        except Exception as exc:
            _record_source_sync(user_id, key, label, healthy=False, items=0, error=str(exc))
            totals["sources"][key] = 0

    c = get_conn()
    row = c.execute(
        "SELECT COUNT(DISTINCT software_product_id) AS n FROM software_installations WHERE user_id=?",
        (user_id,),
    ).fetchone()
    totals["products"] = int(_scalar(row, "n", 0))
    c.commit()

    try:
        from app.software.versions import refresh_versions_for_user

        totals["version_refresh"] = refresh_versions_for_user(user_id)
    except Exception:
        totals["version_refresh"] = {"resolved": 0, "skipped": 0}

    try:
        from app.software.advisories import publish_vulnerability_events, refresh_advisories_for_user

        adv = refresh_advisories_for_user(user_id)
        totals["advisory_refresh"] = adv
        publish_vulnerability_events(user_id, adv)
    except Exception:
        totals["advisory_refresh"] = {"advisories_matched": 0}

    if publish and totals["installations"]:
        _publish_inventory_updated(user_id, totals, changed_assets)

    return totals


def _cached_latest_for_product(user_id: str, product_id: str) -> dict[str, Any] | None:
    try:
        from app.software.versions import get_cached_latest

        return get_cached_latest(user_id, product_id)
    except Exception:
        return None


def ensure_syscollector_schema() -> None:
    c = get_conn()
    c.execute(
        """
        CREATE TABLE IF NOT EXISTS wazuh_syscollector (
            id TEXT PRIMARY KEY,
            agent_id TEXT NOT NULL,
            packages_json TEXT NOT NULL DEFAULT '[]',
            updated_at REAL NOT NULL
        )
        """
    )
    c.execute(
        "CREATE INDEX IF NOT EXISTS idx_wazuh_syscol_packages ON wazuh_syscollector(agent_id, updated_at DESC)"
    )
    c.commit()


async def refresh_wazuh_syscollector(limit_agents: int = 50) -> int:
    """Pull syscollector packages from Wazuh manager when configured."""
    try:
        from app.connectors import wazuh as wz
    except Exception:
        return 0
    if not wz.is_configured():
        return 0
    ensure_syscollector_schema()
    agents = await wz.fetch_agents(limit=limit_agents)
    n = 0
    c = get_conn()
    ts = now()
    for a in agents:
        aid = str(a.get("agent_id") or "")
        if not aid:
            continue
        try:
            data = await wz.fetch_syscollector_packages(aid, limit=300)
        except Exception:
            continue
        import json

        payload = json.dumps(data[:300])
        existing = c.execute(
            "SELECT id FROM wazuh_syscollector WHERE agent_id=? ORDER BY updated_at DESC LIMIT 1",
            (aid,),
        ).fetchone()
        if existing:
            c.execute(
                "UPDATE wazuh_syscollector SET packages_json=?, updated_at=? WHERE id=?",
                (payload, ts, str(_scalar(existing, "id"))),
            )
        else:
            c.execute(
                "INSERT INTO wazuh_syscollector (id, agent_id, packages_json, updated_at) VALUES (?,?,?,?)",
                (new_id(), aid, payload, ts),
            )
        n += 1
    c.commit()
    return n


def _format_change_message(change: dict[str, Any]) -> str:
    product = change.get("product") or change.get("canonical_id") or "Software"
    host = change.get("asset_name") or change.get("asset_id") or ""
    version = change.get("version") or ""
    latest = change.get("latest_version") or ""
    status = (change.get("status") or change.get("patch_status") or "").lower()
    if change.get("cve") or change.get("kev"):
        cve = change.get("cve") or "CVE"
        return f"{product} · {cve} on {host or 'host'}"
    if latest and version and latest != version:
        return f"{product} {version} → {latest} on {host or 'host'}"
    if status in ("missing_patch", "eol", "outdated"):
        return f"{product} needs update on {host or 'host'}"
    if version:
        return f"{product} {version} on {host or 'host'}"
    return f"{product} updated on {host or 'host'}"


def _publish_inventory_updated(user_id: str, totals: dict, assets: set[str]) -> None:
    try:
        from app.realtime_bus import publish
        from app.software_inventory import publish_software_realtime

        asset_list = list(assets)[:20]
        changes = installation_snapshots(user_id, asset_ids=asset_list, limit=15)
        products = int(totals.get("products") or 0)
        installs = int(totals.get("installations") or 0)
        msg = f"Inventory sync · {products} product(s) · {installs} installation(s)"
        if changes:
            msg = _format_change_message(changes[0])
            if len(changes) > 1:
                msg += f" · +{len(changes) - 1} more"
        publish(
            type="software.inventory.updated",
            user_id=user_id,
            installations=installs,
            products=products,
            asset_ids=asset_list,
            changes=changes,
            message=msg,
            action="sync",
            ts=now(),
        )
        publish_software_realtime(user_id, totals, action="sync", message=msg)
    except Exception:
        pass


def list_sources(user_id: str) -> list[dict[str, Any]]:
    ensure_schema()
    c = get_conn()
    rows = c.execute(
        "SELECT source_key, label, healthy, last_sync, last_error, items_synced FROM inventory_sources WHERE user_id=? ORDER BY label",
        (user_id,),
    ).fetchall()
    if rows:
        return [dict(r) for r in rows]
    # Fallback: source health without sync history
    return [s.health(user_id) for s in all_sources()]


def inventory_status(user_id: str) -> dict[str, Any]:
    ensure_schema()
    c = get_conn()
    products = int(_scalar(c.execute("SELECT COUNT(*) AS n FROM software_products WHERE user_id=?", (user_id,)).fetchone(), "n", 0))
    installs = int(
        _scalar(c.execute("SELECT COUNT(*) AS n FROM software_installations WHERE user_id=?", (user_id,)).fetchone(), "n", 0)
    )
    last = _scalar(
        c.execute("SELECT MAX(last_sync) AS ts FROM inventory_sources WHERE user_id=?", (user_id,)).fetchone(),
        "ts",
        0,
    )
    sources = list_sources(user_id)
    healthy = sum(1 for s in sources if s.get("healthy") or s.get("healthy") == 1)
    return {
        "status": "ok",
        "products": products,
        "installations": installs,
        "last_sync": float(last) if last else None,
        "sources_total": len(sources),
        "sources_healthy": healthy,
        "sources": sources,
    }


def summary_for_user(user_id: str) -> dict[str, Any]:
    ensure_schema()
    c = get_conn()
    counts: dict[str, int] = {k: 0 for k in PATCH_LABELS}
    rows = c.execute(
        "SELECT status, COUNT(*) AS n FROM patch_status WHERE user_id=? GROUP BY status",
        (user_id,),
    ).fetchall()
    for r in rows:
        st = str(_scalar(r, "status", "unknown"))
        counts[st] = int(_scalar(r, "n", 0))
    total = sum(counts.values())
    return {
        "status": "ok",
        "total_installations": total,
        "patch_counts": counts,
        "patch_labels": PATCH_LABELS,
        "up_to_date": counts.get("up_to_date", 0),
        "outdated": counts.get("update_available", 0) + counts.get("security_update", 0),
        "critical": counts.get("critical_security_update", 0) + counts.get("exploited_kev", 0),
        "eol": counts.get("end_of_life", 0),
        "unknown": counts.get("unknown", 0),
    }


def list_normalized_rows(user_id: str, *, limit: int = 500) -> list[dict[str, Any]]:
    ensure_schema()
    c = get_conn()
    q = """
        SELECT i.*, p.name AS product_name, p.vendor, p.publisher, p.canonical_id,
               ps.status AS patch_status, ps.target_version AS latest_version, ps.version_source AS latest_version_source,
               ps.reason AS patch_reason, ps.checked_at AS version_checked_at,
               (SELECT COUNT(*) FROM software_advisories sa WHERE sa.user_id=i.user_id AND sa.software_product_id=i.software_product_id) AS cve_count,
               (SELECT MAX(sa.kev) FROM software_advisories sa WHERE sa.user_id=i.user_id AND sa.software_product_id=i.software_product_id) AS advisory_kev
        FROM software_installations i
        JOIN software_products p ON p.id = i.software_product_id
        LEFT JOIN patch_status ps ON ps.software_installation_id = i.id AND ps.user_id = i.user_id
        WHERE i.user_id=?
        ORDER BY i.last_seen DESC LIMIT ?
    """
    out: list[dict[str, Any]] = []
    for r in c.execute(q, (user_id, max(1, min(limit, 500)))).fetchall():
        d = dict(r)
        d["status_label"] = PATCH_LABELS.get(d.get("patch_status") or d.get("status") or "unknown", "Unknown")
        if not d.get("latest_version"):
            d["latest_version"] = None
        out.append(d)
    return out


_PATCH_TO_LEGACY: dict[str, str] = {
    "up_to_date": "current",
    "update_available": "outdated",
    "security_update": "missing_patch",
    "critical_security_update": "missing_patch",
    "exploited_kev": "missing_patch",
    "end_of_life": "eol",
    "unknown": "unknown",
}


def legacy_row_from_normalized(row: dict[str, Any]) -> dict[str, Any]:
    """Map normalized installation + patch_status to asset_software-shaped dict for the UI."""
    raw_st = str(row.get("status") or "").lower()
    patch_st = str(row.get("patch_status") or "").lower() or ("unknown" if not raw_st else raw_st)
    if patch_st in _PATCH_TO_LEGACY:
        # Keep Control Panel "installed" when we have no resolved patch posture yet.
        if patch_st == "unknown" and raw_st in {"installed", "current", "up_to_date"}:
            legacy_st = "current" if raw_st == "up_to_date" else raw_st
        else:
            legacy_st = _PATCH_TO_LEGACY[patch_st]
    else:
        legacy_st = raw_st or "unknown"
    sev = (row.get("severity") or "info").lower()
    if patch_st in {"critical_security_update", "exploited_kev"}:
        sev = "critical"
    elif patch_st in {"security_update", "end_of_life"} and sev == "info":
        sev = "high"
    src = str(row.get("source") or "inventory")
    src_root = src.split(":")[0].lower() or "inventory"
    source_labels = {
        "scan": "Network scan",
        "vuln": "Vulnerabilities",
        "xdr": "XDR / EDR",
        "wazuh": "SIEM (Wazuh)",
        "openaudit": "Open-AudIT",
        "lan": "LAN inventory",
        "os": "OS patches",
        "control_panel": "Control Panel",
        "local": "SecuraIQ tools",
        "code": "Code / SBOM",
        "legacy": "SecuraIQ inventory",
        "inventory": "Inventory",
    }
    status_labels = {
        "current": "Current",
        "up_to_date": "Up to date",
        "outdated": "Outdated",
        "eol": "End of life",
        "missing_patch": "Missing patch",
        "unknown": "Unknown version",
        "installed": "Installed",
    }
    status_class = {
        "current": "done",
        "up_to_date": "done",
        "installed": "done",
        "outdated": "error",
        "eol": "error",
        "missing_patch": "error",
        "unknown": "planned",
    }
    return {
        "id": row.get("id") or "",
        "asset_id": row.get("asset_id") or "",
        "asset_name": row.get("asset_name") or "",
        "product": row.get("product_name") or row.get("product") or "",
        "version": row.get("version") or "",
        "vendor": row.get("vendor") or row.get("publisher") or "",
        "port": row.get("port"),
        "source": src,
        "source_label": source_labels.get(src_root, src_root.replace("_", " ").title()),
        "status": legacy_st,
        "severity": sev,
        "cve": row.get("cve") or "",
        "detail": row.get("detail") or row.get("patch_reason") or "",
        "updated_at": row.get("last_seen") or row.get("updated_at"),
        "last_seen": row.get("last_seen") or row.get("updated_at"),
        "latest_version": row.get("latest_version"),
        "latest_version_source": row.get("latest_version_source"),
        "version_checked_at": row.get("version_checked_at"),
        "patch_status": patch_st,
        "patch_label": PATCH_LABELS.get(patch_st, "Unknown"),
        "status_label": status_labels.get(legacy_st) or PATCH_LABELS.get(patch_st) or legacy_st.replace("_", " ").title(),
        "status_class": status_class.get(legacy_st, "planned"),
        "canonical_id": row.get("canonical_id") or "",
        "cve_count": int(row.get("cve_count") or 0),
        "kev": bool(row.get("advisory_kev")),
    }


def list_legacy_from_engine(user_id: str, *, limit: int = 200, **filters: Any) -> list[dict[str, Any]]:
    rows = list_normalized_rows(user_id, limit=max(limit, 500))
    out: list[dict[str, Any]] = []
    asset_id = filters.get("asset_id")
    installation_id = filters.get("installation_id")
    product = (filters.get("product") or "").lower()
    canonical_id = (filters.get("canonical_id") or "").lower()
    status = (filters.get("status") or "").lower()
    source = (filters.get("source") or "").lower()
    asset_ids = filters.get("asset_ids") or []
    for r in rows:
        leg = legacy_row_from_normalized(r)
        if installation_id and str(leg.get("id") or "") != str(installation_id):
            continue
        if asset_id and leg.get("asset_id") != asset_id:
            continue
        if asset_ids and leg.get("asset_id") not in asset_ids:
            continue
        if product and product not in (leg.get("product") or "").lower():
            continue
        if canonical_id and canonical_id != (leg.get("canonical_id") or "").lower():
            continue
        if status and leg.get("status") != status:
            continue
        if source and not (leg.get("source") or "").lower().startswith(source):
            continue
        out.append(leg)
        if len(out) >= limit:
            break
    return out


def installation_snapshots(
    user_id: str,
    *,
    asset_ids: list[str] | None = None,
    installation_ids: list[str] | None = None,
    product: str = "",
    canonical_id: str = "",
    limit: int = 20,
) -> list[dict[str, Any]]:
    """Lightweight row payloads for SSE partial UI refresh."""
    filters: dict[str, Any] = {"limit": limit}
    if asset_ids:
        filters["asset_ids"] = [a for a in asset_ids if a][:20]
    if installation_ids:
        for iid in installation_ids[:limit]:
            row = list_legacy_from_engine(user_id, limit=1, installation_id=iid)
            if row:
                return row[:limit]
    if product:
        filters["product"] = product
    if canonical_id:
        filters["canonical_id"] = canonical_id
    return list_legacy_from_engine(user_id, **filters)
