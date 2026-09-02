"""Patch posture reads + remediation/verify workflow (detect → recommend → verify)."""

from __future__ import annotations

from typing import Any

from app.db import get_conn
from app.software.models import PATCH_LABELS, ensure_schema
from app.software.patch_status import compare_versions
from app.software.service import legacy_row_from_normalized, list_legacy_from_engine, list_normalized_rows


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


def list_patches(user_id: str, *, limit: int = 200, critical_only: bool = False) -> list[dict[str, Any]]:
    ensure_schema()
    c = get_conn()
    q = """
        SELECT ps.*, i.asset_name, i.version AS installed_version, i.source, i.cve, i.severity, i.detail,
               p.name AS product_name, p.canonical_id, p.vendor
        FROM patch_status ps
        JOIN software_installations i ON i.id = ps.software_installation_id AND i.user_id = ps.user_id
        JOIN software_products p ON p.id = i.software_product_id
        WHERE ps.user_id=?
    """
    args: list[Any] = [user_id]
    if critical_only:
        q += " AND ps.status IN ('exploited_kev','critical_security_update','security_update')"
    q += " ORDER BY ps.checked_at DESC LIMIT ?"
    args.append(max(1, min(limit, 500)))
    out: list[dict[str, Any]] = []
    for r in c.execute(q, args).fetchall():
        d = dict(r)
        st = str(d.get("status") or "unknown")
        d["patch_label"] = PATCH_LABELS.get(st, st.replace("_", " ").title())
        d["product"] = d.get("product_name") or ""
        d["installation_id"] = d.get("software_installation_id") or ""
        out.append(d)
    return out


def get_patch_detail(user_id: str, patch_id: str) -> dict[str, Any] | None:
    """patch_id is patch_status.id or software_installation_id."""
    ensure_schema()
    c = get_conn()
    row = c.execute(
        """
        SELECT ps.*, i.asset_name, i.version AS installed_version, i.source, i.cve, i.severity, i.detail, i.last_seen,
               p.id AS product_id, p.name AS product_name, p.canonical_id, p.vendor
        FROM patch_status ps
        JOIN software_installations i ON i.id = ps.software_installation_id AND i.user_id = ps.user_id
        JOIN software_products p ON p.id = i.software_product_id
        WHERE ps.user_id=? AND (ps.id=? OR ps.software_installation_id=?)
        LIMIT 1
        """,
        (user_id, patch_id, patch_id),
    ).fetchone()
    if not row:
        inst = c.execute(
            """
            SELECT i.*, p.name AS product_name, p.canonical_id, p.vendor
            FROM software_installations i
            JOIN software_products p ON p.id = i.software_product_id
            WHERE i.user_id=? AND i.id=?
            LIMIT 1
            """,
            (user_id, patch_id),
        ).fetchone()
        if not inst:
            return None
        leg = legacy_row_from_normalized(dict(inst))
        return {
            "status": "ok",
            "patch": {
                "installation_id": patch_id,
                "product": leg.get("product"),
                "installed_version": leg.get("version"),
                "target_version": leg.get("latest_version"),
                "patch_status": leg.get("patch_status") or "unknown",
                "patch_label": leg.get("patch_label") or "Unknown",
                "asset_id": leg.get("asset_id"),
                "asset_name": leg.get("asset_name"),
                "cve": leg.get("cve"),
                "detail": leg.get("detail"),
            },
            "advisories": _advisories_for_product(user_id, str(_scalar(inst, "software_product_id", ""))),
        }
    d = dict(row)
    st = str(d.get("status") or "unknown")
    product_id = str(d.get("product_id") or "")
    return {
        "status": "ok",
        "patch": {
            "id": d.get("id"),
            "installation_id": d.get("software_installation_id"),
            "product": d.get("product_name"),
            "canonical_id": d.get("canonical_id"),
            "vendor": d.get("vendor"),
            "installed_version": d.get("installed_version") or d.get("current_version"),
            "target_version": d.get("target_version"),
            "patch_status": st,
            "patch_label": PATCH_LABELS.get(st, st),
            "reason": d.get("reason"),
            "version_source": d.get("version_source"),
            "checked_at": d.get("checked_at"),
            "asset_id": d.get("asset_id"),
            "asset_name": d.get("asset_name"),
            "cve": d.get("cve"),
            "severity": d.get("severity"),
            "detail": d.get("detail"),
            "last_seen": d.get("last_seen"),
        },
        "advisories": _advisories_for_product(user_id, product_id),
    }


def _advisories_for_product(user_id: str, product_id: str) -> list[dict[str, Any]]:
    if not product_id:
        return []
    try:
        from app.software.advisories import list_advisories_for_product

        return list_advisories_for_product(user_id, product_id)
    except Exception:
        return []


def product_detail(user_id: str, *, key: str) -> dict[str, Any]:
    ensure_schema()
    key_l = (key or "").strip().lower()
    if not key_l:
        return {"status": "ok", "product": None, "installations": [], "advisories": []}
    c = get_conn()
    prod = c.execute(
        """
        SELECT * FROM software_products
        WHERE user_id=? AND (canonical_id=? OR normalized_name=? OR LOWER(name)=?)
        LIMIT 1
        """,
        (user_id, key_l, key_l, key_l),
    ).fetchone()
    if not prod:
        return {"status": "ok", "product": None, "installations": [], "advisories": []}
    pid = str(_scalar(prod, "id", ""))
    versions: dict[str, int] = {}
    assets: list[str] = []
    installations: list[dict[str, Any]] = []
    for r in list_normalized_rows(user_id, limit=500):
        if str(r.get("software_product_id") or "") != pid:
            continue
        leg = legacy_row_from_normalized(r)
        installations.append(leg)
        ver = leg.get("version") or "unknown"
        versions[ver] = versions.get(ver, 0) + 1
        an = leg.get("asset_name") or ""
        if an and an not in assets:
            assets.append(an)
    latest_row = c.execute(
        "SELECT version, source, checked_at FROM software_versions WHERE user_id=? AND software_product_id=? AND is_latest=1 ORDER BY checked_at DESC LIMIT 1",
        (user_id, pid),
    ).fetchone()
    adv = _advisories_for_product(user_id, pid)
    kev = sum(1 for a in adv if a.get("kev"))
    critical = sum(1 for a in adv if (a.get("cvss") or 0) >= 9 or a.get("kev"))
    return {
        "status": "ok",
        "product": {
            "id": pid,
            "name": _scalar(prod, "name"),
            "canonical_id": _scalar(prod, "canonical_id"),
            "vendor": _scalar(prod, "vendor"),
            "latest_version": _scalar(latest_row, "version") if latest_row else None,
            "latest_source": _scalar(latest_row, "source") if latest_row else None,
            "version_checked_at": _scalar(latest_row, "checked_at") if latest_row else None,
        },
        "version_counts": [{"version": k, "assets": v} for k, v in sorted(versions.items(), key=lambda x: -x[1])],
        "affected_assets": assets[:100],
        "installations": installations[:100],
        "advisories": adv,
        "advisory_summary": {"total": len(adv), "kev": kev, "critical": critical},
    }


def asset_software_detail(user_id: str, asset_id: str, *, limit: int = 200) -> dict[str, Any]:
    rows = list_legacy_from_engine(user_id, asset_id=asset_id, limit=limit)
    issues = [r for r in rows if (r.get("patch_status") or r.get("status") or "") not in {"up_to_date", "current", "unknown"}]
    last_seen = max((float(r.get("last_seen") or r.get("updated_at") or 0) for r in rows), default=0)
    return {
        "status": "ok",
        "asset_id": asset_id,
        "total": len(rows),
        "issues": len(issues),
        "last_inventory": last_seen or None,
        "software": rows,
    }


def build_remediation_for_installation(user_id: str, installation_id: str) -> dict[str, str]:
    detail = get_patch_detail(user_id, installation_id)
    if not detail or not detail.get("patch"):
        return {
            "title": "Patch software installation",
            "recommendation": "Re-run inventory sync and apply vendor/OS updates.",
            "control_id": "PATCH",
        }
    p = detail["patch"]
    product = p.get("product") or "Software"
    host = p.get("asset_name") or p.get("asset_id") or "host"
    installed = p.get("installed_version") or "?"
    target = p.get("target_version") or "latest available"
    cve = p.get("cve") or ""
    label = p.get("patch_label") or p.get("patch_status") or "update needed"
    rec = [
        f"Patch {product} on {host}.",
        f"Status: {label}.",
        f"Installed: {installed}.",
        f"Target: {target}.",
    ]
    if cve:
        rec.append(f"CVE: {cve}.")
    adv = detail.get("advisories") or []
    if any(a.get("kev") for a in adv):
        rec.append("CISA KEV — prioritize immediately.")
    rec.append("Apply update during approved window, then run Verify in SecuraIQ.")
    return {
        "title": f"Patch {product} on {host}"[:300],
        "recommendation": " ".join(rec)[:2000],
        "control_id": "PATCH",
    }


def verify_patch(user_id: str, installation_id: str) -> dict[str, Any]:
    """Re-sync inventory and check whether installed version meets target."""
    before = get_patch_detail(user_id, installation_id)
    if not before or not before.get("patch"):
        return {"status": "error", "message": "Installation not found"}
    installed_before = str((before["patch"] or {}).get("installed_version") or "")
    target = str((before["patch"] or {}).get("target_version") or "")

    try:
        from app.software.service import sync_inventory

        sync_inventory(user_id, publish=True)
    except Exception as exc:
        return {"status": "error", "message": str(exc)[:300]}

    after = get_patch_detail(user_id, installation_id)
    installed_after = str((after.get("patch") or {}).get("installed_version") or "")
    patch_st = str((after.get("patch") or {}).get("patch_status") or "unknown")
    verified = patch_st in {"up_to_date"} or (
        target and compare_versions(installed_after, target) is not None and compare_versions(installed_after, target) >= 0
    )
    return {
        "status": "ok",
        "verified": verified,
        "before_version": installed_before,
        "after_version": installed_after,
        "target_version": target or None,
        "patch_status": patch_st,
        "patch_label": (after.get("patch") or {}).get("patch_label"),
        "patch": after.get("patch"),
    }
