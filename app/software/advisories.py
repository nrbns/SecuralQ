"""Vulnerability matching — OSV, NVD, CISA KEV → software_advisories + patch priority."""

from __future__ import annotations

import asyncio
import json
import re
from typing import Any

import httpx

from app.db import get_conn, new_id, now
from app.software.ecosystems import upstream_for
from app.software.models import (
    PATCH_CRITICAL,
    PATCH_KEV,
    PATCH_SECURITY_UPDATE,
    ensure_schema,
)
from app.software.patch_status import compare_versions, compute_patch_status
from app.software.sources.osv import fixed_versions_from_vulns, query_package_vulns

ADVISORY_BATCH_SIZE = 40
CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.I)
EPSS_URL = "https://api.first.org/data/v1/epss"


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


def _norm_token(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "", (text or "").lower())


def parse_cve_ids(text: str) -> list[str]:
    return sorted({m.group(0).upper() for m in CVE_RE.finditer(text or "")})


def load_kev_catalog() -> tuple[set[str], list[dict[str, Any]]]:
    """Read CISA KEV from intel cache — empty when unavailable."""
    try:
        from app.intel_feeds import _cache_get, _normalize_kev_items

        cached = _cache_get("kev", "catalog", max_age_sec=86400 * 7)
        if not cached:
            return set(), []
        items = _normalize_kev_items(cached.get("vulnerabilities") or cached.get("items") or [], limit=500)
        cves = {(i.get("cve") or "").upper() for i in items if i.get("cve")}
        return cves, items
    except Exception:
        return set(), []


def get_nvd_cached(cve_id: str) -> dict[str, Any]:
    cve = (cve_id or "").strip().upper()
    if not cve.startswith("CVE-"):
        return {}
    try:
        from app.intel_feeds import _cache_get

        hit = _cache_get("nvd", cve, max_age_sec=86400 * 14)
        return hit or {}
    except Exception:
        return {}


def fetch_nvd_sync(cve_id: str) -> dict[str, Any]:
    """Populate NVD cache when missing — best effort."""
    cve = (cve_id or "").strip().upper()
    cached = get_nvd_cached(cve)
    if cached:
        return cached
    try:
        from app.intel_feeds import lookup_nvd_cve

        return asyncio.run(lookup_nvd_cve(cve))
    except Exception:
        return {}


def fetch_epss_cached(cve_id: str, *, client: httpx.Client | None = None) -> float | None:
    cve = (cve_id or "").strip().upper()
    if not cve.startswith("CVE-"):
        return None
    try:
        from app.intel_feeds import _cache_get, _cache_put

        hit = _cache_get("epss", cve, max_age_sec=86400)
        if hit and hit.get("epss") is not None:
            return float(hit["epss"])
    except Exception:
        pass
    try:
        if client is None:
            with httpx.Client(timeout=8.0) as c:
                resp = c.get(EPSS_URL, params={"cve": cve})
        else:
            resp = client.get(EPSS_URL, params={"cve": cve})
        if resp.status_code != 200:
            return None
        data = (resp.json() or {}).get("data") or []
        if not data:
            return None
        score = data[0].get("epss")
        if score is None:
            return None
        epss = float(score)
        try:
            from app.intel_feeds import _cache_put

            _cache_put("epss", cve, {"epss": epss})
        except Exception:
            pass
        return epss
    except Exception:
        return None


def kev_matches_product(kev_item: dict[str, Any], product_name: str, vendor: str = "") -> bool:
    k_vendor = _norm_token(str(kev_item.get("vendor") or ""))
    k_product = _norm_token(str(kev_item.get("product") or ""))
    if not k_product:
        return False
    p_name = _norm_token(product_name)
    p_vendor = _norm_token(vendor)
    if k_product in p_name or p_name in k_product:
        if not k_vendor or not p_vendor or k_vendor in p_vendor or p_vendor in k_vendor:
            return True
    return False


def osv_query_target(canonical_id: str, name: str) -> tuple[str, str]:
    """Return (ecosystem, package_name) when OSV lookup is meaningful."""
    up = upstream_for(canonical_id, name)
    src = (up.get("source") or "").lower()
    if src == "pypi" and up.get("package"):
        return "PyPI", str(up["package"])
    if src == "npm" and up.get("package"):
        return "npm", str(up["package"])
    eco = (up.get("ecosystem") or "").strip()
    if eco in {"PyPI", "npm", "NuGet", "Maven", "Go", "crates.io", "RubyGems"}:
        pkg = str(up.get("package") or name or "").strip()
        if pkg:
            return eco, pkg
    key = (name or "").strip().lower()
    if key in {"openssl", "nginx", "httpd", "apache"}:
        return "PyPI", key  # often wrong but OSV may still hit; skip if no version
    return "", ""


def _severity_from_cvss(cvss: float | None) -> str:
    if cvss is None:
        return ""
    if cvss >= 9.0:
        return "CRITICAL"
    if cvss >= 7.0:
        return "HIGH"
    if cvss >= 4.0:
        return "MEDIUM"
    return "LOW"


def upsert_advisory(
    user_id: str,
    product_id: str,
    *,
    cve_id: str,
    severity: str = "",
    cvss: float | None = None,
    epss: float | None = None,
    kev: bool = False,
    fixed_version: str = "",
    source: str = "",
    version_range: str = "",
    detail: str = "",
) -> None:
    ensure_schema()
    c = get_conn()
    ts = now()
    cve = (cve_id or "").strip().upper()[:64]
    if not cve:
        return
    existing = c.execute(
        """
        SELECT id FROM software_advisories
        WHERE user_id=? AND software_product_id=? AND cve_id=? AND source=?
        LIMIT 1
        """,
        (user_id, product_id, cve, (source or "intel")[:32]),
    ).fetchone()
    fields = (
        (version_range or "")[:120],
        (severity or "")[:16],
        cvss,
        epss,
        1 if kev else 0,
        (fixed_version or "")[:80],
        (source or "intel")[:32],
        ts,
        (detail or "")[:500],
    )
    if existing:
        c.execute(
            """
            UPDATE software_advisories SET version_range=?, severity=?, cvss=?, epss=?, kev=?, fixed_version=?, source=?, updated_at=?
            WHERE id=?
            """,
            (fields[0], fields[1], fields[2], fields[3], fields[4], fields[5], fields[6], ts, str(_scalar(existing, "id", ""))),
        )
    else:
        c.execute(
            """
            INSERT INTO software_advisories
            (id, user_id, software_product_id, version_range, cve_id, cwe, cvss, severity, epss, kev, fixed_version, source, published_at, updated_at)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            """,
            (
                new_id(),
                user_id,
                product_id,
                fields[0],
                cve,
                "",
                fields[2],
                fields[1],
                fields[3],
                fields[4],
                fields[5],
                fields[6],
                ts,
                fields[7],
            ),
        )


def list_advisories_for_product(user_id: str, product_id: str) -> list[dict[str, Any]]:
    ensure_schema()
    c = get_conn()
    rows = c.execute(
        """
        SELECT cve_id, severity, cvss, epss, kev, fixed_version, source, version_range, updated_at
        FROM software_advisories WHERE user_id=? AND software_product_id=?
        ORDER BY kev DESC, cvss DESC, updated_at DESC
        """,
        (user_id, product_id),
    ).fetchall()
    out = [dict(r) for r in rows]
    if out:
        return out
    return []


def _best_fixed_version(advisories: list[dict[str, Any]]) -> str:
    fixed = [str(a.get("fixed_version") or "").strip() for a in advisories if a.get("fixed_version")]
    if not fixed:
        return ""
    fixed.sort(key=lambda v: compare_versions(v, "0") or -1, reverse=True)
    return fixed[0]


def compute_patch_with_advisories(
    *,
    installed: str,
    latest: str | None,
    latest_source: str | None,
    raw_status: str = "",
    severity: str = "",
    cve: str = "",
    advisories: list[dict[str, Any]] | None = None,
) -> tuple[str, str, str]:
    adv = list(advisories or [])
    kev_hit = any(a.get("kev") for a in adv)
    max_cvss = max((float(a["cvss"]) for a in adv if a.get("cvss") is not None), default=None)
    fixed = _best_fixed_version(adv)
    target_latest = (latest or "").strip() or fixed

    if kev_hit:
        cve_ids = ", ".join(sorted({str(a.get("cve_id") or "") for a in adv if a.get("kev")})[:3])
        return PATCH_KEV, target_latest, f"CISA KEV: {cve_ids or 'known exploited'}"

    if max_cvss is not None and max_cvss >= 9.0:
        cve_ids = ", ".join(sorted({str(a.get("cve_id") or "") for a in adv if (a.get("cvss") or 0) >= 9})[:3])
        return PATCH_CRITICAL, target_latest, f"Critical CVE (CVSS {max_cvss:.1f}): {cve_ids}"

    if max_cvss is not None and max_cvss >= 7.0:
        cve_ids = ", ".join(sorted({str(a.get("cve_id") or "") for a in adv if (a.get("cvss") or 0) >= 7})[:3])
        return PATCH_SECURITY_UPDATE, target_latest, f"High severity CVE (CVSS {max_cvss:.1f}): {cve_ids}"

    if adv and fixed:
        cmp = compare_versions(installed, fixed)
        if cmp is not None and cmp < 0:
            return PATCH_SECURITY_UPDATE, fixed, f"Fixed in {fixed} ({adv[0].get('source') or 'advisory'})"

    return compute_patch_status(
        installed=installed,
        latest=latest,
        latest_source=latest_source,
        raw_status=raw_status,
        severity=severity,
        cve=cve,
        kev=kev_hit,
    )


def _match_installation_advisories(
    user_id: str,
    inst: dict[str, Any],
    prod: dict[str, Any],
    *,
    kev_cves: set[str],
    kev_items: list[dict[str, Any]],
    client: httpx.Client,
) -> list[dict[str, Any]]:
    product_id = str(prod.get("id") or "")
    product_name = str(prod.get("name") or inst.get("product_name") or "")
    vendor = str(prod.get("vendor") or prod.get("publisher") or "")
    version = str(inst.get("version") or "")
    canonical = str(prod.get("canonical_id") or "")
    matched: list[dict[str, Any]] = []
    seen: set[str] = set()

    def _add(cve: str, *, cvss: float | None, severity: str, kev: bool, fixed: str, source: str, detail: str) -> None:
        cve_u = cve.upper()
        if not cve_u.startswith("CVE-") or cve_u in seen:
            return
        seen.add(cve_u)
        epss = fetch_epss_cached(cve_u, client=client)
        upsert_advisory(
            user_id,
            product_id,
            cve_id=cve_u,
            severity=severity,
            cvss=cvss,
            epss=epss,
            kev=kev,
            fixed_version=fixed,
            source=source,
            detail=detail,
        )
        matched.append(
            {
                "cve_id": cve_u,
                "cvss": cvss,
                "severity": severity,
                "kev": kev,
                "epss": epss,
                "fixed_version": fixed,
                "source": source,
            }
        )

    for cve in parse_cve_ids(str(inst.get("cve") or "")):
        nvd = fetch_nvd_sync(cve)
        cvss = nvd.get("cvss")
        if isinstance(cvss, str):
            try:
                cvss = float(cvss)
            except ValueError:
                cvss = None
        sev = str(nvd.get("severity") or _severity_from_cvss(cvss if isinstance(cvss, (int, float)) else None))
        _add(
            cve,
            cvss=cvss if isinstance(cvss, (int, float)) else None,
            severity=sev,
            kev=cve in kev_cves,
            fixed="",
            source="nvd",
            detail=str(nvd.get("description") or inst.get("detail") or "")[:500],
        )

    for cve in parse_cve_ids(str(inst.get("detail") or "")):
        if cve in seen:
            continue
        nvd = fetch_nvd_sync(cve)
        cvss = nvd.get("cvss")
        if isinstance(cvss, str):
            try:
                cvss = float(cvss)
            except ValueError:
                cvss = None
        _add(
            cve,
            cvss=cvss if isinstance(cvss, (int, float)) else None,
            severity=str(nvd.get("severity") or _severity_from_cvss(cvss if isinstance(cvss, (int, float)) else None)),
            kev=cve in kev_cves,
            fixed="",
            source="nvd",
            detail=str(nvd.get("description") or "")[:500],
        )

    eco, pkg = osv_query_target(canonical, product_name)
    if eco and pkg and version:
        vulns = query_package_vulns(name=pkg, ecosystem=eco, version=version, client=client)
        for v in vulns[:10]:
            vid = str(v.get("id") or "")
            if not vid.upper().startswith("CVE-"):
                continue
            fixed_list = fixed_versions_from_vulns([v])
            fixed = fixed_list[-1] if fixed_list else ""
            sev_arr = v.get("severity") or []
            sev_type = ""
            if isinstance(sev_arr, list) and sev_arr:
                sev_type = str((sev_arr[0] or {}).get("type") or "")
            _add(
                vid,
                cvss=None,
                severity=sev_type.upper()[:16],
                kev=vid.upper() in kev_cves,
                fixed=fixed,
                source="osv",
                detail=str(v.get("summary") or "")[:500],
            )

    for item in kev_items:
        cve = (item.get("cve") or "").upper()
        if not cve or cve in seen:
            continue
        if kev_matches_product(item, product_name, vendor):
            _add(
                cve,
                cvss=None,
                severity="HIGH",
                kev=True,
                fixed="",
                source="kev",
                detail=str(item.get("name") or item.get("notes") or "")[:500],
            )

    return matched


def _apply_patch_for_installation(
    user_id: str,
    inst: dict[str, Any],
    advisories: list[dict[str, Any]],
) -> None:
    c = get_conn()
    iid = str(inst.get("id") or "")
    if not iid:
        return
    ts = now()
    ps = c.execute(
        """
        SELECT target_version, version_source FROM patch_status
        WHERE user_id=? AND software_installation_id=? LIMIT 1
        """,
        (user_id, iid),
    ).fetchone()
    latest = str(_scalar(ps, "target_version", "") or "") or None
    latest_src = str(_scalar(ps, "version_source", "") or "") or None
    if not latest:
        try:
            from app.software.versions import get_cached_latest

            cached = get_cached_latest(user_id, str(inst.get("software_product_id") or ""))
            if cached:
                latest = cached.get("latest")
                latest_src = cached.get("source")
        except Exception:
            pass

    patch_st, target, reason = compute_patch_with_advisories(
        installed=str(inst.get("version") or ""),
        latest=latest,
        latest_source=latest_src,
        raw_status=str(inst.get("status") or ""),
        severity=str(inst.get("severity") or ""),
        cve=str(inst.get("cve") or ""),
        advisories=advisories,
    )
    top_cve = advisories[0].get("cve_id") if advisories else str(inst.get("cve") or "")
    existing = c.execute(
        "SELECT id FROM patch_status WHERE user_id=? AND software_installation_id=? LIMIT 1",
        (user_id, iid),
    ).fetchone()
    if existing:
        c.execute(
            """
            UPDATE patch_status SET current_version=?, target_version=?, status=?, reason=?, checked_at=?
            WHERE software_installation_id=? AND user_id=?
            """,
            (str(inst.get("version") or ""), target or (latest or ""), patch_st, reason[:500], ts, iid, user_id),
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
                str(inst.get("asset_id") or ""),
                iid,
                str(inst.get("version") or ""),
                target or (latest or ""),
                patch_st,
                reason[:500],
                (latest_src or "")[:32],
                ts,
            ),
        )
    if top_cve and advisories:
        c.execute(
            "UPDATE software_installations SET cve=?, severity=?, updated_at=? WHERE id=? AND user_id=?",
            (
                str(top_cve)[:64],
                "critical" if any(a.get("kev") for a in advisories) else str(inst.get("severity") or "info")[:16],
                ts,
                iid,
                user_id,
            ),
        )


def installations_for_advisory_refresh(user_id: str, *, limit: int = ADVISORY_BATCH_SIZE) -> list[dict[str, Any]]:
    ensure_schema()
    c = get_conn()
    rows = c.execute(
        """
        SELECT i.*, p.name AS product_name, p.vendor, p.publisher, p.canonical_id, p.id AS product_id
        FROM software_installations i
        JOIN software_products p ON p.id = i.software_product_id
        WHERE i.user_id=?
        ORDER BY i.updated_at ASC
        LIMIT ?
        """,
        (user_id, max(1, min(limit, 200))),
    ).fetchall()
    return [dict(r) for r in rows]


def refresh_advisories_for_user(user_id: str, *, limit: int = ADVISORY_BATCH_SIZE) -> dict[str, Any]:
    """Match advisories for a batch of installations and recalculate patch priority."""
    ensure_schema()
    kev_cves, kev_items = load_kev_catalog()
    if not kev_cves:
        try:
            from app.intel_feeds import fetch_cisa_kev

            feed = asyncio.run(fetch_cisa_kev(limit=500))
            kev_cves = {(i.get("cve") or "").upper() for i in (feed.get("items") or []) if i.get("cve")}
            kev_items = [i for i in (feed.get("items") or []) if isinstance(i, dict)]
        except Exception:
            kev_cves, kev_items = set(), []

    inst_rows = installations_for_advisory_refresh(user_id, limit=limit)
    matched_total = 0
    kev_hits = 0
    critical_hits = 0
    errors = 0

    with httpx.Client(timeout=12.0) as client:
        for inst in inst_rows:
            prod = {
                "id": inst.get("product_id") or inst.get("software_product_id"),
                "name": inst.get("product_name"),
                "vendor": inst.get("vendor"),
                "publisher": inst.get("publisher"),
                "canonical_id": inst.get("canonical_id"),
            }
            try:
                adv = _match_installation_advisories(
                    user_id,
                    inst,
                    prod,
                    kev_cves=kev_cves,
                    kev_items=kev_items,
                    client=client,
                )
                _apply_patch_for_installation(user_id, inst, adv)
                matched_total += len(adv)
                if any(a.get("kev") for a in adv):
                    kev_hits += 1
                if any((a.get("cvss") or 0) >= 9 for a in adv if a.get("cvss") is not None):
                    critical_hits += 1
            except Exception:
                errors += 1

    c = get_conn()
    c.commit()
    return {
        "checked": len(inst_rows),
        "advisories_matched": matched_total,
        "kev_installations": kev_hits,
        "critical_installations": critical_hits,
        "errors": errors,
        "kev_catalog_size": len(kev_cves),
    }


def list_advisories(
    user_id: str,
    *,
    limit: int = 200,
    critical_only: bool = False,
) -> list[dict[str, Any]]:
    ensure_schema()
    c = get_conn()
    q = """
        SELECT a.*, p.name AS product_name, p.canonical_id
        FROM software_advisories a
        JOIN software_products p ON p.id = a.software_product_id
        WHERE a.user_id=?
    """
    args: list[Any] = [user_id]
    if critical_only:
        q += " AND (a.kev=1 OR a.cvss >= 7.0)"
    q += " ORDER BY a.kev DESC, a.cvss DESC, a.updated_at DESC LIMIT ?"
    args.append(max(1, min(limit, 500)))
    return [dict(r) for r in c.execute(q, args).fetchall()]


def advisory_summary(user_id: str) -> dict[str, Any]:
    ensure_schema()
    c = get_conn()
    total = int(
        _scalar(c.execute("SELECT COUNT(*) AS n FROM software_advisories WHERE user_id=?", (user_id,)).fetchone(), "n", 0)
    )
    kev = int(
        _scalar(
            c.execute("SELECT COUNT(*) AS n FROM software_advisories WHERE user_id=? AND kev=1", (user_id,)).fetchone(),
            "n",
            0,
        )
    )
    critical = int(
        _scalar(
            c.execute(
                "SELECT COUNT(*) AS n FROM software_advisories WHERE user_id=? AND (kev=1 OR cvss >= 9.0)",
                (user_id,),
            ).fetchone(),
            "n",
            0,
        )
    )
    high = int(
        _scalar(
            c.execute(
                "SELECT COUNT(*) AS n FROM software_advisories WHERE user_id=? AND cvss >= 7.0 AND cvss < 9.0",
                (user_id,),
            ).fetchone(),
            "n",
            0,
        )
    )
    last = _scalar(
        c.execute("SELECT MAX(updated_at) AS ts FROM software_advisories WHERE user_id=?", (user_id,)).fetchone(),
        "ts",
        None,
    )
    return {
        "status": "ok",
        "total_advisories": total,
        "kev": kev,
        "critical": critical,
        "high": high,
        "last_updated": float(last) if last else None,
    }


def publish_vulnerability_events(user_id: str, refresh_result: dict[str, Any]) -> None:
    if not refresh_result.get("kev_installations") and not refresh_result.get("critical_installations"):
        return
    try:
        from app.realtime_bus import publish
        from app.software.service import installation_snapshots

        changes = installation_snapshots(user_id, limit=10)
        critical = [r for r in changes if (r.get("patch_status") or "") in {"exploited_kev", "critical_security_update"}]
        kev_n = int(refresh_result.get("kev_installations") or 0)
        crit_n = int(refresh_result.get("critical_installations") or 0)
        msg = f"Critical vulnerabilities · {crit_n} installation(s)"
        if kev_n:
            msg = f"KEV alert · {kev_n} exploited CVE(s) on live inventory"
        elif critical:
            c0 = critical[0]
            msg = f"{c0.get('product') or 'Software'} · {c0.get('cve') or 'critical CVE'} on {c0.get('asset_name') or 'host'}"
        publish(
            type="software.vulnerability.changed",
            user_id=user_id,
            kev_installations=kev_n,
            critical_installations=crit_n,
            advisories_matched=int(refresh_result.get("advisories_matched") or 0),
            changes=critical[:10] or changes[:10],
            message=msg,
            action="vuln",
            ts=now(),
        )
    except Exception:
        pass
