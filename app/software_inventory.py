"""Per-asset software inventory and patch/outdated posture.

Aggregates products and patch gaps from every SecuraIQ source:
scans, vulns (nmap/trivy/grype/code/OSV), XDR patches, Wazuh agents,
Open-AudIT / LAN inventory, HTTP banners, and local scanner tools.
"""

from __future__ import annotations

import json
import re
from typing import Any

from app.db import get_conn, new_id, now

STATUS_LABELS: dict[str, str] = {
    "current": "Current",
    "up_to_date": "Up to date",
    "outdated": "Outdated",
    "eol": "End of life",
    "missing_patch": "Missing patch",
    "unknown": "Unknown version",
    "installed": "Installed",
}

STATUS_CLASS: dict[str, str] = {
    "current": "done",
    "up_to_date": "done",
    "outdated": "error",
    "eol": "error",
    "missing_patch": "error",
    "unknown": "planned",
    "installed": "done",
}

SOURCE_LABELS: dict[str, str] = {
    "scan": "Network scan",
    "vuln": "Vulnerabilities",
    "xdr": "XDR / EDR",
    "wazuh": "SIEM (Wazuh)",
    "siem": "SIEM",
    "openaudit": "Open-AudIT",
    "lan": "LAN inventory",
    "asset": "Asset inventory",
    "inventory": "Inventory",
    "local": "SecuraIQ tools",
    "hardening": "Hardening",
    "cloud": "Cloud posture",
    "code": "Code / SBOM",
    "os": "OS patches",
    "control_panel": "Control Panel",
}

_SEV_WEIGHT = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}

_VULN_SOURCE_RE = re.compile(
    r"nmap|scan:|netvuln|openvas|securaiq|trivy|grype|code_scan|securaiq_code|"
    r"dependabot|github:|osv|nuclei|zap|web_builtin|hardening|cloud",
    re.I,
)

_SERVER_BANNER_RE = re.compile(
    r"(?P<product>Apache|nginx|Microsoft-IIS|IIS|OpenSSH|lighttpd|Caddy|Tomcat|"
    r"Jetty|gunicorn|uvicorn|Node\.js|Express|PHP|OpenSSL|"
    r"MariaDB|MySQL|PostgreSQL|Redis|MongoDB)"
    r"[/\s]*(?P<version>\d+(?:\.\d+){0,3}[^\s,]*)?",
    re.I,
)

_OS_EOL_RULES: list[tuple[re.Pattern[str], str, str]] = [
    (re.compile(r"windows\s+server\s+2003|windows\s+2003", re.I), "Windows Server 2003", "EOL"),
    (re.compile(r"windows\s+server\s+2008(?!\s+R2)|windows\s+2008(?!\s+R2)", re.I), "Windows Server 2008", "EOL"),
    (re.compile(r"windows\s+server\s+2008\s+r2|windows\s+2008\s+r2", re.I), "Windows Server 2008 R2", "EOL"),
    (re.compile(r"windows\s+server\s+2012(?!\s+R2)", re.I), "Windows Server 2012", "EOL"),
    (re.compile(r"windows\s+server\s+2012\s+r2", re.I), "Windows Server 2012 R2", "EOL"),
    (re.compile(r"windows\s+7\b|windows\s+vista", re.I), "Windows 7/Vista", "EOL"),
    (re.compile(r"ubuntu\s+(12|14|16|18)\.", re.I), "Ubuntu LTS (old)", "EOL"),
    (re.compile(r"debian\s+(7|8|9)\b", re.I), "Debian (old)", "EOL"),
    (re.compile(r"centos\s+(6|7)\b", re.I), "CentOS (legacy)", "EOL"),
    (re.compile(r"rhel\s+(6|7)\b", re.I), "RHEL (legacy)", "EOL"),
]

_OS_CURRENT_HINTS = re.compile(
    r"windows\s+server\s+202[25]|windows\s+11|windows\s+10|ubuntu\s+(20|22|24)\.|debian\s+(11|12)\b|rhel\s+(8|9)\b",
    re.I,
)

_SERVER_CATEGORIES = frozenset({"server", "computer", "endpoint", "database", "web", "network"})

_ISSUE_STATUSES = frozenset({"outdated", "eol", "missing_patch"})
_OK_STATUSES = frozenset({"current", "up_to_date", "installed"})


def _scalar_int(row: Any, key: str = "n", default: int = 0) -> int:
    if row is None:
        return default
    try:
        return int(row[key])
    except (TypeError, KeyError, IndexError):
        pass
    try:
        return int(dict(row).get(key) or default)
    except Exception:
        return default


def _last_sync_ts(user_id: str) -> float | None:
    ensure_schema()
    c = get_conn()
    row = c.execute(
        "SELECT MAX(updated_at) AS ts FROM asset_software WHERE user_id=?",
        (user_id,),
    ).fetchone()
    ts = _scalar_int(row, "ts", 0)
    try:
        from app.software.models import ensure_schema as ensure_engine_schema

        ensure_engine_schema()
        eng = c.execute(
            "SELECT MAX(last_sync) AS ts FROM inventory_sources WHERE user_id=?",
            (user_id,),
        ).fetchone()
        eng_ts = _scalar_int(eng, "ts", 0)
        ts = max(ts, eng_ts)
    except Exception:
        pass
    return float(ts) if ts else None


def empty_posture() -> dict[str, Any]:
    return {
        "total_products": 0,
        "counts": {
            "current": 0,
            "up_to_date": 0,
            "outdated": 0,
            "eol": 0,
            "missing_patch": 0,
            "unknown": 0,
            "installed": 0,
        },
        "issues": 0,
        "healthy": 0,
        "health_score": 100,
        "hosts_with_issues": 0,
        "top_issues": [],
        "inventory": [],
        "by_source": {},
        "by_source_label": {},
        "source_labels": SOURCE_LABELS,
        "patch_compliance": {"total_missing_patches": 0, "hosts_with_gaps": 0, "by_host": {}},
        "status_labels": STATUS_LABELS,
        "server_posture": {"summary": {"total": 0, "up_to_date": 0, "needs_update": 0, "unknown": 0}, "servers": []},
        "server_summary": {"total": 0, "up_to_date": 0, "needs_update": 0, "unknown": 0},
        "servers": [],
        "coverage": {
            "scans": 0,
            "xdr": 0,
            "siem": 0,
            "inventory": 0,
            "code": 0,
            "local_tools": 0,
            "hardening": 0,
            "cloud": 0,
            "os_patches": 0,
            "remote_ssh": 0,
            "control_panel": 0,
        },
        "windows_host": {
            "platform": "",
            "host": "",
            "installed_apps": 0,
            "pending_updates": 0,
            "last_patch": "",
            "programs_preview": [],
            "pending_preview": [],
            "needs_refresh": False,
        },
    }


def inventory_api_payload(
    user_id: str,
    *,
    inventory: list[dict[str, Any]] | None = None,
    posture: dict[str, Any] | None = None,
    message: str = "",
) -> dict[str, Any]:
    inv = list(inventory or [])
    post = dict(posture or empty_posture())
    total = len(inv) if inv else int(post.get("total_products") or 0)
    sources = sorted((post.get("by_source_label") or {}).keys())
    last_sync = _last_sync_ts(user_id)
    msg = message or (
        "No software inventory has been collected yet." if total == 0 else ""
    )
    return {
        "status": "ok",
        "data": inv,
        "inventory": inv,
        "total": total,
        "last_sync": last_sync,
        "sources": sources,
        "message": msg,
        "posture": post,
    }


def ensure_schema() -> None:
    c = get_conn()
    c.execute(
        """
        CREATE TABLE IF NOT EXISTS asset_software (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            asset_id TEXT NOT NULL DEFAULT '',
            asset_name TEXT NOT NULL DEFAULT '',
            product TEXT NOT NULL,
            version TEXT NOT NULL DEFAULT '',
            vendor TEXT NOT NULL DEFAULT '',
            port INTEGER,
            source TEXT NOT NULL DEFAULT '',
            status TEXT NOT NULL DEFAULT 'unknown',
            severity TEXT NOT NULL DEFAULT 'info',
            cve TEXT NOT NULL DEFAULT '',
            detail TEXT NOT NULL DEFAULT '',
            updated_at REAL NOT NULL
        )
        """
    )
    c.execute(
        "CREATE INDEX IF NOT EXISTS idx_asset_software_user ON asset_software(user_id, updated_at DESC)"
    )
    c.execute(
        "CREATE INDEX IF NOT EXISTS idx_asset_software_asset ON asset_software(user_id, asset_id)"
    )
    c.commit()


def status_label(status: str | None) -> str:
    return STATUS_LABELS.get((status or "").lower(), (status or "unknown").replace("_", " ").title())


def source_label(source: str | None) -> str:
    root = (source or "scan").split(":")[0].lower()
    return SOURCE_LABELS.get(root, root.replace("_", " ").title())


def _classify_banner(text: str) -> dict[str, str]:
    from app.tools.runner import _VERSION_VULN_RULES

    blob = (text or "").strip()
    if not blob:
        return {"status": "unknown", "cve": "", "detail": "", "severity": "info"}
    for pattern, product, cve, note in _VERSION_VULN_RULES:
        if pattern.search(blob):
            sev = "critical" if cve.startswith("CVE-") and "backdoor" in note.lower() else "high"
            if cve == "EOL":
                sev = "high"
            return {
                "status": "eol" if cve == "EOL" else "outdated",
                "cve": cve,
                "detail": note,
                "severity": sev,
                "product_hint": product,
            }
    return {"status": "unknown", "cve": "", "detail": "", "severity": "info"}


def classify_os(os_name: str, version: str = "") -> dict[str, str]:
    """Server/OS-oriented latest-vs-EOL classification."""
    blob = " ".join(x for x in (os_name, version) if x).strip()
    if not blob:
        return {"status": "unknown", "cve": "", "detail": "", "severity": "info"}
    for pattern, product, cve in _OS_EOL_RULES:
        if pattern.search(blob):
            return {
                "status": "eol",
                "cve": cve,
                "detail": f"{product} is end-of-life — no security patches",
                "severity": "high",
            }
    if _OS_CURRENT_HINTS.search(blob):
        return {
            "status": "current",
            "cve": "",
            "detail": "OS version appears supported / current generation",
            "severity": "info",
        }
    return classify_product(os_name or "OS", version, banner=blob)


def _is_os_source(source: str) -> bool:
    s = (source or "").lower()
    return any(x in s for x in ("agent-os", "openaudit:os", "asset:os", ":os"))


def _host_patch_rollup(rows: list[dict[str, Any]]) -> tuple[str, str, int, int, int]:
    """Return patch_status, patch_label, issues, ok_count, unknown_count."""
    issues = sum(1 for r in rows if (r.get("status") or "").lower() in _ISSUE_STATUSES)
    ok = sum(1 for r in rows if (r.get("status") or "").lower() in _OK_STATUSES)
    unknown = sum(1 for r in rows if (r.get("status") or "").lower() == "unknown")
    total = len(rows)
    if not total:
        return "unknown", "No data", 0, 0, 0
    if issues > 0:
        return "needs_update", "Needs update", issues, ok, unknown
    if ok > 0 and unknown == 0:
        return "up_to_date", "Up to date", 0, ok, unknown
    if ok > 0:
        return "up_to_date", "Likely current", 0, ok, unknown
    return "unknown", "Unknown", 0, ok, unknown


def build_server_posture(user_id: str, rows: list[dict[str, Any]]) -> dict[str, Any]:
    """Per-server / system rollup — is this host patched and on a supported OS?"""
    from app.asset_categories import asset_category_id, category_label
    from app.enterprise import list_assets

    assets = list_assets(user_id)
    assets_by_id = {str(a.get("id") or ""): a for a in assets if a.get("id")}
    xdr_by_host = (_xdr_patch_summary().get("by_host") or {}) if rows else {}

    grouped: dict[str, dict[str, Any]] = {}

    def _ensure(key: str, *, asset_id: str = "", asset_name: str = "") -> dict[str, Any]:
        if key not in grouped:
            asset = assets_by_id.get(asset_id) or {}
            cat = asset_category_id(asset) if asset else "other"
            grouped[key] = {
                "asset_id": asset_id,
                "asset_name": asset_name or "Unknown host",
                "category": cat,
                "category_label": category_label(cat),
                "os_product": "",
                "os_version": "",
                "os_status": "unknown",
                "os_status_label": "Unknown",
                "products": [],
                "xdr_missing_patches": 0,
            }
        return grouped[key]

    for r in rows:
        aid = str(r.get("asset_id") or "")
        name = (r.get("asset_name") or "").strip() or "Unknown host"
        key = aid or name.lower()
        host = _ensure(key, asset_id=aid, asset_name=name)
        host["products"].append(r)
        src = (r.get("source") or "").lower()
        product = str(r.get("product") or "")
        if _is_os_source(src) or re.search(r"windows|linux|ubuntu|debian|centos|rhel|macos|server", product, re.I):
            if not host["os_product"] or _is_os_source(src):
                host["os_product"] = product
                host["os_version"] = str(r.get("version") or "")
                host["os_status"] = (r.get("status") or "unknown").lower()
                host["os_status_label"] = r.get("status_label") or status_label(host["os_status"])

    # Include inventoried servers with no software rows yet
    for asset in assets:
        cat = asset_category_id(asset)
        if cat not in _SERVER_CATEGORIES:
            continue
        aid = str(asset.get("id") or "")
        name = str(asset.get("display_name") or asset.get("name") or aid or "host")
        key = aid or name.lower()
        host = _ensure(key, asset_id=aid, asset_name=name)
        if not host["os_product"]:
            os_guess = str(asset.get("os") or "").strip()
            if os_guess:
                meta = classify_os(os_guess)
                host["os_product"] = os_guess
                host["os_status"] = meta.get("status") or "unknown"
                host["os_status_label"] = status_label(host["os_status"])

    servers: list[dict[str, Any]] = []
    summary = {"total": 0, "up_to_date": 0, "needs_update": 0, "unknown": 0}

    for host in grouped.values():
        cat = host.get("category") or "other"
        # Skip local SecuraIQ host row and non-system categories when empty
        if host["asset_name"] == "SecuraIQ host" and not host.get("asset_id"):
            continue
        prods = host.get("products") or []
        patch_st, patch_label, issues, ok, unknown = _host_patch_rollup(prods)
        xdr_missing = 0
        for hname, sevs in xdr_by_host.items():
            if hname.lower() in (host["asset_name"] or "").lower() or (host["asset_name"] or "").lower() in hname.lower():
                xdr_missing = sum(sevs.values()) if isinstance(sevs, dict) else 0
                break
        if xdr_missing and patch_st != "needs_update":
            patch_st, patch_label = "needs_update", "Missing patches (XDR)"
            issues = max(issues, xdr_missing)

        if patch_st == "up_to_date":
            summary["up_to_date"] += 1
        elif patch_st == "needs_update":
            summary["needs_update"] += 1
        else:
            summary["unknown"] += 1
        summary["total"] += 1

        issue_items = _sort_issues([p for p in prods if (p.get("status") or "").lower() in _ISSUE_STATUSES])[:5]
        servers.append(
            {
                **host,
                "patch_status": patch_st,
                "patch_label": patch_label,
                "issues_count": issues,
                "products_count": len(prods),
                "ok_count": ok,
                "unknown_count": unknown,
                "xdr_missing_patches": xdr_missing,
                "top_issues": issue_items,
            }
        )

    servers.sort(
        key=lambda s: (
            0 if s.get("patch_status") == "needs_update" else 1 if s.get("patch_status") == "unknown" else 2,
            -(s.get("issues_count") or 0),
            (s.get("asset_name") or "").lower(),
        )
    )
    return {"summary": summary, "servers": servers[:100]}


def classify_product(product: str, version: str = "", *, banner: str = "") -> dict[str, str]:
    candidates = [
        banner,
        " ".join(x for x in (product, version) if x).strip(),
        f"{product}/{version}".strip("/") if product and version else "",
        product,
    ]
    for label in candidates:
        if not label:
            continue
        hit = _classify_banner(label)
        if hit.get("status") != "unknown":
            return hit
    if version and re.match(r"^\d+\.\d+", version):
        return {
            "status": "current",
            "cve": "",
            "detail": "Version detected — no known EOL/CVE rule matched",
            "severity": "info",
        }
    return {"status": "unknown", "cve": "", "detail": "", "severity": "info"}


def _enrich_row(row: dict[str, Any]) -> dict[str, Any]:
    out = dict(row)
    st = (out.get("status") or "unknown").lower()
    out["status_label"] = status_label(st)
    out["status_class"] = STATUS_CLASS.get(st, "planned")
    out["source_label"] = source_label(out.get("source"))
    # Never fabricate latest version — only expose when we have a trusted source later.
    out.setdefault("latest_version", None)
    out.setdefault("latest_version_source", None)
    out.setdefault("version_checked_at", None)
    if out.get("updated_at"):
        out["last_seen"] = out["updated_at"]
    return out


def upsert_software_row(
    user_id: str,
    *,
    asset_id: str = "",
    asset_name: str = "",
    product: str,
    version: str = "",
    vendor: str = "",
    port: int | None = None,
    source: str = "scan",
    status: str = "",
    severity: str = "info",
    cve: str = "",
    detail: str = "",
) -> None:
    ensure_schema()
    product = (product or "").strip()[:200]
    if not product:
        return
    banner = f"{product}/{version}" if version else product
    if not status:
        meta = classify_product(product, version, banner=banner)
        status = meta.get("status") or "unknown"
        if not cve:
            cve = meta.get("cve") or ""
        if not detail:
            detail = meta.get("detail") or ""
        if severity == "info" and meta.get("severity"):
            severity = meta.get("severity") or "info"

    c = get_conn()
    ts = now()
    existing = c.execute(
        """
        SELECT id FROM asset_software
        WHERE user_id=? AND asset_id=? AND lower(product)=? AND coalesce(port,0)=? AND source=?
        """,
        (user_id, asset_id or "", product.lower(), port or 0, source),
    ).fetchone()
    fields = (
        asset_name[:200],
        version[:80],
        vendor[:120],
        port,
        status[:32],
        severity[:16],
        cve[:64],
        detail[:500],
        ts,
    )
    if existing:
        c.execute(
            """
            UPDATE asset_software SET asset_name=?, version=?, vendor=?, port=?,
            status=?, severity=?, cve=?, detail=?, updated_at=? WHERE id=?
            """,
            (*fields, existing["id"]),
        )
    else:
        c.execute(
            """
            INSERT INTO asset_software
            (id, user_id, asset_id, asset_name, product, version, vendor, port, source,
             status, severity, cve, detail, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                new_id(),
                user_id,
                asset_id or "",
                asset_name[:200],
                product,
                version[:80],
                vendor[:120],
                port,
                source,
                status[:32],
                severity[:16],
                cve[:64],
                detail[:500],
                ts,
            ),
        )
    c.commit()


def _parse_server_banner(banner: str) -> list[tuple[str, str]]:
    text = (banner or "").strip()
    if not text:
        return []
    out: list[tuple[str, str]] = []
    for m in _SERVER_BANNER_RE.finditer(text):
        product = (m.group("product") or "").strip()
        version = (m.group("version") or "").strip().rstrip("/")
        if product:
            out.append((product, version))
    if not out and text:
        # Generic "Name/1.2.3" fallback
        m = re.match(r"([A-Za-z][\w.\-]+)[/ ]+(\d+(?:\.\d+){0,3})", text)
        if m:
            out.append((m.group(1), m.group(2)))
    return out


def _extract_pkg_from_raw(raw: dict[str, Any]) -> tuple[str, str, str]:
    """Return (product, version, vendor) from heterogeneous vuln raw payloads."""
    if not isinstance(raw, dict):
        return "", "", ""
    # Trivy
    product = str(
        raw.get("PkgName")
        or raw.get("product")
        or raw.get("service")
        or raw.get("name")
        or raw.get("Package")
        or ""
    ).strip()
    version = str(
        raw.get("InstalledVersion")
        or raw.get("version")
        or raw.get("PackageVersion")
        or ""
    ).strip()
    vendor = str(raw.get("vendor") or raw.get("PkgPath") or raw.get("ecosystem") or "").strip()
    # Grype nested
    art = raw.get("artifact") if isinstance(raw.get("artifact"), dict) else {}
    if art:
        product = product or str(art.get("name") or "").strip()
        version = version or str(art.get("version") or "").strip()
    # Dependabot / OSV
    pkg = raw.get("package") if isinstance(raw.get("package"), dict) else {}
    if pkg:
        product = product or str(pkg.get("name") or pkg.get("ecosystem") or "").strip()
        version = version or str(pkg.get("version") or pkg.get("ecosystem") or "").strip()
    vuln = raw.get("vulnerability") if isinstance(raw.get("vulnerability"), dict) else {}
    if not product and vuln:
        product = str(vuln.get("package") or "").strip()
    return product[:200], version[:80], vendor[:120]


def ingest_from_scan_services(
    user_id: str,
    *,
    asset_id: str = "",
    asset_name: str = "",
    services: list[Any],
    scanner: str = "scan",
) -> int:
    n = 0
    for svc in services or []:
        if isinstance(svc, dict):
            port = svc.get("port")
            product = str(svc.get("product") or svc.get("service") or "").strip()
            version = str(svc.get("version") or "").strip()
            vendor = str(svc.get("vendor") or "").strip()
            banner = str(svc.get("banner") or svc.get("extrainfo") or "").strip()
        else:
            port = getattr(svc, "port", None)
            product = str(getattr(svc, "product", "") or getattr(svc, "service", "") or "").strip()
            version = str(getattr(svc, "version", "") or "").strip()
            vendor = ""
            banner = str(getattr(svc, "banner", "") or "").strip()
        if not product and banner:
            parsed = _parse_server_banner(banner)
            if parsed:
                product, version = parsed[0]
        if not product and not version:
            continue
        if not product:
            product = f"service:{port}" if port else "network-service"
        try:
            port_i = int(port) if port is not None else None
        except (TypeError, ValueError):
            port_i = None
        upsert_software_row(
            user_id,
            asset_id=asset_id,
            asset_name=asset_name,
            product=product,
            version=version,
            vendor=vendor,
            port=port_i,
            source=f"scan:{scanner}",
        )
        n += 1
    return n


def ingest_from_xdr(user_id: str) -> int:
    ensure_schema()
    c = get_conn()
    try:
        rows = c.execute(
            """
            SELECT vendor, host, title, severity, raw_json, external_id, kind
            FROM xdr_events
            WHERE status='open' AND kind IN ('patch_missing', 'vulnerability')
            ORDER BY updated_at DESC LIMIT 500
            """
        ).fetchall()
    except Exception:
        return 0
    n = 0
    for r in rows:
        host = (r["host"] or "").strip()
        title = (r["title"] or "").strip()
        kind = (r["kind"] or "").strip()
        desc = ""
        raw: dict[str, Any] = {}
        try:
            raw = json.loads(r["raw_json"] or "{}")
            if isinstance(raw, dict):
                desc = str(raw.get("description") or "").strip()
                if not desc:
                    inner = raw.get("raw") if isinstance(raw.get("raw"), dict) else raw
                    if isinstance(inner, dict):
                        vendor = inner.get("softwareVendor") or inner.get("software_vendor") or ""
                        version_hint = inner.get("softwareVersion") or inner.get("software_version") or ""
                        if vendor or version_hint:
                            desc = f"vendor={vendor} version={version_hint}".strip()
        except Exception:
            raw = {}
        product, version, vendor = _extract_pkg_from_raw(raw if isinstance(raw, dict) else {})
        if not product:
            product = title.split("—")[-1].strip() if "—" in title else title
        if not version:
            m = re.search(r"version=([^\s,]+)", desc)
            version = m.group(1) if m else ""
        cve_m = re.search(r"(CVE-\d{4}-\d+)", title)
        st = "missing_patch" if kind == "patch_missing" else "outdated"
        upsert_software_row(
            user_id,
            asset_name=host,
            product=product[:200] or ("missing-patch" if st == "missing_patch" else "vulnerability"),
            version=version,
            vendor=vendor or str(r["vendor"] or ""),
            source=f"xdr:{r['vendor']}",
            status=st,
            severity=(r["severity"] or "high")[:16],
            cve=cve_m.group(1) if cve_m else "",
            detail=(desc or title)[:500],
        )
        n += 1
    return n


def ingest_from_vulnerabilities(user_id: str) -> int:
    """Pull product/version from all vuln sources that carry package metadata."""
    from app.enterprise import list_vulnerabilities

    n = 0
    for v in list_vulnerabilities(user_id)[:500]:
        raw = v.get("raw") or {}
        if isinstance(raw, str):
            try:
                raw = json.loads(raw)
            except Exception:
                raw = {}
        if not isinstance(raw, dict):
            continue
        src = str(v.get("source") or "")
        if not _VULN_SOURCE_RE.search(src):
            continue
        product, version, vendor = _extract_pkg_from_raw(raw)
        port = raw.get("port")
        if not product and not version:
            # Hardening / cloud: treat finding title as control gap signal
            if re.search(r"hardening|cloud|cis", src, re.I):
                product = str(v.get("title") or "control-gap")[:200]
                version = ""
            else:
                continue
        try:
            port_i = int(port) if port is not None else None
        except (TypeError, ValueError):
            port_i = None
        sev = str(v.get("severity") or "medium").lower()
        meta = classify_product(product or "service", version, banner=f"{product}/{version}")
        st = meta.get("status") or "unknown"
        if st == "unknown" and (v.get("cve") or re.search(r"hardening|cloud|trivy|grype|dependabot", src, re.I)):
            st = "outdated" if v.get("cve") or re.search(r"trivy|grype|dependabot", src, re.I) else "missing_patch"
        src_root = "code" if re.search(r"trivy|grype|code|dependabot|osv|semgrep", src, re.I) else (
            "hardening" if re.search(r"hardening", src, re.I) else (
                "cloud" if re.search(r"cloud", src, re.I) else f"vuln:{src[:40]}"
            )
        )
        if src_root in {"code", "hardening", "cloud"}:
            source = f"{src_root}:{src[:48]}"
        else:
            source = src_root
        upsert_software_row(
            user_id,
            asset_id=str(v.get("asset_id") or ""),
            asset_name=str(v.get("asset_name") or v.get("display_asset_name") or ""),
            product=product or f"port-{port_i or '?'}",
            version=version,
            vendor=vendor,
            port=port_i,
            source=source[:80],
            status=st,
            severity=sev if st in {"outdated", "eol", "missing_patch"} else meta.get("severity") or "info",
            cve=str(v.get("cve") or meta.get("cve") or ""),
            detail=str(v.get("title") or meta.get("detail") or "")[:500],
        )
        n += 1
    return n


def ingest_from_asset_notes(user_id: str, asset: dict[str, Any]) -> int:
    from app.asset_names import parse_notes_meta

    meta = parse_notes_meta(asset.get("notes") or "")
    n = 0
    services = meta.get("services") or []
    if isinstance(services, list) and services:
        n += ingest_from_scan_services(
            user_id,
            asset_id=str(asset.get("id") or ""),
            asset_name=str(asset.get("name") or ""),
            services=services,
            scanner=str(meta.get("scanner") or "inventory"),
        )
    # OS from notes or asset fields
    os_name = str(meta.get("os") or asset.get("os") or "").strip()
    if os_name:
        ometa = classify_os(os_name)
        upsert_software_row(
            user_id,
            asset_id=str(asset.get("id") or ""),
            asset_name=str(asset.get("name") or asset.get("display_name") or ""),
            product=os_name.split("(")[0].strip()[:200] or "OS",
            version="",
            source="asset:os",
            status=ometa.get("status") or "unknown",
            severity=ometa.get("severity") or "info",
            cve=ometa.get("cve") or "",
            detail=(ometa.get("detail") or f"OS on asset {asset.get('name') or ''}")[:500],
        )
        n += 1
    # Technology fingerprints (strings like "OpenSSH 7.4", "nginx/1.18")
    techs = meta.get("technologies") or meta.get("tech") or []
    if isinstance(techs, str):
        techs = [t.strip() for t in techs.split(",") if t.strip()]
    if isinstance(techs, list):
        for t in techs[:40]:
            label = str(t or "").strip()
            if not label:
                continue
            parsed = _parse_server_banner(label)
            if parsed:
                product, version = parsed[0]
            else:
                parts = label.rsplit(" ", 1)
                if len(parts) == 2 and re.match(r"^\d+\.\d+", parts[1]):
                    product, version = parts[0], parts[1]
                else:
                    product, version = label, ""
            upsert_software_row(
                user_id,
                asset_id=str(asset.get("id") or ""),
                asset_name=str(asset.get("name") or ""),
                product=product,
                version=version,
                source="asset:tech",
            )
            n += 1
    return n


def ingest_from_wazuh_agents(user_id: str) -> int:
    try:
        from app.wazuh import list_agents
    except Exception:
        return 0
    n = 0
    for a in list_agents(limit=500):
        os_name = str(a.get("os") or "").strip()
        agent_ver = str(a.get("version") or "").strip()
        name = str(a.get("name") or a.get("ip") or "").strip()
        asset_id = str(a.get("asset_id") or "")
        if os_name:
            meta = classify_os(os_name)
            upsert_software_row(
                user_id,
                asset_id=asset_id,
                asset_name=name,
                product=os_name.split("|")[0].strip()[:200] or "OS",
                version="",
                vendor="wazuh",
                source="wazuh:agent-os",
                status=meta.get("status") or "unknown",
                severity=meta.get("severity") or "info",
                cve=meta.get("cve") or "",
                detail=(meta.get("detail") or f"Wazuh agent {a.get('agent_id') or ''}")[:500],
            )
            n += 1
        if agent_ver:
            upsert_software_row(
                user_id,
                asset_id=asset_id,
                asset_name=name,
                product="Wazuh agent",
                version=agent_ver,
                vendor="wazuh",
                source="wazuh:agent",
                status="current" if agent_ver else "unknown",
            )
            n += 1
    return n


def ingest_from_openaudit(user_id: str) -> int:
    try:
        from app.openaudit import list_devices
    except Exception:
        return 0
    n = 0
    for d in list_devices(limit=500):
        name = str(d.get("name") or d.get("hostname") or d.get("ip") or "").strip()
        asset_id = str(d.get("asset_id") or "")
        os_name = str(d.get("os") or "").strip()
        if os_name:
            meta = classify_os(os_name)
            upsert_software_row(
                user_id,
                asset_id=asset_id,
                asset_name=name,
                product=os_name[:200],
                version="",
                vendor=str((d.get("raw") or {}).get("manufacturer") or "")[:120],
                source="openaudit:os",
                status=meta.get("status") or "unknown",
                severity=meta.get("severity") or "info",
                cve=meta.get("cve") or "",
                detail=(meta.get("detail") or str(d.get("description") or ""))[:500],
            )
            n += 1
        raw = d.get("raw") if isinstance(d.get("raw"), dict) else {}
        # HTTP Server banners from live LAN audit
        http_rows = raw.get("http") if isinstance(raw.get("http"), list) else []
        model_banner = str(d.get("model") or raw.get("model") or "").strip()
        banners = [model_banner] if model_banner else []
        for h in http_rows:
            if isinstance(h, dict) and h.get("server"):
                banners.append(str(h["server"]))
        for banner in banners:
            for product, version in _parse_server_banner(banner):
                upsert_software_row(
                    user_id,
                    asset_id=asset_id,
                    asset_name=name,
                    product=product,
                    version=version,
                    source="lan:http",
                    detail=banner[:500],
                )
                n += 1
        # Open ports with known service names (best-effort)
        for p in (raw.get("open_ports") or d.get("open_ports") or [])[:30]:
            try:
                port_i = int(p)
            except (TypeError, ValueError):
                continue
            # skip anonymous ports — services already covered via scan ingest
            _ = port_i
    return n


def ingest_from_local_tools(user_id: str = "local") -> int:
    """SecuraIQ PATH scanner tools (nmap, nuclei…) — same machine, not remote hosts."""
    try:
        from app.tools import version_check as vc

        payload = getattr(vc, "_CACHE", {}).get("payload")
    except Exception:
        payload = None
    if not payload or not isinstance(payload, dict):
        return 0
    n = 0
    product = payload.get("product") or {}
    if product.get("version"):
        upsert_software_row(
            user_id,
            asset_name="SecuraIQ host",
            product="SecuraIQ",
            version=str(product.get("version") or ""),
            source="local:product",
            status="current",
            detail=str(product.get("commit") or "")[:500],
        )
        n += 1
    for t in payload.get("tools") or []:
        st = (t.get("status") or "unknown").lower()
        if st == "not_installed":
            continue
        mapped = {
            "outdated": "outdated",
            "up_to_date": "up_to_date",
            "installed": "installed",
            "unknown": "unknown",
        }.get(st, "unknown")
        upsert_software_row(
            user_id,
            asset_name="SecuraIQ host",
            product=str(t.get("name") or t.get("id") or "tool"),
            version=str(t.get("installed_version") or ""),
            source=f"local:{t.get('id') or 'tool'}",
            status=mapped,
            severity="medium" if mapped == "outdated" else "info",
            detail=(
                f"latest {t.get('latest_version')}" if t.get("latest_version") else "Local scanner tool"
            )[:500],
        )
        n += 1
    return n


def rebuild_for_user(user_id: str) -> dict[str, int]:
    from app.enterprise import list_assets

    ensure_schema()
    counts = {
        "assets": 0,
        "services": 0,
        "xdr": 0,
        "vulns": 0,
        "wazuh": 0,
        "openaudit": 0,
        "local_tools": 0,
        "local_os": 0,
        "control_panel": 0,
        "remote_os": 0,
    }
    for asset in list_assets(user_id):
        try:
            counts["services"] += ingest_from_asset_notes(user_id, asset)
        except Exception:
            pass
        counts["assets"] += 1
    for key, fn in (
        ("xdr", ingest_from_xdr),
        ("vulns", ingest_from_vulnerabilities),
        ("wazuh", ingest_from_wazuh_agents),
        ("openaudit", ingest_from_openaudit),
        ("local_tools", ingest_from_local_tools),
    ):
        try:
            counts[key] = fn(user_id)
        except Exception:
            counts[key] = 0
    try:
        import platform as _plat

        from app.os_patches import ingest_local_os_patches

        if (_plat.system() or "").lower() == "windows":
            counts["local_os"] = 0
        else:
            counts["local_os"] = int(ingest_local_os_patches(user_id).get("ingested") or 0)
    except Exception:
        counts["local_os"] = 0
    try:
        import platform as _plat

        from app.windows_inventory import refresh_local_windows_host

        if (_plat.system() or "").lower() == "windows":
            win = refresh_local_windows_host(user_id, force=True)
            counts["control_panel"] = int((win.get("control_panel") or {}).get("ingested") or 0)
            counts["windows_updates"] = int((win.get("windows_updates") or {}).get("ingested") or 0)
            counts["local_os"] = counts["windows_updates"]
        else:
            counts["control_panel"] = 0
    except Exception:
        counts["control_panel"] = 0
    try:
        from app.os_patches import ingest_remote_os_patches

        counts["remote_os"] = int(ingest_remote_os_patches(user_id).get("ingested") or 0)
    except Exception:
        counts["remote_os"] = 0
    try:
        from app.software.service import sync_inventory

        engine = sync_inventory(user_id, publish=False)
        counts["engine_products"] = int(engine.get("products") or 0)
        counts["engine_installations"] = int(engine.get("installations") or 0)
        counts["engine_sources"] = engine.get("sources") or {}
    except Exception:
        counts["engine_products"] = 0
        counts["engine_installations"] = 0
        counts["engine_sources"] = {}
    publish_software_realtime(user_id, counts)
    return counts


def publish_software_realtime(user_id: str, counts: dict[str, Any] | None = None, *, action: str = "sync", message: str = "") -> None:
    """Push software/patch posture to SSE clients (Software, Assets patch column, MC KPIs)."""
    try:
        from app.realtime_bus import publish

        posture = posture_summary(user_id, rebuild_if_empty=False)
        summary = posture.get("server_summary") or {}
        payload: dict[str, Any] = {
            "user_id": user_id,
            "issues": int(posture.get("issues") or 0),
            "health_score": int(posture.get("health_score") or 100),
            "needs_update": int(summary.get("needs_update") or 0),
            "up_to_date": int(summary.get("up_to_date") or 0),
            "unknown": int(summary.get("unknown") or 0),
            "total_products": int(posture.get("total_products") or 0),
            "hosts_with_issues": int(posture.get("hosts_with_issues") or 0),
            "action": action,
            "ts": now(),
        }
        if counts:
            payload.update(counts)
        if not message:
            total = int(payload.get("total_products") or 0)
            if action == "rebuild":
                message = f"Inventory rebuilt · {total} product(s) tracked"
            elif action == "vuln":
                message = f"Vulnerability data refreshed · {int(payload.get('issues') or 0)} gap(s)"
            elif counts and any(isinstance(v, int) and v > 0 for k, v in counts.items() if k not in ("engine_products", "engine_installations")):
                parts = [f"{k} +{v}" for k, v in counts.items() if isinstance(v, int) and v > 0 and not k.startswith("engine")]
                message = f"Sync complete · {total} product(s)" + (f" · {', '.join(parts[:3])}" if parts else "")
            else:
                message = f"Software inventory updated · {total} product(s)"
        payload["message"] = message
        publish(type="software_inventory", **payload)
    except Exception:
        pass


def queue_software_sync_jobs(user_id: str) -> list[dict[str, Any]]:
    """Queue SIEM/XDR/inventory sync jobs for software inventory refresh."""
    from app.jobs import enqueue_job

    queued: list[dict[str, Any]] = []

    def _queue(kind: str) -> None:
        try:
            j = enqueue_job(kind, {"user_id": user_id})
            if j and j.get("id"):
                queued.append({"kind": kind, "id": j.get("id"), "status": j.get("status")})
        except Exception:
            pass

    try:
        from app.connectors import wazuh as wz

        if wz.is_configured():
            _queue("wazuh_sync")
    except Exception:
        pass
    try:
        from app.xdr import status as xdr_st

        vendors = xdr_st() if callable(xdr_st) else {}
        if isinstance(vendors, dict) and any(
            (v or {}).get("configured") for v in vendors.values()
        ):
            _queue("xdr_sync")
    except Exception:
        pass
    try:
        from app.connectors import openaudit as oa

        if oa.is_configured():
            _queue("openaudit_sync")
    except Exception:
        pass
    return queued


def sync_all_and_rebuild(user_id: str, *, rebuild: bool = True) -> dict[str, Any]:
    """Queue SOC/inventory sync jobs, probe local OS patches, optionally rebuild inventory."""
    queued = queue_software_sync_jobs(user_id)

    local_os: dict[str, Any] = {"ingested": 0, "probe": {}}
    try:
        from app.os_patches import probe_local_os_patches

        local_os["probe"] = probe_local_os_patches()
    except Exception:
        pass

    rebuilt: dict[str, Any] = {}
    if rebuild:
        rebuilt = rebuild_for_user(user_id)
        local_os["ingested"] = int(rebuilt.get("local_os") or 0)
    posture = posture_summary(user_id, rebuild_if_empty=False)
    publish_software_realtime(user_id, {**(rebuilt or {}), "jobs_queued": len(queued)})
    return {
        "jobs_queued": queued,
        "local_os_patches": local_os,
        "rebuilt": rebuilt,
        "posture": posture,
    }


def refresh_after_sync(user_id: str, *sources: str) -> dict[str, int]:
    """Lightweight post-job refresh — only re-run named source ingestors."""
    ensure_schema()
    mapping = {
        "xdr": ingest_from_xdr,
        "wazuh": ingest_from_wazuh_agents,
        "openaudit": ingest_from_openaudit,
        "lan": ingest_from_openaudit,
        "vulns": ingest_from_vulnerabilities,
        "local": ingest_from_local_tools,
        "all": None,
    }
    if not sources or "all" in sources:
        return rebuild_for_user(user_id)
    out: dict[str, int] = {}
    for s in sources:
        fn = mapping.get(s)
        if not fn:
            continue
        try:
            out[s] = fn(user_id)
        except Exception:
            out[s] = 0
    publish_software_realtime(user_id, out)
    return out


def list_software(
    user_id: str,
    *,
    limit: int = 200,
    asset_id: str | None = None,
    status: str | None = None,
    source: str | None = None,
) -> list[dict[str, Any]]:
    ensure_schema()
    try:
        from app.software.models import ensure_schema as ensure_engine_schema
        from app.software.service import list_legacy_from_engine

        ensure_engine_schema()
        c = get_conn()
        n = c.execute(
            "SELECT COUNT(*) AS n FROM software_installations WHERE user_id=?",
            (user_id,),
        ).fetchone()
        if _scalar_int(n, "n", 0) > 0:
            engine_rows = [
                _enrich_row(r)
                for r in list_legacy_from_engine(
                    user_id,
                    limit=limit,
                    asset_id=asset_id,
                    status=status,
                    source=source,
                )
            ]
            extra = _list_asset_software(
                user_id, limit=limit, asset_id=asset_id, status=status, source=source
            )
            return _merge_software_rows(engine_rows, extra, limit)
    except Exception:
        pass
    return _list_asset_software(user_id, limit=limit, asset_id=asset_id, status=status, source=source)


def _software_row_key(row: dict[str, Any]) -> str:
    return "|".join(
        [
            str(row.get("asset_id") or ""),
            str(row.get("product") or "").lower(),
            str(row.get("version") or ""),
            str(row.get("source") or "").split(":")[0].lower(),
            str(row.get("port") or 0),
        ]
    )


def _merge_software_rows(primary: list[dict[str, Any]], extra: list[dict[str, Any]], limit: int) -> list[dict[str, Any]]:
    """Merge engine + asset_software rows; always reserve room for Control Panel / OS."""
    lim = max(1, min(int(limit or 200), 1500))
    priority: list[dict[str, Any]] = []
    rest: list[dict[str, Any]] = []
    for r in extra:
        src = str(r.get("source") or "").split(":")[0].lower()
        if src in {"control_panel", "os"}:
            priority.append(r)
        else:
            rest.append(r)
    reserve = min(len(priority), max(80, lim // 4))
    out = list(primary)
    if len(out) + reserve > lim:
        out = out[: max(0, lim - reserve)]
    seen = {_software_row_key(r) for r in out}
    for r in priority + rest:
        k = _software_row_key(r)
        if k in seen:
            continue
        seen.add(k)
        out.append(r)
        if len(out) >= lim:
            break
    return out


def _list_asset_software(
    user_id: str,
    *,
    limit: int = 200,
    asset_id: str | None = None,
    status: str | None = None,
    source: str | None = None,
) -> list[dict[str, Any]]:
    c = get_conn()
    q = "SELECT * FROM asset_software WHERE user_id=?"
    args: list[Any] = [user_id]
    if asset_id:
        q += " AND asset_id=?"
        args.append(asset_id)
    if status:
        q += " AND status=?"
        args.append(status.lower())
    if source:
        q += " AND (source=? OR source LIKE ?)"
        args.extend([source, f"{source}:%"])
    q += " ORDER BY updated_at DESC LIMIT ?"
    args.append(max(1, min(limit, 1500)))
    return [_enrich_row(dict(r)) for r in c.execute(q, args).fetchall()]


def _windows_host_for_posture(user_id: str | None = None) -> dict[str, Any]:
    try:
        from app.windows_inventory import windows_host_snapshot

        return windows_host_snapshot(user_id)
    except Exception:
        return dict(empty_posture()["windows_host"])


def _sort_issues(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    def key(r: dict[str, Any]) -> tuple[int, str]:
        st = (r.get("status") or "").lower()
        st_rank = {"missing_patch": 4, "eol": 3, "outdated": 2}.get(st, 0)
        sev = _SEV_WEIGHT.get((r.get("severity") or "info").lower(), 0)
        return (-st_rank, -sev, (r.get("product") or "").lower())

    return sorted(rows, key=key)


def posture_summary(user_id: str, *, rebuild_if_empty: bool = True) -> dict[str, Any]:
    ensure_schema()
    try:
        return _posture_summary_inner(user_id, rebuild_if_empty=rebuild_if_empty)
    except Exception:
        return empty_posture()


def _posture_summary_inner(user_id: str, *, rebuild_if_empty: bool = True) -> dict[str, Any]:
    c = get_conn()
    n = c.execute("SELECT COUNT(*) AS n FROM asset_software WHERE user_id=?", (user_id,)).fetchone()
    if rebuild_if_empty and _scalar_int(n, "n", 0) == 0:
        try:
            rebuild_for_user(user_id)
        except Exception:
            pass

    rows = [
        _enrich_row(dict(r))
        for r in c.execute(
            """
            SELECT id, asset_id, status, severity, asset_name, product, version, cve, detail, source, port, updated_at
            FROM asset_software WHERE user_id=? ORDER BY updated_at DESC LIMIT 1500
            """,
            (user_id,),
        ).fetchall()
    ]

    counts = {
        "current": 0,
        "up_to_date": 0,
        "outdated": 0,
        "eol": 0,
        "missing_patch": 0,
        "unknown": 0,
        "installed": 0,
    }
    hosts: set[str] = set()
    by_source: dict[str, int] = {}
    by_source_label: dict[str, int] = {}
    issue_rows: list[dict[str, Any]] = []

    for r in rows:
        st = (r.get("status") or "unknown").lower()
        if st not in counts:
            st = "unknown"
        counts[st] = counts.get(st, 0) + 1
        src = (r.get("source") or "scan").split(":")[0]
        by_source[src] = by_source.get(src, 0) + 1
        lab = source_label(r.get("source"))
        by_source_label[lab] = by_source_label.get(lab, 0) + 1
        if st in {"outdated", "eol", "missing_patch"}:
            an = (r.get("asset_name") or "").strip()
            if an:
                hosts.add(an.lower())
            issue_rows.append(r)

    issues_sorted = _sort_issues(issue_rows)
    total = sum(counts.values())
    issues = counts["outdated"] + counts["eol"] + counts["missing_patch"]
    ok = counts["current"] + counts.get("up_to_date", 0) + counts.get("installed", 0)
    health = round((ok / total) * 100) if total else 100
    remote_ssh = sum(1 for r in rows if "ssh" in (r.get("source") or ""))
    try:
        server_posture = build_server_posture(user_id, rows)
    except Exception:
        server_posture = empty_posture()["server_posture"]

    return {
        "total_products": total,
        "counts": counts,
        "issues": issues,
        "healthy": ok,
        "health_score": health,
        "hosts_with_issues": len(hosts),
        "top_issues": issues_sorted[:20],
        "inventory": rows[:60],
        "by_source": by_source,
        "by_source_label": by_source_label,
        "source_labels": SOURCE_LABELS,
        "patch_compliance": _xdr_patch_summary(),
        "status_labels": STATUS_LABELS,
        "server_posture": server_posture,
        "server_summary": server_posture.get("summary") or {},
        "servers": server_posture.get("servers") or [],
        "coverage": {
            "scans": by_source.get("scan", 0) + by_source.get("vuln", 0),
            "xdr": by_source.get("xdr", 0),
            "siem": by_source.get("wazuh", 0) + by_source.get("siem", 0),
            "inventory": by_source.get("openaudit", 0) + by_source.get("lan", 0) + by_source.get("asset", 0),
            "code": by_source.get("code", 0),
            "local_tools": by_source.get("local", 0),
            "hardening": by_source.get("hardening", 0),
            "cloud": by_source.get("cloud", 0),
            "os_patches": by_source.get("os", 0),
            "control_panel": by_source.get("control_panel", 0),
            "remote_ssh": remote_ssh,
        },
        "windows_host": _windows_host_for_posture(user_id),
    }


def _xdr_patch_summary() -> dict[str, Any]:
    try:
        from app.xdr import patch_compliance_summary

        return patch_compliance_summary()
    except Exception:
        return {"total_missing_patches": 0, "hosts_with_gaps": 0, "by_host": {}}


def _find_server_posture(
    user_id: str, *, asset_id: str = "", asset_name: str = ""
) -> dict[str, Any] | None:
    posture = posture_summary(user_id, rebuild_if_empty=False)
    aid = (asset_id or "").strip()
    name = (asset_name or "").strip().lower()
    for s in posture.get("servers") or []:
        if aid and str(s.get("asset_id") or "") == aid:
            return s
        if name and (s.get("asset_name") or "").strip().lower() == name:
            return s
    return None


def build_remediation_for_server(
    user_id: str, *, asset_id: str = "", asset_name: str = ""
) -> dict[str, str]:
    """Draft gap remediation title/recommendation for a server patch gap."""
    host = _find_server_posture(user_id, asset_id=asset_id, asset_name=asset_name)
    label = (host or {}).get("asset_name") or asset_name or asset_id or "Unknown host"
    issues = (host or {}).get("issues_count") or 0
    patch_label = (host or {}).get("patch_label") or "Needs update"
    os_line = ""
    if host:
        os_bits = [host.get("os_product") or "", host.get("os_version") or ""]
        os_line = " ".join(x for x in os_bits if x).strip()
    top = [str(i.get("product") or "?") for i in ((host or {}).get("top_issues") or [])[:5]]
    xdr = int((host or {}).get("xdr_missing_patches") or 0)
    rec_parts = [f"Patch posture: {patch_label}."]
    if os_line:
        rec_parts.append(f"OS: {os_line}.")
    if issues:
        rec_parts.append(f"{issues} software issue(s) detected.")
    if xdr:
        rec_parts.append(f"{xdr} XDR-reported missing patch(es).")
    if top:
        rec_parts.append(f"Top gaps: {', '.join(top)}.")
    rec_parts.append("Apply OS updates, vendor patches, and re-run Software sync.")
    return {
        "title": f"Patch server: {label}"[:300],
        "recommendation": " ".join(rec_parts)[:2000],
        "control_id": "PATCH",
    }


def export_software_markdown(user_id: str) -> str:
    posture = posture_summary(user_id, rebuild_if_empty=False)
    servers = posture.get("servers") or []
    summary = posture.get("server_summary") or {}
    lines = [
        "# Software & Patch Inventory",
        "",
        f"Products tracked: **{posture.get('total_products', 0)}** · "
        f"Issues: **{posture.get('issues', 0)}** · Health: **{posture.get('health_score', 100)}%**",
        "",
        "## Server patch posture",
        "",
        f"Systems: **{summary.get('total', 0)}** · Up to date: **{summary.get('up_to_date', 0)}** · "
        f"Needs update: **{summary.get('needs_update', 0)}** · Unknown: **{summary.get('unknown', 0)}**",
        "",
        "| Patch status | Host | OS | Issues | Products | Top gaps |",
        "|---|---|---|---:|---:|---|",
    ]
    for s in servers:
        os_bits = " ".join(x for x in (s.get("os_product") or "", s.get("os_version") or "") if x).strip() or "—"
        gaps = ", ".join(str(i.get("product") or "?") for i in (s.get("top_issues") or [])[:3]) or "—"
        lines.append(
            f"| {s.get('patch_label') or s.get('patch_status') or '?'} | {s.get('asset_name') or '—'} | "
            f"{os_bits} | {s.get('issues_count') or 0} | {s.get('products_count') or 0} | {gaps} |"
        )
    rows = list_software(user_id, limit=500)
    lines += ["", "## All products", "", "| Status | Product | Version | Host | CVE | Source |", "|---|---|---|---|---|---|"]
    for r in rows:
        lines.append(
            f"| {r.get('status_label') or r.get('status') or '?'} | {r.get('product') or '?'} | "
            f"{r.get('version') or '—'} | {r.get('asset_name') or '—'} | {r.get('cve') or '—'} | "
            f"{r.get('source_label') or r.get('source') or '—'} |"
        )
    lines += ["", "---", "_SecuraIQ software & patch inventory export._"]
    return "\n".join(lines)


def export_software_csv(user_id: str) -> str:
    import csv
    import io

    rows = list_software(user_id, limit=500)
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(
        ["status", "product", "version", "host", "port", "cve", "severity", "source", "detail", "updated_at"]
    )
    for r in rows:
        writer.writerow(
            [
                r.get("status") or "",
                r.get("product") or "",
                r.get("version") or "",
                r.get("asset_name") or "",
                r.get("port") or "",
                r.get("cve") or "",
                r.get("severity") or "",
                r.get("source_label") or r.get("source") or "",
                r.get("detail") or "",
                r.get("updated_at") or "",
            ]
        )
    return buf.getvalue()
