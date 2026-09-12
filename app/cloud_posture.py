"""Cloud posture orchestration — AWS Security Hub / Azure Defender / GCP SCC."""

from __future__ import annotations

import json
from typing import Any

from app.config import settings
from app.connectors import aws_security_hub, azure_defender_cloud, gcp_scc
from app.db import get_conn, new_id, now
from app.enterprise import create_vulnerability

VENDORS = {
    "aws_security_hub": aws_security_hub,
    "azure_defender": azure_defender_cloud,
    "gcp_scc": gcp_scc,
}


def ensure_schema() -> None:
    c = get_conn()
    c.execute(
        """
        CREATE TABLE IF NOT EXISTS cloud_findings (
            id TEXT PRIMARY KEY,
            vendor TEXT NOT NULL,
            finding_id TEXT NOT NULL,
            title TEXT NOT NULL DEFAULT '',
            severity TEXT NOT NULL DEFAULT '',
            status TEXT NOT NULL DEFAULT '',
            resource TEXT NOT NULL DEFAULT '',
            vuln_id TEXT NOT NULL DEFAULT '',
            raw_json TEXT NOT NULL DEFAULT '{}',
            updated_at REAL NOT NULL,
            UNIQUE(vendor, finding_id)
        )
        """
    )
    c.commit()


def status() -> dict[str, Any]:
    ensure_schema()
    vendors = {}
    for name, mod in VENDORS.items():
        vendors[name] = {"configured": bool(mod.is_configured())}
    cached = 0
    try:
        row = get_conn().execute("SELECT COUNT(*) AS n FROM cloud_findings").fetchone()
        cached = int(row["n"] if row else 0)
    except Exception:
        cached = 0
    return {
        "vendors": vendors,
        "configured_count": sum(1 for v in vendors.values() if v["configured"]),
        "findings_cached": cached,
        "aws_region": (settings.aws_region or "") or None,
    }


async def ping_all() -> dict[str, Any]:
    out = {}
    for name, mod in VENDORS.items():
        if mod.is_configured():
            out[name] = await mod.ping()
        else:
            out[name] = {"ok": False, "error": "not_configured"}
    return out


def _upsert_finding(item: dict[str, Any], user_id: str) -> str:
    ensure_schema()
    vendor = item.get("source") or item.get("vendor") or "cloud"
    fid = str(item.get("id") or "")
    if not fid:
        return ""
    c = get_conn()
    ts = now()
    row = c.execute(
        "SELECT vuln_id FROM cloud_findings WHERE vendor = ? AND finding_id = ?",
        (vendor, fid),
    ).fetchone()
    vuln_id = (row["vuln_id"] if row else "") or ""
    if not vuln_id:
        sev = (item.get("severity") or "medium").lower()
        if sev == "informational":
            sev = "low"
        v = create_vulnerability(
            user_id,
            {
                "cve": "",
                "title": f"[{vendor}] {item.get('title') or fid}"[:240],
                "severity": sev if sev in {"critical", "high", "medium", "low"} else "medium",
                "status": "open",
                "source": vendor,
                "asset_name": (item.get("resource") or "")[:200],
                "raw": item,
            },
        )
        vuln_id = v.get("id") or ""
    pk = new_id()
    c.execute(
        """
        INSERT INTO cloud_findings
        (id, vendor, finding_id, title, severity, status, resource, vuln_id, raw_json, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(vendor, finding_id) DO UPDATE SET
          title=excluded.title,
          severity=excluded.severity,
          status=excluded.status,
          resource=excluded.resource,
          vuln_id=CASE WHEN excluded.vuln_id != '' THEN excluded.vuln_id ELSE cloud_findings.vuln_id END,
          raw_json=excluded.raw_json,
          updated_at=excluded.updated_at
        """,
        (
            pk,
            vendor,
            fid,
            item.get("title") or "",
            item.get("severity") or "",
            item.get("status") or "",
            item.get("resource") or "",
            vuln_id,
            json.dumps(item)[:8000],
            ts,
        ),
    )
    c.commit()
    return vuln_id


async def sync_all(user_id: str = "local") -> dict[str, Any]:
    ensure_schema()
    summary: dict[str, Any] = {"vendors": {}, "imported": 0}
    for name, mod in VENDORS.items():
        if not mod.is_configured():
            summary["vendors"][name] = {"skipped": True}
            continue
        try:
            findings = await mod.fetch_findings(limit=60)
            for f in findings:
                f.setdefault("source", name)
                _upsert_finding(f, user_id)
            summary["vendors"][name] = {"ok": True, "count": len(findings)}
            summary["imported"] += len(findings)
        except Exception as exc:  # noqa: BLE001
            summary["vendors"][name] = {"ok": False, "error": str(exc)[:300]}
    try:
        from app.realtime_bus import publish

        publish(type="cloud", imported=summary.get("imported") or 0)
    except Exception:
        pass
    return summary


def import_findings(user_id: str, findings: list[dict[str, Any]], vendor: str = "cloud_import") -> dict[str, Any]:
    """Lab path: import normalized findings JSON without live cloud creds."""
    ensure_schema()
    n = 0
    for raw in findings[:500]:
        item = {
            "id": str(raw.get("id") or raw.get("finding_id") or new_id()),
            "title": raw.get("title") or "Cloud finding",
            "severity": raw.get("severity") or "medium",
            "status": raw.get("status") or "open",
            "source": raw.get("source") or vendor,
            "resource": raw.get("resource") or "",
        }
        _upsert_finding(item, user_id)
        n += 1
    out = {"imported": n, "vendor": vendor}
    try:
        from app.realtime_bus import publish

        publish(type="cloud", imported=n, vendor=vendor)
    except Exception:
        pass
    return out


def clear_cached_findings(*, delete_linked_vulns: bool = True, user_id: str = "local") -> dict[str, Any]:
    """Lab clear: wipe cloud_findings cache and optionally linked register rows."""
    ensure_schema()
    c = get_conn()
    vuln_ids: list[str] = []
    if delete_linked_vulns:
        rows = c.execute(
            "SELECT DISTINCT vuln_id FROM cloud_findings WHERE vuln_id != ''"
        ).fetchall()
        vuln_ids = [str(r["vuln_id"] if hasattr(r, "keys") else r[0]) for r in rows if r]
    cur = c.execute("DELETE FROM cloud_findings")
    cleared = int(cur.rowcount or 0)
    c.commit()
    vulns_deleted = 0
    if delete_linked_vulns and vuln_ids:
        try:
            from app.enterprise import delete_vulnerability

            for vid in vuln_ids:
                if delete_vulnerability(user_id, vid):
                    vulns_deleted += 1
        except Exception:
            pass
    try:
        from app.realtime_bus import publish

        publish(
            type="cloud",
            action="clear",
            cleared=cleared,
            vulns_deleted=vulns_deleted,
            user_id=user_id,
        )
        if vulns_deleted:
            publish(type="vuln_batch", source="cloud", action="clear", count=vulns_deleted, user_id=user_id)
    except Exception:
        pass
    return {"ok": True, "cleared": cleared, "vulns_deleted": vulns_deleted}


def list_findings(limit: int = 50, vendor: str | None = None) -> list[dict[str, Any]]:
    ensure_schema()
    if vendor:
        rows = get_conn().execute(
            """
            SELECT vendor, finding_id, title, severity, status, resource, vuln_id, updated_at
            FROM cloud_findings WHERE vendor = ? ORDER BY updated_at DESC LIMIT ?
            """,
            (vendor, max(1, min(limit, 200))),
        ).fetchall()
    else:
        rows = get_conn().execute(
            """
            SELECT vendor, finding_id, title, severity, status, resource, vuln_id, updated_at
            FROM cloud_findings ORDER BY updated_at DESC LIMIT ?
            """,
            (max(1, min(limit, 200)),),
        ).fetchall()
    return [dict(r) for r in rows]
