"""Network scan / Nmap / Nuclei derived software from asset_software."""

from __future__ import annotations

from typing import Any

from app.db import get_conn, now
from app.software.models import InstallationRecord, PATCH_UNKNOWN
from app.software.sources.base import InventorySource, register_source


@register_source
class ScanSource(InventorySource):
    key = "scan"
    label = "Network scan"

    def health(self, user_id: str) -> dict[str, Any]:
        c = get_conn()
        try:
            row = c.execute(
                "SELECT COUNT(*) AS n FROM asset_software WHERE user_id=? AND (source LIKE 'scan%' OR source LIKE 'vuln%' OR source LIKE 'nmap%' OR source LIKE 'nuclei%')",
                (user_id,),
            ).fetchone()
            n = int(row["n"] if row and hasattr(row, "keys") else (row[0] if row else 0))
        except Exception:
            n = 0
        return {"key": self.key, "label": self.label, "configured": True, "healthy": n >= 0, "items": n}

    def collect(self, user_id: str) -> list[InstallationRecord]:
        c = get_conn()
        rows: list[InstallationRecord] = []
        try:
            db_rows = c.execute(
                """
                SELECT asset_id, asset_name, product, version, vendor, port, source, status, severity, cve, detail, updated_at
                FROM asset_software
                WHERE user_id=? AND (
                    source LIKE 'scan%' OR source LIKE 'vuln%' OR source LIKE 'nmap%'
                    OR source LIKE 'nuclei%' OR source LIKE 'zap%' OR source LIKE 'securaiq%'
                )
                ORDER BY updated_at DESC LIMIT 800
                """,
                (user_id,),
            ).fetchall()
        except Exception:
            return rows
        for r in db_rows:
            d = dict(r)
            rows.append(
                InstallationRecord(
                    asset_id=str(d.get("asset_id") or ""),
                    asset_name=str(d.get("asset_name") or ""),
                    product=str(d.get("product") or ""),
                    version=str(d.get("version") or ""),
                    vendor=str(d.get("vendor") or ""),
                    source="scan",
                    source_id=str(d.get("source") or "scan"),
                    last_seen=float(d.get("updated_at") or now()),
                    port=int(d["port"]) if d.get("port") else None,
                    raw_status=str(d.get("status") or "unknown"),
                    severity=str(d.get("severity") or "info"),
                    cve=str(d.get("cve") or ""),
                    detail=str(d.get("detail") or ""),
                    patch_status=PATCH_UNKNOWN,
                )
            )
        return rows
