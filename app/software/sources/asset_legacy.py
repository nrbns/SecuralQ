"""Bridge legacy asset_software rows into normalized inventory."""

from __future__ import annotations

from typing import Any

from app.db import get_conn, now
from app.software.models import InstallationRecord, PATCH_UNKNOWN
from app.software.sources.base import InventorySource, register_source


@register_source
class AssetLegacySource(InventorySource):
    key = "legacy"
    label = "SecuraIQ inventory"

    def health(self, user_id: str) -> dict[str, Any]:
        c = get_conn()
        try:
            row = c.execute("SELECT COUNT(*) AS n FROM asset_software WHERE user_id=?", (user_id,)).fetchone()
            n = int(row["n"] if row and hasattr(row, "keys") else (row[0] if row else 0))
        except Exception:
            n = 0
        return {"key": self.key, "label": self.label, "configured": True, "healthy": True, "items": n}

    def collect(self, user_id: str) -> list[InstallationRecord]:
        c = get_conn()
        out: list[InstallationRecord] = []
        try:
            db_rows = c.execute(
                """
                SELECT asset_id, asset_name, product, version, vendor, port, source, status, severity, cve, detail, updated_at
                FROM asset_software WHERE user_id=? ORDER BY updated_at DESC LIMIT 1200
                """,
                (user_id,),
            ).fetchall()
        except Exception:
            return out
        seen: set[str] = set()
        for r in db_rows:
            d = dict(r)
            src = str(d.get("source") or "legacy").split(":")[0]
            if src in {"scan", "vuln", "nmap", "nuclei", "zap", "securaiq"}:
                continue  # scan source handles these
            if src in {"wazuh", "siem"}:
                continue
            if src in {"openaudit", "lan"}:
                continue
            if src in {"control_panel"}:
                continue
            key = f"{d.get('asset_id')}|{d.get('product','').lower()}|{d.get('port') or 0}|{src}"
            if key in seen:
                continue
            seen.add(key)
            root = src or "legacy"
            out.append(
                InstallationRecord(
                    asset_id=str(d.get("asset_id") or ""),
                    asset_name=str(d.get("asset_name") or ""),
                    product=str(d.get("product") or ""),
                    version=str(d.get("version") or ""),
                    vendor=str(d.get("vendor") or ""),
                    source=root,
                    source_id=str(d.get("source") or root),
                    last_seen=float(d.get("updated_at") or now()),
                    port=int(d["port"]) if d.get("port") else None,
                    raw_status=str(d.get("status") or "unknown"),
                    severity=str(d.get("severity") or "info"),
                    cve=str(d.get("cve") or ""),
                    detail=str(d.get("detail") or ""),
                    patch_status=PATCH_UNKNOWN,
                )
            )
        return out
