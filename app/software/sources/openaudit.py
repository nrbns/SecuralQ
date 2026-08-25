"""Open-AudIT / LAN inventory devices."""

from __future__ import annotations

import re
from typing import Any

from app.db import now
from app.software.models import InstallationRecord, PATCH_UNKNOWN
from app.software.sources.base import InventorySource, register_source


@register_source
class OpenAuditSource(InventorySource):
    key = "openaudit"
    label = "Open-AudIT"

    def health(self, user_id: str) -> dict[str, Any]:
        try:
            from app.openaudit import status

            st = status()
            return {
                "key": self.key,
                "label": self.label,
                "configured": bool(st.get("configured")),
                "healthy": bool(st.get("configured")),
                "devices_cached": int(st.get("devices_cached") or 0),
            }
        except Exception as exc:
            return {"key": self.key, "label": self.label, "configured": False, "healthy": False, "error": str(exc)[:200]}

    def collect(self, user_id: str) -> list[InstallationRecord]:
        from app.software_inventory import classify_os, classify_product

        rows: list[InstallationRecord] = []
        try:
            from app.openaudit import list_devices
        except Exception:
            return rows

        ts = now()
        banner_re = re.compile(
            r"(?P<product>Apache|nginx|Microsoft-IIS|IIS|OpenSSH|OpenSSL|MariaDB|MySQL|PostgreSQL|Redis)"
            r"[/\s]*(?P<version>\d+(?:\.\d+){0,3}[^\s,]*)?",
            re.I,
        )
        for d in list_devices(limit=500):
            name = str(d.get("name") or d.get("hostname") or d.get("ip") or "").strip()
            asset_id = str(d.get("asset_id") or "")
            os_name = str(d.get("os") or "").strip()
            if os_name:
                meta = classify_os(os_name)
                rows.append(
                    InstallationRecord(
                        asset_id=asset_id,
                        asset_name=name,
                        product=os_name[:200],
                        version="",
                        vendor=str((d.get("raw") or {}).get("manufacturer") or "")[:120],
                        source="openaudit",
                        source_id=f"os:{d.get('device_id') or name}",
                        last_seen=ts,
                        raw_status=meta.get("status") or "unknown",
                        severity=meta.get("severity") or "info",
                        cve=meta.get("cve") or "",
                        detail=(meta.get("detail") or str(d.get("description") or ""))[:500],
                    )
                )
            raw = d.get("raw") if isinstance(d.get("raw"), dict) else {}
            for banner in self._banners(d, raw):
                for m in banner_re.finditer(banner):
                    product = m.group("product")
                    version = m.group("version") or ""
                    meta = classify_product(product, version, banner=banner)
                    rows.append(
                        InstallationRecord(
                            asset_id=asset_id,
                            asset_name=name,
                            product=product,
                            version=version,
                            source="openaudit",
                            source_id=f"banner:{hash(banner) & 0xFFFFFF}",
                            last_seen=ts,
                            raw_status=meta.get("status") or "unknown",
                            severity=meta.get("severity") or "info",
                            cve=meta.get("cve") or "",
                            detail=banner[:500],
                            patch_status=PATCH_UNKNOWN,
                        )
                    )
        return rows

    @staticmethod
    def _banners(d: dict, raw: dict) -> list[str]:
        out: list[str] = []
        model = str(d.get("model") or raw.get("model") or "").strip()
        if model:
            out.append(model)
        for h in raw.get("http") or []:
            if isinstance(h, dict) and h.get("server"):
                out.append(str(h["server"]))
        return out
