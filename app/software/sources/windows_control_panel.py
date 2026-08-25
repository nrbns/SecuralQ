"""Windows Control Panel installed software (local SecuraIQ host)."""

from __future__ import annotations

from typing import Any

from app.db import now
from app.software.models import InstallationRecord, PATCH_UNKNOWN
from app.software.sources.base import InventorySource, register_source
from app.windows_inventory import probe_windows_control_panel


@register_source
class WindowsControlPanelSource(InventorySource):
    key = "control_panel"
    label = "Control Panel"

    def health(self, user_id: str) -> dict[str, Any]:
        import platform

        from app.db import get_conn

        windows = (platform.system() or "").lower() == "windows"
        n = 0
        try:
            row = get_conn().execute(
                "SELECT COUNT(*) AS n FROM asset_software WHERE user_id=? AND source LIKE 'control_panel%'",
                (user_id,),
            ).fetchone()
            n = int(row["n"] if row and hasattr(row, "keys") else (row[0] if row else 0))
        except Exception:
            n = 0
        return {
            "key": self.key,
            "label": self.label,
            "configured": windows,
            "healthy": windows,
            "items": n,
        }

    def collect(self, user_id: str) -> list[InstallationRecord]:
        probe = probe_windows_control_panel(force=False)
        if not (probe.get("programs") or []) and (probe.get("platform") or "").lower() == "windows":
            probe = probe_windows_control_panel(force=True)
        host = str(probe.get("host") or "SecuraIQ host")
        ts = now()
        rows: list[InstallationRecord] = []
        for app in probe.get("programs") or []:
            name = str(app.get("name") or "").strip()
            if not name:
                continue
            when = str(app.get("install_date") or "").strip()
            publisher = str(app.get("publisher") or "").strip()
            rows.append(
                InstallationRecord(
                    asset_id="",
                    asset_name=host,
                    product=name,
                    version=str(app.get("version") or ""),
                    vendor=publisher,
                    source="control_panel",
                    source_id="control_panel:uninstall",
                    last_seen=ts,
                    raw_status="installed",
                    detail=("Control Panel" + (f" · {publisher}" if publisher else "") + (f" · installed {when}" if when else "")),
                    patch_status=PATCH_UNKNOWN,
                )
            )
        return rows
