"""Wazuh SIEM — agents + syscollector packages when available."""

from __future__ import annotations

import json
from typing import Any

from app.db import get_conn, now
from app.software.models import InstallationRecord, PATCH_UNKNOWN
from app.software.sources.base import InventorySource, register_source


@register_source
class WazuhSource(InventorySource):
    key = "wazuh"
    label = "Wazuh"

    def health(self, user_id: str) -> dict[str, Any]:
        try:
            from app.wazuh import status

            st = status()
            return {
                "key": self.key,
                "label": self.label,
                "configured": bool(st.get("configured")),
                "healthy": bool(st.get("configured")),
                "indexer": bool(st.get("indexer_configured")),
            }
        except Exception as exc:
            return {
                "key": self.key,
                "label": self.label,
                "configured": False,
                "healthy": False,
                "error": str(exc)[:200],
            }

    def collect(self, user_id: str) -> list[InstallationRecord]:
        from app.software_inventory import classify_os

        rows: list[InstallationRecord] = []
        try:
            from app.wazuh import list_agents
        except Exception:
            return rows

        ts = now()
        for a in list_agents(limit=500):
            os_name = str(a.get("os") or "").strip()
            agent_ver = str(a.get("version") or "").strip()
            name = str(a.get("name") or a.get("ip") or "").strip()
            asset_id = str(a.get("asset_id") or "")
            agent_id = str(a.get("agent_id") or "")
            if os_name:
                meta = classify_os(os_name)
                rows.append(
                    InstallationRecord(
                        asset_id=asset_id,
                        asset_name=name,
                        product=os_name.split("|")[0].strip()[:200] or "OS",
                        version="",
                        vendor="wazuh",
                        publisher="wazuh",
                        source="wazuh",
                        source_id=f"agent-os:{agent_id}",
                        last_seen=ts,
                        raw_status=meta.get("status") or "unknown",
                        severity=meta.get("severity") or "info",
                        cve=meta.get("cve") or "",
                        detail=(meta.get("detail") or f"Wazuh agent {agent_id}")[:500],
                    )
                )
            if agent_ver:
                rows.append(
                    InstallationRecord(
                        asset_id=asset_id,
                        asset_name=name,
                        product="Wazuh agent",
                        version=agent_ver,
                        vendor="wazuh",
                        source="wazuh",
                        source_id=f"agent:{agent_id}",
                        last_seen=ts,
                        raw_status="current",
                        patch_status=PATCH_UNKNOWN,
                    )
                )
            rows.extend(self._packages_for_agent(agent_id, asset_id, name, ts))
        return rows

    def _packages_for_agent(
        self, agent_id: str, asset_id: str, asset_name: str, ts: float
    ) -> list[InstallationRecord]:
        if not agent_id:
            return []
        c = get_conn()
        try:
            row = c.execute(
                "SELECT packages_json, updated_at FROM wazuh_syscollector WHERE agent_id=? ORDER BY updated_at DESC LIMIT 1",
                (agent_id,),
            ).fetchone()
        except Exception:
            return []
        if not row:
            return []
        try:
            packages = json.loads(row["packages_json"] if hasattr(row, "keys") else row[0] or "[]")
        except Exception:
            packages = []
        if not isinstance(packages, list):
            return []
        last = float(row["updated_at"] if hasattr(row, "keys") else row[1] or ts)
        out: list[InstallationRecord] = []
        for pkg in packages[:500]:
            if not isinstance(pkg, dict):
                continue
            product = str(pkg.get("name") or pkg.get("package") or "").strip()
            if not product:
                continue
            out.append(
                InstallationRecord(
                    asset_id=asset_id,
                    asset_name=asset_name,
                    product=product,
                    version=str(pkg.get("version") or "")[:80],
                    vendor=str(pkg.get("vendor") or pkg.get("publisher") or "")[:120],
                    publisher=str(pkg.get("publisher") or pkg.get("vendor") or "")[:120],
                    architecture=str(pkg.get("architecture") or pkg.get("arch") or "")[:32],
                    install_path=str(pkg.get("location") or pkg.get("install_time") or "")[:200],
                    source="wazuh",
                    source_id=f"syscollector:{agent_id}:{product.lower()[:40]}",
                    last_seen=last,
                    install_date=str(pkg.get("install_time") or "")[:40],
                    patch_status=PATCH_UNKNOWN,
                )
            )
        return out
