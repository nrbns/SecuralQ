"""SecuraIQ SBOM — branded surface over software inventory.

Honesty: CycloneDX-ish export from existing inventory rows — not a separate
Syft/scanner engine. Lab-production productization of wired inventory.
"""

from __future__ import annotations

import json
from typing import Any

from app.db import now


def sbom_status(user_id: str) -> dict[str, Any]:
    from app.software_inventory import list_software, posture_summary

    rows = list_software(user_id, limit=5)
    try:
        posture = posture_summary(user_id)
    except Exception:
        posture = {}
    return {
        "ok": True,
        "product": "SecuraIQ SBOM",
        "lab_production": True,
        "branded_engine": True,
        "standalone_syft": False,
        "component_sample": len(rows),
        "posture": {
            "total": posture.get("total") or posture.get("packages"),
            "outdated": posture.get("outdated"),
            "eol": posture.get("eol"),
        },
        "formats": ["cyclonedx-json", "json"],
        "note": (
            "Branded SBOM export over software inventory / agent packages. "
            "Not a separate Syft binary — generate via GET /api/sbom/export."
        ),
    }


def build_cyclonedx(user_id: str, *, limit: int = 2000) -> dict[str, Any]:
    from app.software_inventory import list_software

    comps = []
    for row in list_software(user_id, limit=limit):
        name = str(row.get("product") or row.get("name") or "component")
        version = str(row.get("version") or "unknown")
        comps.append(
            {
                "type": "library",
                "name": name[:200],
                "version": version[:80],
                "bom-ref": f"{name}@{version}"[:240],
                "properties": [
                    {"name": "securaiq:asset_id", "value": str(row.get("asset_id") or "")},
                    {"name": "securaiq:source", "value": str(row.get("source") or "")},
                    {"name": "securaiq:status", "value": str(row.get("status") or "")},
                ],
            }
        )
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "metadata": {
            "timestamp": now(),
            "tools": [{"vendor": "SecuraIQ", "name": "SecuraIQ SBOM", "version": "lab"}],
            "component": {
                "type": "application",
                "name": "securaiq-managed-estate",
                "version": "lab",
            },
        },
        "components": comps,
        "securaiq": {
            "lab_production": True,
            "note": "Derived from software inventory — not a Syft filesystem scan.",
            "component_count": len(comps),
        },
    }


def export_sbom_json(user_id: str) -> str:
    return json.dumps(build_cyclonedx(user_id), indent=2, default=str)
