"""Framework version / effective-dating for CMMC catalogs."""

from __future__ import annotations

from typing import Any

from app.gap_analysis import load_framework


def framework_version_info(framework_id: str = "cmmc_l2") -> dict[str, Any]:
    """Return versioned catalog metadata — never invent DoD policy beyond the JSON note."""
    fw = load_framework(framework_id)
    return {
        "ok": True,
        "framework_id": str(fw.get("id") or framework_id),
        "name": fw.get("name") or framework_id,
        "version": fw.get("version") or "",
        "status_note": fw.get("status_note") or "",
        "resources": fw.get("resources") or [],
        "control_count": len(fw.get("controls") or []),
        "disclaimer": (
            "Catalog version and status_note are stored with the framework JSON. "
            "Confirm current DoD CMMC program status on dodcio.defense.gov before "
            "contractual decisions. SecuraIQ does not submit to SPRS."
        ),
    }
