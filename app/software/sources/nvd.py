"""NVD CVE lookup wrapper — advisory enrichment (Phase 4 bridge)."""

from __future__ import annotations

import asyncio
from typing import Any


def lookup_cve_sync(cve_id: str) -> dict[str, Any]:
    """Sync wrapper around intel_feeds NVD lookup — returns {} when unavailable."""
    cve = (cve_id or "").strip().upper()
    if not cve.startswith("CVE-"):
        return {}
    try:
        from app.intel_feeds import lookup_nvd_cve

        try:
            asyncio.get_running_loop()
        except RuntimeError:
            return asyncio.run(lookup_nvd_cve(cve))
        import concurrent.futures

        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
            return pool.submit(asyncio.run, lookup_nvd_cve(cve)).result(timeout=20)
    except Exception:
        return {}
