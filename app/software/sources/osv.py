"""OSV.dev queries — vulnerability intelligence (fixed versions when published)."""

from __future__ import annotations

from typing import Any

import httpx

OSV_QUERY_URL = "https://api.osv.dev/v1/query"
_USER_AGENT = "SecuraIQ-Inventory/1.0"


def query_package_vulns(
    *,
    name: str,
    ecosystem: str,
    version: str = "",
    client: httpx.Client | None = None,
) -> list[dict[str, Any]]:
    """Best-effort OSV lookup. Returns [] on network/parse failure — never raises."""
    if not name or not ecosystem:
        return []
    body: dict[str, Any] = {"package": {"name": name, "ecosystem": ecosystem}}
    if version:
        body["version"] = version
    try:
        if client is None:
            with httpx.Client(timeout=10.0) as c:
                resp = c.post(OSV_QUERY_URL, json=body, headers={"User-Agent": _USER_AGENT})
        else:
            resp = client.post(OSV_QUERY_URL, json=body, headers={"User-Agent": _USER_AGENT})
        if resp.status_code != 200:
            return []
        vulns = (resp.json() or {}).get("vulns") or []
        return [v for v in vulns if isinstance(v, dict)]
    except Exception:
        return []


def fixed_versions_from_vulns(vulns: list[dict[str, Any]]) -> list[str]:
    """Collect fixed-version hints from OSV affected ranges."""
    fixed: list[str] = []
    for v in vulns:
        for aff in v.get("affected") or []:
            if not isinstance(aff, dict):
                continue
            for r in aff.get("ranges") or []:
                if not isinstance(r, dict):
                    continue
                for ev in r.get("events") or []:
                    if isinstance(ev, dict) and ev.get("fixed"):
                        fixed.append(str(ev["fixed"]))
    return fixed
