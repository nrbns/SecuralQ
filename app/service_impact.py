"""Which business services a vulnerability affects (lab graph, not a digital twin)."""

from __future__ import annotations

from typing import Any


def _service_labels(asset: dict[str, Any]) -> list[str]:
    labels: list[str] = []
    crit = str(asset.get("business_criticality") or "").strip()
    if crit:
        labels.append(f"criticality:{crit}")
    name = str(asset.get("name") or "").strip()
    if name:
        labels.append(name)
    accounts = str(asset.get("service_accounts") or "").strip()
    if accounts:
        labels.extend([a.strip() for a in accounts.replace(";", ",").split(",") if a.strip()])
    owner = str(asset.get("owner") or "").strip()
    if owner:
        labels.append(f"owner:{owner}")
    # unique preserve order
    seen: set[str] = set()
    out: list[str] = []
    for x in labels:
        if x not in seen:
            seen.add(x)
            out.append(x[:80])
    return out


def services_affected_by_vuln(user_id: str, *, vuln_id: str | None = None, limit: int = 50) -> dict[str, Any]:
    from app.enterprise import list_assets, list_vulnerabilities

    assets = {str(a.get("id") or ""): a for a in list_assets(user_id)}
    vulns = list_vulnerabilities(user_id)
    if vuln_id:
        vulns = [v for v in vulns if str(v.get("id") or "") == vuln_id]
    rows: list[dict[str, Any]] = []
    for v in vulns[: max(1, min(int(limit), 200))]:
        aid = str(v.get("asset_id") or "")
        asset = assets.get(aid) or {}
        rows.append(
            {
                "vuln_id": v.get("id"),
                "title": v.get("title") or v.get("cve") or "vulnerability",
                "severity": v.get("severity"),
                "asset_id": aid,
                "services": _service_labels(asset),
            }
        )
    return {
        "ok": True,
        "count": len(rows),
        "items": rows,
        "disclaimer": "Service labels come from asset name/criticality/service_accounts — not a digital twin",
    }
