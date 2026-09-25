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


def service_graph(user_id: str, *, limit: int = 80) -> dict[str, Any]:
    """Service → asset → findings. Lab graph, not a digital twin."""
    from app.enterprise import list_assets, list_vulnerabilities

    assets = list_assets(user_id)
    vulns = list_vulnerabilities(user_id, status="open")
    nodes: list[dict[str, Any]] = []
    edges: list[dict[str, Any]] = []
    for a in assets[: max(1, min(int(limit), 200))]:
        aid = str(a.get("id") or "")
        services = _service_labels(a)
        nodes.append({"id": aid, "kind": "asset", "name": a.get("name"), "services": services})
        for svc in services[:6]:
            sid = f"svc:{svc}"
            if not any(n.get("id") == sid for n in nodes):
                nodes.append({"id": sid, "kind": "service", "name": svc})
            edges.append({"from": sid, "to": aid, "kind": "runs_on"})
    for v in vulns[:limit]:
        aid = str(v.get("asset_id") or "")
        if aid:
            edges.append({"from": str(v.get("id") or ""), "to": aid, "kind": "affects"})
            nodes.append(
                {
                    "id": v.get("id"),
                    "kind": "finding",
                    "name": v.get("title") or v.get("cve"),
                    "severity": v.get("severity"),
                }
            )
    return {
        "ok": True,
        "nodes": nodes,
        "edges": edges,
        "disclaimer": "Declared service labels + open findings — not a twin simulation.",
    }


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
