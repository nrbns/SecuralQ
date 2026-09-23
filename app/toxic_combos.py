"""Toxic combinations — derived from real exposure + vuln + control rows.

Not a full misconfig-chain twin. Lab-production Phase 2 depth.
"""

from __future__ import annotations

from typing import Any

from app.exposure import HIGH_RISK_PORTS, network_scope


def compute_toxic_combinations(user_id: str, *, limit: int = 25) -> dict[str, Any]:
    from app.enterprise import list_assets, list_vulnerabilities

    assets = list_assets(user_id)
    vulns = list_vulnerabilities(user_id, status="open")
    by_id = {str(a.get("id") or ""): a for a in assets}
    combos: list[dict[str, Any]] = []

    for v in vulns:
        aid = str(v.get("asset_id") or "")
        asset = by_id.get(aid) or {}
        name = str(asset.get("name") or v.get("host") or v.get("target") or aid or "unknown")
        scope = network_scope(name, asset.get("ip") or v.get("ip"))
        sev = str(v.get("severity") or "").lower()
        if scope in {"public", "unknown"} and sev in {"critical", "high"}:
            combos.append(
                {
                    "kind": "internet_facing_high_vuln",
                    "asset_id": aid,
                    "asset": name,
                    "scope": scope,
                    "severity": sev,
                    "title": v.get("title") or v.get("cve") or "open vuln",
                }
            )
        if len(combos) >= limit:
            break

    for a in assets:
        if len(combos) >= limit:
            break
        name = str(a.get("name") or a.get("id") or "")
        scope = network_scope(name, a.get("ip"))
        ports_raw = str(a.get("open_ports") or a.get("ports") or "")
        risky = [p for p in HIGH_RISK_PORTS if str(p) in ports_raw]
        if scope == "public" and risky:
            combos.append(
                {
                    "kind": "public_risky_port",
                    "asset_id": a.get("id"),
                    "asset": name,
                    "scope": scope,
                    "ports": risky,
                    "title": f"Internet-facing high-risk port(s) {risky}",
                }
            )

    return {
        "ok": True,
        "count": len(combos),
        "combinations": combos[:limit],
        "disclaimer": "Derived from inventory + open vulns — not a full exploit-chain twin",
    }
