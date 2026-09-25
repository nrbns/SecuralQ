"""Toxic combinations — derived from real exposure + vuln + control rows.

Not a full misconfig-chain twin. Lab-production Phase 2 depth.
"""

from __future__ import annotations

from typing import Any

from app.exposure import HIGH_RISK_PORTS, network_scope

TOXIC_KINDS = (
    "internet_facing_high_vuln",
    "public_risky_port",
    "public_kev",
    "public_service_account_high_vuln",
    "public_firewall_off",
    "public_unencrypted",
    "high_vuln_missing_compensating_control",
)


def _truthy(v: Any) -> bool | None:
    if v is None:
        return None
    if isinstance(v, bool):
        return v
    s = str(v).strip().lower()
    if s in {"1", "true", "yes", "on", "enabled"}:
        return True
    if s in {"0", "false", "no", "off", "disabled"}:
        return False
    return None


def _is_kev(v: dict[str, Any]) -> bool:
    raw = v.get("raw") if isinstance(v.get("raw"), dict) else {}
    if _truthy(v.get("kev")) or _truthy(raw.get("kev")) or _truthy(raw.get("in_kev")):
        return True
    title = f"{v.get('title') or ''} {v.get('cve') or ''}".lower()
    return "kev" in title


def _agent_controls_by_host(user_id: str) -> dict[str, dict[str, Any]]:
    from app.agents import list_agents

    out: dict[str, dict[str, Any]] = {}
    for ag in list_agents(user_id):
        payload = ag.get("last_payload") if isinstance(ag.get("last_payload"), dict) else {}
        fw = payload.get("firewall_status") if isinstance(payload.get("firewall_status"), dict) else {}
        de = (
            payload.get("disk_encryption_status")
            if isinstance(payload.get("disk_encryption_status"), dict)
            else {}
        )
        host = str(ag.get("hostname") or payload.get("hostname") or ag.get("name") or "").lower()
        ip = str(ag.get("ip") or payload.get("ip") or "")
        row = {
            "firewall_enabled": fw.get("enabled"),
            "disk_encrypted": de.get("encrypted"),
            "listening_ports": payload.get("listening_ports") or [],
        }
        if host:
            out[host] = row
        if ip:
            out[ip] = row
    return out


def compute_toxic_combinations(user_id: str, *, limit: int = 25) -> dict[str, Any]:
    from app.enterprise import list_assets, list_vulnerabilities

    assets = list_assets(user_id)
    vulns = list_vulnerabilities(user_id, status="open")
    by_id = {str(a.get("id") or ""): a for a in assets}
    controls = _agent_controls_by_host(user_id)
    combos: list[dict[str, Any]] = []

    def _add(row: dict[str, Any]) -> None:
        if len(combos) < limit:
            combos.append(row)

    for v in vulns:
        aid = str(v.get("asset_id") or "")
        asset = by_id.get(aid) or {}
        name = str(asset.get("name") or v.get("host") or v.get("asset_name") or v.get("target") or aid or "unknown")
        scope = network_scope(name, asset.get("ip") or v.get("ip"))
        sev = str(v.get("severity") or "").lower()
        sa = str(asset.get("service_accounts") or "").strip()
        if scope in {"public", "unknown"} and sev in {"critical", "high"}:
            _add(
                {
                    "kind": "internet_facing_high_vuln",
                    "asset_id": aid,
                    "asset": name,
                    "scope": scope,
                    "severity": sev,
                    "title": v.get("title") or v.get("cve") or "open vuln",
                }
            )
        if scope in {"public", "unknown"} and _is_kev(v):
            _add(
                {
                    "kind": "public_kev",
                    "asset_id": aid,
                    "asset": name,
                    "scope": scope,
                    "cve": v.get("cve"),
                    "title": f"KEV exposed on {name}: {v.get('cve') or v.get('title')}",
                }
            )
        if scope in {"public", "unknown"} and sev in {"critical", "high"} and sa:
            _add(
                {
                    "kind": "public_service_account_high_vuln",
                    "asset_id": aid,
                    "asset": name,
                    "scope": scope,
                    "service_accounts": sa,
                    "title": f"Service account {sa} on internet-facing {name} with {sev} vuln",
                }
            )
        raw = v.get("raw") if isinstance(v.get("raw"), dict) else {}
        compensating = raw.get("compensating_controls") or v.get("compensating_controls")
        if sev in {"critical", "high"} and not compensating:
            _add(
                {
                    "kind": "high_vuln_missing_compensating_control",
                    "asset_id": aid,
                    "asset": name,
                    "severity": sev,
                    "title": f"No compensating control recorded for {v.get('cve') or v.get('title')}",
                }
            )

    for a in assets:
        name = str(a.get("name") or a.get("id") or "")
        scope = network_scope(name, a.get("ip"))
        ports_raw = str(a.get("open_ports") or a.get("ports") or "")
        ctrl = controls.get(name.lower()) or controls.get(str(a.get("ip") or "")) or {}
        extra_ports = ctrl.get("listening_ports") or []
        ports_blob = ports_raw + " " + str(extra_ports)
        risky = [p for p in HIGH_RISK_PORTS if str(p) in ports_blob]
        if scope == "public" and risky:
            _add(
                {
                    "kind": "public_risky_port",
                    "asset_id": a.get("id"),
                    "asset": name,
                    "scope": scope,
                    "ports": risky,
                    "title": f"Internet-facing high-risk port(s) {risky}",
                }
            )
        if scope in {"public", "unknown"} and _truthy(ctrl.get("firewall_enabled")) is False:
            _add(
                {
                    "kind": "public_firewall_off",
                    "asset_id": a.get("id"),
                    "asset": name,
                    "scope": scope,
                    "title": f"Internet-facing {name} with firewall disabled",
                }
            )
        if scope in {"public", "unknown"} and _truthy(ctrl.get("disk_encrypted")) is False:
            _add(
                {
                    "kind": "public_unencrypted",
                    "asset_id": a.get("id"),
                    "asset": name,
                    "scope": scope,
                    "title": f"Internet-facing {name} without disk encryption",
                }
            )

    kinds = sorted({c.get("kind") for c in combos if c.get("kind")})
    return {
        "ok": True,
        "count": len(combos),
        "kinds": kinds,
        "supported_kinds": list(TOXIC_KINDS),
        "combinations": combos[:limit],
        "disclaimer": "Derived from inventory + open vulns + host controls — not a full exploit-chain twin",
    }
