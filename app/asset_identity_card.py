"""Security Identity Card — one canonical asset view."""

from __future__ import annotations

from typing import Any

from app.exposure import network_scope


def _failing_controls(user_id: str, asset_id: str, name: str) -> list[dict[str, Any]]:
    from app.controls.results import ensure_schema
    from app.db import get_conn, row_to_dict

    ensure_schema()
    rows = get_conn().execute(
        """
        SELECT * FROM securaiq_control_test_results
        WHERE user_id = ? AND LOWER(status) = 'fail'
        ORDER BY tested_at DESC
        LIMIT 80
        """,
        (user_id,),
    ).fetchall()
    out: list[dict[str, Any]] = []
    name_l = (name or "").strip().lower()
    for raw in rows:
        r = row_to_dict(raw) or {}
        detail = r.get("detail") if isinstance(r.get("detail"), dict) else {}
        if not detail:
            try:
                import json

                detail = json.loads(r.get("detail_json") or "{}")
            except Exception:
                detail = {}
        aid = str(detail.get("asset_id") or r.get("asset_id") or "")
        host = str(detail.get("hostname") or detail.get("asset_name") or "").lower()
        if aid and aid not in {str(asset_id)}:
            if name_l and name_l not in host:
                continue
        elif name_l and host and name_l not in host and aid != str(asset_id):
            continue
        out.append(
            {
                "test": r.get("test_name") or r.get("control_id"),
                "control_id": r.get("control_id"),
                "framework_id": r.get("framework_id"),
                "status": "fail",
                "summary": r.get("summary") or "",
            }
        )
        if len(out) >= 12:
            break
    return out


def asset_identity_card(user_id: str, asset_id: str) -> dict[str, Any] | None:
    from app.asset_identity import list_aliases
    from app.enterprise import get_asset, list_vulnerabilities
    from app.service_impact import services_affected_by_vuln

    asset = get_asset(user_id, asset_id)
    if not asset:
        return None
    name = str(asset.get("name") or asset_id)
    ip = str(asset.get("ip") or "")
    scope = network_scope(name, ip or None)
    vulns = [
        v
        for v in list_vulnerabilities(user_id, status="open")
        if str(v.get("asset_id") or "") == str(asset_id)
        or str(v.get("asset_name") or "") == name
    ]
    crit = sum(1 for v in vulns if str(v.get("severity") or "").lower() == "critical")
    high = sum(1 for v in vulns if str(v.get("severity") or "").lower() == "high")
    failed_controls = _failing_controls(user_id, asset_id, name)
    impact: dict[str, Any] = {}
    try:
        impact = services_affected_by_vuln(user_id)
    except Exception:
        impact = {}
    aliases = []
    try:
        aliases = list_aliases(user_id, asset_id)
    except Exception:
        aliases = []
    online = None
    try:
        from app.agents import list_agents

        for ag in list_agents(user_id) or []:
            if str(ag.get("asset_id") or "") == str(asset_id) or str(ag.get("hostname") or "") == name:
                st = str(ag.get("status") or "").lower()
                online = st in {"online", "connected", "live", "healthy"} or bool(
                    ag.get("online") or ag.get("connected")
                )
                break
    except Exception:
        online = None
    return {
        "ok": True,
        "asset_id": asset_id,
        "name": name,
        "display_name": asset.get("display_name") or name,
        "role": asset.get("notes") or asset.get("asset_type") or "",
        "owner": asset.get("owner") or "",
        "business_service": asset.get("service_accounts") or "",
        "business_criticality": asset.get("business_criticality") or asset.get("criticality") or "",
        "online": online,
        "risk_band": "high" if crit or (scope == "public" and high) else ("medium" if high else "low"),
        "exposure": {
            "internet_facing": scope == "public",
            "scope": scope,
            "critical_cves": crit,
            "high_cves": high,
            "open_findings": len(vulns),
            "failed_controls": len(failed_controls),
        },
        "failed_controls": failed_controls,
        "compliance": {
            "note": "framework % is live-control based when results exist — not certification"
        },
        "aliases": aliases,
        "actions": ["fix_highest_risk", "investigate", "simulate"],
        "tabs": [
            "overview",
            "security",
            "vulnerabilities",
            "threats",
            "software",
            "network",
            "controls",
            "compliance",
            "evidence",
            "remediation",
            "attack_paths",
            "timeline",
        ],
        "services_impact": {
            "ok": bool(impact.get("ok")),
            "count": impact.get("count") or len(impact.get("services") or []),
        },
    }
