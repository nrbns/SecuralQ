"""Phase 8 AI SecOps — allowlisted server-side tools only.

No direct DB/SQL/shell from the model. Tools wrap existing control-plane
services with tenant scoping. Mutating remediations are propose-only.
"""

from __future__ import annotations

from typing import Any

# Frozen allowlist — architecture tool surface (read + propose).
ALLOWED_TOOLS: frozenset[str] = frozenset(
    {
        "get_asset",
        "get_agent",
        "get_inventory",
        "get_events",
        "get_vulnerabilities",
        "get_controls",
        "get_evidence",
        "get_attack_paths",
        "calculate_risk",
        "list_priority_findings",
        "list_agent_threats",
        "propose_remediation",
        "propose_approval",
        "verify_host_remediation",
    }
)


def list_allowed_tools() -> list[str]:
    return sorted(ALLOWED_TOOLS)


def call_tool(
    name: str,
    user_id: str,
    *,
    org_id: str | None = None,
    engagement_id: str | None = None,
    args: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Dispatch one allowlisted tool. Unknown names are denied (fail closed)."""
    args = args if isinstance(args, dict) else {}
    tool = (name or "").strip()
    if tool not in ALLOWED_TOOLS:
        return {
            "ok": False,
            "error": "tool_not_allowed",
            "tool": tool,
            "detail": "Unknown or disallowed SecOps tool — no shell/DB access.",
        }
    try:
        fn = _DISPATCH[tool]
        data = fn(user_id, org_id=org_id, engagement_id=engagement_id, **_safe_kwargs(tool, args))
        return {"ok": True, "tool": tool, "data": data}
    except TypeError as exc:
        return {"ok": False, "error": "bad_args", "tool": tool, "detail": str(exc)[:300]}
    except Exception as exc:
        return {"ok": False, "error": "tool_failed", "tool": tool, "detail": str(exc)[:300]}


def _safe_kwargs(tool: str, args: dict[str, Any]) -> dict[str, Any]:
    """Pass only scalar/string args the tool expects — never raw SQL fragments."""
    out: dict[str, Any] = {}
    for k, v in args.items():
        key = str(k)[:64]
        if key.startswith("_"):
            continue
        if isinstance(v, (str, int, float, bool)) or v is None:
            out[key] = v
        elif isinstance(v, list) and all(isinstance(x, (str, int, float, bool)) or x is None for x in v[:50]):
            out[key] = v[:50]
    return out


def _get_asset(
    user_id: str,
    *,
    org_id: str | None = None,
    engagement_id: str | None = None,
    asset_id: str = "",
    **_: Any,
) -> dict[str, Any] | None:
    from app.enterprise import get_asset, list_assets

    aid = str(asset_id or "").strip()
    if not aid:
        return None
    row = get_asset(user_id, aid)
    if row:
        return row
    # Fail closed: only return if visible in scoped list
    for a in list_assets(user_id, engagement_id, org_id=org_id):
        if a.get("id") == aid:
            return a
    return None


def _get_agent(
    user_id: str,
    *,
    org_id: str | None = None,
    engagement_id: str | None = None,
    agent_id: str = "",
    **_: Any,
) -> dict[str, Any] | None:
    from app.agents import agent_visible_to_user, get_agent

    aid = str(agent_id or "").strip()
    if not aid:
        return None
    agent = get_agent(aid)
    if not agent_visible_to_user(user_id, agent):
        return None
    if org_id and agent and agent.get("org_id") and agent.get("org_id") != org_id:
        if user_id != "local":
            return None
    # Strip secrets if any linger
    if agent:
        agent = {k: v for k, v in agent.items() if k not in {"key_hash", "key_enc", "agent_key"}}
    return agent


def _get_inventory(
    user_id: str,
    *,
    org_id: str | None = None,
    engagement_id: str | None = None,
    asset_id: str = "",
    agent_id: str = "",
    **_: Any,
) -> dict[str, Any]:
    """Host inventory from agent last_payload and/or software installations."""
    from app.agents import agent_visible_to_user, get_agent, list_agents

    payload: dict[str, Any] = {}
    aid = str(agent_id or "").strip()
    asset = str(asset_id or "").strip()
    agent = None
    if aid:
        agent = get_agent(aid)
        if not agent_visible_to_user(user_id, agent):
            agent = None
    elif asset:
        for a in list_agents(user_id, org_id=org_id):
            if a.get("asset_id") == asset and a.get("status") == "online":
                agent = a
                break
        if agent is None:
            for a in list_agents(user_id, org_id=org_id):
                if a.get("asset_id") == asset:
                    agent = a
                    break
    if agent:
        lp = agent.get("last_payload") if isinstance(agent.get("last_payload"), dict) else {}
        for key in (
            "hostname",
            "os",
            "os_version",
            "packages",
            "firewall_status",
            "defender_status",
            "disk_encryption_status",
            "ssh_config",
            "file_integrity",
            "security_logs",
        ):
            if key in lp:
                payload[key] = lp[key]
        payload["agent_id"] = agent.get("id")
        payload["asset_id"] = agent.get("asset_id")
    # Optional software table join
    try:
        from app.db import get_conn

        c = get_conn()
        target_asset = asset or (agent or {}).get("asset_id") or ""
        if target_asset:
            rows = c.execute(
                """
                SELECT i.id, i.version, i.cve, p.name AS product_name
                FROM software_installations i
                LEFT JOIN software_products p ON p.id = i.software_product_id
                WHERE i.user_id = ? AND i.asset_id = ?
                LIMIT 200
                """,
                (user_id, target_asset),
            ).fetchall()
            payload["software_installations"] = [dict(r) for r in rows]
    except Exception:
        pass
    return payload


def _get_events(
    user_id: str,
    *,
    org_id: str | None = None,
    engagement_id: str | None = None,
    limit: int = 25,
    **_: Any,
) -> list[dict[str, Any]]:
    """Native agent threats as the honest event surface (not invented SIEM)."""
    from app.agents import list_threats

    lim = max(1, min(100, int(limit or 25)))
    return list_threats(user_id, limit=lim, org_id=org_id)


def _get_vulnerabilities(
    user_id: str,
    *,
    org_id: str | None = None,
    engagement_id: str | None = None,
    asset_id: str = "",
    status: str = "open",
    limit: int = 50,
    **_: Any,
) -> list[dict[str, Any]]:
    from app.enterprise import list_vulnerabilities

    rows = list_vulnerabilities(
        user_id,
        status=status or None,
        org_id=org_id,
        engagement_id=engagement_id,
    )
    aid = str(asset_id or "").strip()
    if aid:
        rows = [r for r in rows if r.get("asset_id") == aid]
    return rows[: max(1, min(200, int(limit or 50)))]


def _get_controls(
    user_id: str,
    *,
    org_id: str | None = None,
    engagement_id: str | None = None,
    framework_id: str = "cmmc_l2",
    **_: Any,
) -> dict[str, Any]:
    from app.controls.results import aggregate_control_statuses, list_results_for_framework
    from app.controls.test_registry import list_registry

    fid = str(framework_id or "cmmc_l2").strip() or "cmmc_l2"
    return {
        "framework_id": fid,
        "registry": [
            {
                "test_name": e.get("test_name"),
                "frequency": e.get("frequency"),
                "verifiability": e.get("verifiability"),
            }
            for e in list_registry()
        ],
        "aggregate": aggregate_control_statuses(user_id, fid),
        "recent_results": list_results_for_framework(user_id, fid)[:40],
    }


def _get_evidence(
    user_id: str,
    *,
    org_id: str | None = None,
    engagement_id: str | None = None,
    entity_type: str = "",
    entity_id: str = "",
    limit: int = 30,
    **_: Any,
) -> list[dict[str, Any]]:
    from app.services.evidence import get_evidence_for, list_evidence

    lim = max(1, min(100, int(limit or 30)))
    et = str(entity_type or "").strip()
    eid = str(entity_id or "").strip()
    if et and eid:
        return get_evidence_for(user_id, entity_type=et, entity_id=eid)[:lim]
    return list_evidence(user_id, limit=lim, org_id=org_id)


def _get_attack_paths(
    user_id: str,
    *,
    org_id: str | None = None,
    engagement_id: str | None = None,
    limit: int = 15,
    **_: Any,
) -> dict[str, Any]:
    from app.services.attack_graph import compute_attack_paths

    return compute_attack_paths(
        user_id,
        org_id=org_id,
        engagement_id=engagement_id,
        limit=max(1, min(50, int(limit or 15))),
    )


def _calculate_risk(
    user_id: str,
    *,
    org_id: str | None = None,
    engagement_id: str | None = None,
    **_: Any,
) -> dict[str, Any]:
    from app.services.risk_priority import compute_org_risk_score, compute_priority_list

    return {
        "organizational": compute_org_risk_score(
            user_id, org_id=org_id, engagement_id=engagement_id
        ),
        "priority": compute_priority_list(
            user_id, org_id=org_id, engagement_id=engagement_id, limit=10
        ),
    }


def _list_priority_findings(
    user_id: str,
    *,
    org_id: str | None = None,
    engagement_id: str | None = None,
    limit: int = 10,
    **_: Any,
) -> dict[str, Any]:
    from app.services.risk_priority import compute_priority_list

    return compute_priority_list(
        user_id,
        org_id=org_id,
        engagement_id=engagement_id,
        limit=max(1, min(50, int(limit or 10))),
    )


def _list_agent_threats(
    user_id: str,
    *,
    org_id: str | None = None,
    engagement_id: str | None = None,
    agent_id: str = "",
    limit: int = 40,
    **_: Any,
) -> list[dict[str, Any]]:
    from app.agents import list_threats

    return list_threats(
        user_id,
        agent_id=str(agent_id or "").strip() or None,
        limit=max(1, min(200, int(limit or 40))),
        org_id=org_id,
    )


def _propose_remediation(
    user_id: str,
    *,
    org_id: str | None = None,
    engagement_id: str | None = None,
    title: str = "",
    recommendation: str = "",
    asset_id: str = "",
    control_id: str = "",
    **_: Any,
) -> dict[str, Any]:
    """Propose-only — does not write remediations. Human must call enterprise API."""
    return {
        "proposed": True,
        "mutated": False,
        "draft": {
            "title": str(title or "Proposed remediation")[:200],
            "recommendation": str(recommendation or "")[:2000],
            "asset_id": str(asset_id or "")[:80],
            "control_id": str(control_id or "")[:80],
            "org_id": org_id,
            "engagement_id": engagement_id,
        },
        "next_step": "Create via existing remediations / POA&M APIs after analyst approval.",
    }


def _propose_approval(
    user_id: str,
    *,
    org_id: str | None = None,
    engagement_id: str | None = None,
    agent_id: str = "",
    command_kind: str = "",
    **_: Any,
) -> dict[str, Any]:
    """Propose-only — never queues agent commands from the model."""
    kind = str(command_kind or "").strip()
    allowed_kinds = {"enable_firewall", "enable_defender", "patch_package", "agent_upgrade"}
    return {
        "proposed": True,
        "mutated": False,
        "draft": {
            "agent_id": str(agent_id or "")[:80],
            "command_kind": kind if kind in allowed_kinds else "",
            "note": "Use Agents UI / POST commands then approve (pending_approval → queued).",
        },
        "denied_kind": kind if kind and kind not in allowed_kinds else None,
    }


def _verify_host_remediation(
    user_id: str,
    *,
    org_id: str | None = None,
    engagement_id: str | None = None,
    agent_id: str = "",
    test_name: str = "host_firewall",
    **_: Any,
) -> dict[str, Any]:
    from app.secops.verification import verify_host_remediation

    return verify_host_remediation(
        user_id,
        agent_id=str(agent_id or ""),
        test_name=str(test_name or "host_firewall"),
        org_id=org_id,
    )


_DISPATCH = {
    "get_asset": _get_asset,
    "get_agent": _get_agent,
    "get_inventory": _get_inventory,
    "get_events": _get_events,
    "get_vulnerabilities": _get_vulnerabilities,
    "get_controls": _get_controls,
    "get_evidence": _get_evidence,
    "get_attack_paths": _get_attack_paths,
    "calculate_risk": _calculate_risk,
    "list_priority_findings": _list_priority_findings,
    "list_agent_threats": _list_agent_threats,
    "propose_remediation": _propose_remediation,
    "propose_approval": _propose_approval,
    "verify_host_remediation": _verify_host_remediation,
}
