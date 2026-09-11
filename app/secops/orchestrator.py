"""Phase 8 SecOps investigation orchestrator — tool-bound, audited, tenant-scoped.

Runs a fixed plan of allowlisted tools (no model-chosen shell). Returns a
structured pack the UI / LLM can narrate without inventing control-plane facts.
"""

from __future__ import annotations

from typing import Any

from app.db import audit, new_id, now
from app.secops.tools import ALLOWED_TOOLS, call_tool, list_allowed_tools


def run_secops_investigation(
    user_id: str,
    *,
    org_id: str | None = None,
    engagement_id: str | None = None,
    asset_id: str | None = None,
    limit: int = 5,
) -> dict[str, Any]:
    """Investigate via allowlisted tools only.

    When ``asset_id`` is set, focuses tools on that asset; otherwise ranks via
    ``list_priority_findings`` then enriches top assets.
    """
    investigation_id = new_id()
    tool_trace: list[dict[str, Any]] = []
    lim = max(1, min(15, int(limit or 5)))

    def _run(name: str, args: dict[str, Any] | None = None) -> dict[str, Any]:
        result = call_tool(
            name,
            user_id,
            org_id=org_id,
            engagement_id=engagement_id,
            args=args or {},
        )
        tool_trace.append(
            {
                "tool": name,
                "ok": bool(result.get("ok")),
                "error": result.get("error"),
                "args": {k: args.get(k) for k in (args or {}) if k in ("asset_id", "agent_id", "limit", "framework_id")},
            }
        )
        return result

    risk = _run("calculate_risk", {})
    priority = _run("list_priority_findings", {"limit": lim})
    threats = _run("list_agent_threats", {"limit": 30})
    controls = _run("get_controls", {"framework_id": "cmmc_l2"})
    paths = _run("get_attack_paths", {"limit": 10})

    focus_assets: list[str] = []
    if asset_id:
        focus_assets = [str(asset_id).strip()]
    else:
        items = ((priority.get("data") or {}).get("items") or []) if priority.get("ok") else []
        for item in items:
            aid = str(item.get("asset_id") or "").strip()
            if aid and aid not in focus_assets:
                focus_assets.append(aid)
            if len(focus_assets) >= lim:
                break

    assets_detail: list[dict[str, Any]] = []
    for aid in focus_assets:
        asset = _run("get_asset", {"asset_id": aid})
        vulns = _run("get_vulnerabilities", {"asset_id": aid, "status": "open", "limit": 20})
        inventory = _run("get_inventory", {"asset_id": aid})
        evidence = _run("get_evidence", {"entity_type": "asset", "entity_id": aid, "limit": 10})
        assets_detail.append(
            {
                "asset_id": aid,
                "asset": asset.get("data") if asset.get("ok") else None,
                "vulnerabilities": vulns.get("data") if vulns.get("ok") else [],
                "inventory": inventory.get("data") if inventory.get("ok") else {},
                "evidence": evidence.get("data") if evidence.get("ok") else [],
            }
        )

    # Propose-only remediation hints from priority reasons (no mutation).
    proposals: list[dict[str, Any]] = []
    items = ((priority.get("data") or {}).get("items") or []) if priority.get("ok") else []
    for item in items[:3]:
        reasons = item.get("reasons") or []
        hint = "; ".join(str(r) for r in reasons[:3]) if reasons else "Review priority finding"
        prop = _run(
            "propose_remediation",
            {
                "title": f"Address {item.get('title') or item.get('cve') or 'finding'}",
                "recommendation": hint[:1500],
                "asset_id": str(item.get("asset_id") or ""),
            },
        )
        if prop.get("ok"):
            proposals.append(prop.get("data") or {})

    pack = {
        "investigation_id": investigation_id,
        "created_at": now(),
        "org_id": org_id,
        "engagement_id": engagement_id,
        "mode": "secops_tools",
        "honesty": (
            "AI-assisted investigation over SecuraIQ control-plane tools only. "
            "Not a compliance certification. Does not invent telemetry or auto-remediate."
        ),
        "allowed_tools": list_allowed_tools(),
        "tool_trace": tool_trace,
        "risk": risk.get("data") if risk.get("ok") else None,
        "priority": priority.get("data") if priority.get("ok") else None,
        "threats": threats.get("data") if threats.get("ok") else [],
        "controls": controls.get("data") if controls.get("ok") else None,
        "attack_paths": paths.get("data") if paths.get("ok") else None,
        "assets": assets_detail,
        "proposed_remediations": proposals,
        "summary": {
            "assets_focused": len(assets_detail),
            "tools_ok": sum(1 for t in tool_trace if t.get("ok")),
            "tools_failed": sum(1 for t in tool_trace if not t.get("ok")),
            "active_threats": len(threats.get("data") or []) if threats.get("ok") else 0,
        },
        "ai_prompt": {
            "instruction": (
                "Explain the investigation pack using only the structured tool results. "
                "Cite asset_id / vuln_id / threat ids. Do not invent CVEs, scores, or PASS controls."
            ),
            "questions": [
                "Why is this risky?",
                "What evidence supports it?",
                "What should I fix first?",
                "How do I verify after remediation?",
            ],
        },
    }
    audit(
        "secops_investigation",
        user_id,
        {
            "investigation_id": investigation_id,
            "org_id": org_id,
            "tools": [t["tool"] for t in tool_trace],
            "assets": focus_assets,
        },
    )
    return pack


def deny_unknown_tool_probe(name: str, user_id: str) -> dict[str, Any]:
    """Test helper / API guard — proves unknown tools never run."""
    return call_tool(name, user_id, args={})


__all__ = [
    "ALLOWED_TOOLS",
    "run_secops_investigation",
    "deny_unknown_tool_probe",
    "list_allowed_tools",
]
