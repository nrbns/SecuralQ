"""Productized 'why did risk increase' narrative — USP #7 lab-production gate.

Builds a demo-able explanation from risk.changed deltas + factor scores.
Template-first (deterministic). Optional LLM polish when a chat backend is ready
— never invents causes not present in the data.
"""

from __future__ import annotations

from typing import Any


def explain_risk_increase(
    user_id: str,
    *,
    limit_findings: int = 8,
    use_llm: bool = False,
) -> dict[str, Any]:
    """Return narrative + structured drivers for org risk movement."""
    from app.services.risk import explain_risk_score
    from app.services.risk_priority import compute_org_risk_score, compute_priority_list

    org = compute_org_risk_score(user_id)
    priority = compute_priority_list(user_id, limit=limit_findings)
    items = priority.get("items") or priority.get("findings") or []
    if isinstance(priority, list):
        items = priority

    # Pull last delta from in-process processor cache if present
    previous = None
    delta = None
    try:
        from app.event_processor import _last_org_risk_score

        previous = _last_org_risk_score.get(user_id)
        if previous is not None and org.get("score") is not None:
            delta = round(float(org["score"]) - float(previous), 4)
    except Exception:
        previous = None
        delta = None

    drivers: list[dict[str, Any]] = []
    for it in (items or [])[:limit_findings]:
        if not isinstance(it, dict):
            continue
        why = it.get("reasons") or it.get("why") or it.get("why_flags") or []
        if isinstance(why, str):
            why = [why]
        drivers.append(
            {
                "id": it.get("id") or it.get("finding_id") or it.get("vuln_id"),
                "title": it.get("title") or it.get("cve") or it.get("threat"),
                "score": it.get("score") or it.get("risk_score"),
                "why": why,
                "kev": bool(it.get("kev") or it.get("known_exploited")),
                "quick_win": bool(it.get("quick_win")),
                "exposure": it.get("exposure") or it.get("internet_exposed"),
                "asset": it.get("asset_name") or it.get("asset"),
            }
        )

    # Factor explanation on top finding if available
    top_explain = ""
    if drivers:
        try:
            sample = {
                "score": drivers[0].get("score") or org.get("score"),
                "band": org.get("band"),
                "factors": (items[0].get("factors") if items and isinstance(items[0], dict) else {})
                or {},
                "weights": (items[0].get("weights") if items and isinstance(items[0], dict) else {})
                or {},
                "formula": "org_priority",
            }
            if sample.get("factors"):
                top_explain = explain_risk_score(sample)
        except Exception:
            top_explain = ""

    direction = "unchanged"
    if delta is not None:
        if delta > 0.5:
            direction = "increased"
        elif delta < -0.5:
            direction = "decreased"

    bullets: list[str] = []
    if direction == "increased":
        bullets.append(
            f"Organizational risk moved from {previous} → {org.get('score')} "
            f"(Δ {delta:+}). Band: {org.get('band')}."
        )
    elif direction == "decreased":
        bullets.append(
            f"Organizational risk decreased from {previous} → {org.get('score')} "
            f"(Δ {delta:+}). Band: {org.get('band')}."
        )
    else:
        bullets.append(
            f"Current organizational risk score is {org.get('score')} ({org.get('band')}). "
            "No significant prior delta in this process yet."
        )

    for d in drivers[:5]:
        flags = []
        if d.get("kev"):
            flags.append("KEV/actively exploited")
        if d.get("quick_win"):
            flags.append("quick-win (patch available)")
        if d.get("exposure"):
            flags.append("internet-exposed")
        for w in d.get("why") or []:
            flags.append(str(w))
        flag_s = ", ".join(dict.fromkeys(flags)) if flags else "priority factors"
        bullets.append(
            f"Driver: {d.get('title') or d.get('id')} on {d.get('asset') or 'asset'} "
            f"(score {d.get('score')}) — {flag_s}."
        )

    if top_explain:
        bullets.append(f"Factor math: {top_explain}")

    narrative = " ".join(bullets)
    llm_text = None
    if use_llm:
        try:
            llm_text = _optional_llm_polish(user_id, narrative, drivers)
        except Exception:
            llm_text = None

    return {
        "ok": True,
        "lab_production": True,
        "llm_product_gate": bool(llm_text),
        "direction": direction,
        "score": org.get("score"),
        "band": org.get("band"),
        "previous_score": previous,
        "score_delta": delta,
        "drivers": drivers,
        "narrative": narrative,
        "llm_narrative": llm_text,
        "note": (
            "Deterministic narrative from org score + priority drivers (KEV/exposure/quick-win). "
            "LLM polish is optional and never invents causes."
        ),
    }


def explain_finding(user_id: str, finding_id: str) -> dict[str, Any]:
    """Why this finding matters + what-if-I-fix delta. Never invents paths."""
    from app.enterprise import get_vulnerability
    from app.exposure import network_scope
    from app.service_impact import services_affected_by_vuln
    from app.services.risk_priority import compute_risk_simulation

    v = {}
    try:
        v = get_vulnerability(user_id, finding_id) or {}
    except Exception:
        v = {}
    if not v:
        return {
            "ok": False,
            "kind": "vuln",
            "title": "Finding not found",
            "what": finding_id,
            "why": "No tenant-visible finding with this id.",
            "evidence": "",
            "impact": "",
            "action": "",
            "verify": "",
            "simulate": True,
            "request_approval": False,
        }
    sim = {}
    try:
        sim = compute_risk_simulation(user_id, limit=12)
    except Exception:
        sim = {}
    impact = {}
    try:
        impact = services_affected_by_vuln(user_id, vuln_id=finding_id)
    except Exception:
        impact = {}
    asset_name = str(v.get("asset_name") or v.get("asset_id") or "")
    scope = network_scope(asset_name, v.get("ip"))
    kev = bool(v.get("kev") or v.get("known_exploited") or (v.get("raw") or {}).get("kev"))
    group_hit = None
    vid = str(v.get("id") or finding_id)
    cve = str(v.get("cve") or "")
    for g in sim.get("groups") or []:
        ids = {str(x) for x in (g.get("vuln_ids") or g.get("finding_ids") or [])}
        if vid in ids or (cve and str(g.get("key") or "") == f"cve:{cve}"):
            group_hit = g
            break
    reduction = None
    if group_hit:
        reduction = group_hit.get("reduction") or group_hit.get("estimated_reduction")
    services = impact.get("services") or []
    return {
        "ok": True,
        "kind": "vuln",
        "title": v.get("title") or "Why does this finding matter?",
        "what": v.get("title") or finding_id,
        "why": (
            f"Severity {v.get('severity')} on {asset_name or 'asset'} · CVE {cve or 'n/a'}"
            + (" · KEV/actively exploited" if kev else "")
            + f" · exposure {scope}"
        ),
        "evidence": "Finding raw + linked observations. Show evidence from the vault; do not trust execute.",
        "impact": (
            f"Services affected: {len(services) if isinstance(services, list) else 0}. "
            f"If this class is fixed, estimated org-risk reduction: {reduction if reduction is not None else 'n/a'}."
        ),
        "action": "Patch / compensate / exception — never mark fixed from ticket close alone.",
        "verify": "Inventory refresh or host control re-test.",
        "expected": sim.get("disclaimer")
        or "Simulator recomputes the same org score with this CVE group excluded.",
        "simulate": True,
        "request_approval": True,
        "finding": {
            k: v.get(k)
            for k in ("id", "title", "severity", "cve", "asset_name", "asset_id", "status")
            if v
        },
        "kev": kev,
        "exposure": scope,
        "services": services[:8] if isinstance(services, list) else [],
        "simulation": {
            "baseline_score": sim.get("baseline_score"),
            "reduction": reduction,
            "group": group_hit,
        },
    }


def _optional_llm_polish(user_id: str, narrative: str, drivers: list[dict[str, Any]]) -> str | None:
    """Best-effort short rewrite — skipped if backend not ready."""
    from app.config import settings

    if not getattr(settings, "model_backend", None):
        return None
    # Soft: only return None in lab unless explicitly wired; keep product gate honest
    _ = user_id, drivers
    return None  # Template narrative is the product gate; LLM hook reserved
