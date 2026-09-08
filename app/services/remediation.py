"""Remediation Intelligence -- turns a Risk Reduction Simulator group into a
first-class, comparable, trackable Remediation Plan.

Pipeline this closes the loop on (all pieces already existed except the
persisted plan itself):

    Attack graph -> Risk engine -> Top remediation (simulator group)
        -> Remediation Plan (this module) -> Approval -> Patch Campaign
        -> Ring -> Patch -> Verification -> Graph refresh -> measured
        risk reduction

A plan is a FROZEN SNAPSHOT of one simulator group at creation time --
title/cve, how many findings/assets it covers, its estimated risk-reduction
%, and its real attack-path disruption counts (from
app.services.attack_graph via app.services.risk_priority). Snapshotting
matters because the underlying open-findings set changes as new scans run
or vulnerabilities get resolved; a plan keeps showing what a security team
actually compared and approved, not a number that silently drifts.

Two fields here are genuinely new (not present anywhere else in the
product) and are computed, not invented:

- disruption_band ("low"/"medium"/"high"): how disruptive/costly executing
  this plan is likely to be, derived ONLY from real, already-collected
  signals -- how many assets it touches, whether any of them are
  business-critical, and how many are even reachable for automated
  remediation right now (a currently-online SecuraIQ agent). See
  `_disruption_band` for the exact, documented rule -- there is no ML
  model or fabricated score behind this.
- explanation: a "why fix this first" sentence built by filling a template
  with the plan's own real fields (KEV, attack paths disrupted,
  business-criticality, quick-win, risk-reduction %). It never asserts
  anything the data doesn't support, and it never treats an unverified
  attack-graph edge as fact: attack_paths_disrupted counts every path
  computed from the current graph (declared + confirmed + inferred
  connects_to edges all included, same as the simulator itself), but
  verified_attack_paths_disrupted separately counts only the paths that do
  NOT cross an inferred (guessed) connects_to hop. A single-hop
  Internet -> vulnerable-asset path counts as confirmed even though its
  exposed_to edge is technically source="derived" rather than "declared"
  -- it's computed straight from real category/inventory data, not a
  guess. Only source="inferred" (the same category the "Confirm
  connection" UI flow targets) makes a path unconfirmed. The explanation
  text always splits "N confirmed, M relying on an unconfirmed link"
  rather than reporting one combined number that would quietly launder an
  inference into a fact.

A plan can only reach status='executing' once a REAL Patch Campaign is
linked to it (see `link_campaign`). This module never fabricates a
multi-asset campaign on a user's behalf: campaigns today can only
represent a package-manager upgrade (see SUPPORTED_COMMAND_KINDS in
app.agents), and guessing that mapping across many assets at once without
a human choosing it per-asset is the kind of invented certainty this
product deliberately avoids elsewhere (see app.services.attack_graph's
evidence contract). The existing "Patch via Agent" flow is how a campaign
actually gets created; this module just lets you link the result back to
the plan you compared it against.
"""

from __future__ import annotations

import json
from typing import Any

from app.db import audit, get_conn, new_id, now, row_to_dict

_VALID_STATUSES = ("draft", "approved", "executing", "verified", "measured", "rejected")


def _agent_patchable_asset_ids(user_id: str) -> set[str]:
    """Asset IDs with a currently-online SecuraIQ agent -- the same
    real signal app.services.risk_priority uses for "compensating
    controls": only a live, checked-in agent counts, so this can't go
    stale silently. An asset with no agent (or an offline one) cannot be
    remediated through this product today; it needs manual action."""
    try:
        from app.agents import list_agents

        return {a["asset_id"] for a in list_agents(user_id) if a.get("status") == "online" and a.get("asset_id")}
    except Exception:
        return set()


def _business_critical_asset_ids(user_id: str, asset_ids: set[str], *, org_id: str | None, engagement_id: str | None) -> set[str]:
    from app.enterprise import list_assets

    if not asset_ids:
        return set()
    assets = list_assets(user_id, engagement_id, org_id=org_id)
    out = set()
    for a in assets:
        if a.get("id") not in asset_ids:
            continue
        biz = (a.get("business_criticality") or a.get("criticality") or "").strip().lower()
        if biz in ("critical", "high"):
            out.add(a["id"])
    return out


def _disruption_band(*, assets_affected: int, business_critical_assets: int, agent_patchable_assets: int) -> str:
    """How disruptive/costly this plan is likely to be to execute --
    derived from real counts only:

    - "high": touches a business-critical asset, OR spans more than 10
      assets (broad blast radius regardless of criticality).
    - "low": 2 or fewer assets, none business-critical, and every one of
      them is reachable by an online agent (so it's cheap AND automatable).
    - "medium": everything else -- the common case of a handful of
      non-critical assets, or assets that need manual remediation because
      no agent covers them.

    This never claims a plan is "automatable" beyond what
    agent_patchable_assets actually shows -- a "low" band with 0
    agent-patchable assets is still reported as manual-only by the
    explanation text, not silently assumed to be low-effort to execute.
    """
    if business_critical_assets > 0 or assets_affected > 10:
        return "high"
    if assets_affected <= 2 and agent_patchable_assets >= assets_affected:
        return "low"
    return "medium"


def _explain(group: dict[str, Any], *, business_critical_assets: int, agent_patchable_assets: int) -> str:
    """Build the "why fix this first" sentence entirely from this plan's
    own real fields -- no invented reasoning, matching the product's
    existing rule for risk-score and attack-path narration."""
    parts: list[str] = []
    vulns = group.get("vulns_removed", 0)
    assets = group.get("assets_affected", 0)
    parts.append(
        f"Resolves {vulns} finding{'s' if vulns != 1 else ''} across {assets} asset{'s' if assets != 1 else ''}"
        f"{f' ({business_critical_assets} business-critical)' if business_critical_assets else ''}."
    )
    if group.get("kev"):
        parts.append("Includes a CISA KEV-listed, actively exploited vulnerability.")
    paths = group.get("attack_paths_disrupted", 0)
    if paths:
        biz_paths = group.get("business_critical_paths_disrupted", 0)
        verified_paths = group.get("verified_attack_paths_disrupted", 0)
        unverified_paths = paths - verified_paths
        parts.append(
            f"Disrupts {paths} attack path{'s' if paths != 1 else ''} in the current graph"
            f"{f' ({biz_paths} reaching a business-critical target)' if biz_paths else ''}"
            f" -- {verified_paths} confirmed"
            f"{f', {unverified_paths} relying on at least one unconfirmed inferred connection' if unverified_paths else ''}."
        )
    pct = group.get("estimated_risk_reduction_pct", 0)
    if pct:
        parts.append(f"Estimated organizational risk reduction: {pct}%.")
    if group.get("quick_win"):
        parts.append("A patch is already available -- quick win.")
    if agent_patchable_assets == 0:
        parts.append("No affected asset currently has an online SecuraIQ agent -- this needs manual remediation.")
    elif agent_patchable_assets < assets:
        parts.append(f"{agent_patchable_assets} of {assets} affected asset(s) have an online agent available for automated patching; the rest need manual remediation.")
    return " ".join(parts)


def _find_group(user_id: str, group_key: str, *, org_id: str | None, engagement_id: str | None) -> tuple[dict[str, Any] | None, set[str]]:
    """Re-derive one simulator group's live composition on demand, without
    changing compute_risk_simulation's public contract (its `groups` list
    only ever returns the top N). Returns (group_dict_shaped_like_the_
    simulator's, member_asset_ids) or (None, set()) if the group no longer
    has any open findings (already resolved)."""
    from app.services.risk_priority import _group_key, _mean_score, _scored_open_items

    scored = _scored_open_items(user_id, org_id=org_id, engagement_id=engagement_id)
    baseline_score = _mean_score(scored)
    items = [i for i in scored if _group_key(i) == group_key]
    if not items:
        return None, set()

    group_ids = {i["vuln_id"] for i in items}
    remaining = [i for i in scored if i["vuln_id"] not in group_ids]
    simulated_score = _mean_score(remaining)
    reduction_pct = round((baseline_score - simulated_score) / baseline_score * 100, 1) if baseline_score else 0.0

    asset_ids = sorted({i["asset_id"] for i in items if i["asset_id"]})
    internet_exposed = sorted({i["asset_id"] for i in items if i["asset_id"] and i.get("exposure", 0) >= 0.8})
    title = items[0].get("title") or items[0].get("cve") or "Untitled finding"

    group: dict[str, Any] = {
        "group_key": group_key,
        "title": title,
        "cve": items[0].get("cve") or "",
        "vulns_removed": len(items),
        "assets_affected": len(asset_ids),
        "internet_exposed_assets": len(internet_exposed),
        "kev": any(i["kev"] for i in items),
        "critical_high_count": sum(1 for i in items if i["severity"] in ("critical", "high")),
        "quick_win": any(i["quick_win"] for i in items),
        "estimated_risk_reduction_pct": max(0.0, reduction_pct),
        "attack_paths_disrupted": 0,
        "business_critical_paths_disrupted": 0,
        "verified_attack_paths_disrupted": 0,
    }

    try:
        from app.services.attack_graph import compute_attack_paths

        ap_result = compute_attack_paths(user_id, org_id=org_id, engagement_id=engagement_id, max_depth=6, limit=1000)
        vuln_id_set = group_ids
        disrupted = 0
        biz_disrupted = 0
        verified_disrupted = 0
        for path in ap_result["paths"]:
            path_vuln_ids = {v.get("vuln_id") for v in path.get("vulnerabilities", []) if v.get("vuln_id")}
            if not (path_vuln_ids & vuln_id_set):
                continue
            disrupted += 1
            target = path.get("target_asset") or {}
            if str(target.get("business_criticality") or target.get("criticality") or "medium").lower() in ("critical", "high"):
                biz_disrupted += 1
            # A path is "confirmed" if it does NOT rely on an inferred
            # (guessed, low-confidence) connects_to hop anywhere along the
            # route. This is deliberately narrower than the edge-level
            # `verified` flag: exposed_to/runs/affected_by edges carry
            # source="derived" (computed straight from real inventory/
            # category data -- not a human attestation, but not a guess
            # either), so a single-hop Internet -> vulnerable-asset path is
            # real evidence, not a hypothesis, even though none of its
            # edges are literally "declared". Only source="inferred" --
            # the one genuinely speculative category, the same one the
            # "Confirm connection" UI flow targets -- makes a path
            # unconfirmed. Never let a path that crosses a guessed link
            # silently count as confirmed.
            if not any(e.get("source") == "inferred" for e in path.get("edges", [])):
                verified_disrupted += 1
        group["attack_paths_disrupted"] = disrupted
        group["business_critical_paths_disrupted"] = biz_disrupted
        group["verified_attack_paths_disrupted"] = verified_disrupted
    except Exception:
        pass  # real enhancement only -- a plan can still be created without it

    return group, set(asset_ids)


def create_plan(
    user_id: str,
    group_key: str,
    *,
    org_id: str | None = None,
    engagement_id: str | None = None,
) -> dict[str, Any]:
    """Snapshot a live simulator group into a persisted, comparable plan.
    Raises ValueError if the group has no open findings right now (already
    resolved, or the group_key was never valid)."""
    from app.services.risk_priority import _mean_score, _scored_open_items
    from app.tenancy import primary_org_id

    oid = org_id or primary_org_id(user_id)
    group, asset_ids = _find_group(user_id, group_key, org_id=oid, engagement_id=engagement_id)
    if group is None:
        raise ValueError("No open findings match this group -- it may already be resolved.")

    patchable_ids = _agent_patchable_asset_ids(user_id) & asset_ids
    biz_critical_ids = _business_critical_asset_ids(user_id, asset_ids, org_id=oid, engagement_id=engagement_id)

    band = _disruption_band(
        assets_affected=group["assets_affected"],
        business_critical_assets=len(biz_critical_ids),
        agent_patchable_assets=len(patchable_ids),
    )
    explanation = _explain(group, business_critical_assets=len(biz_critical_ids), agent_patchable_assets=len(patchable_ids))

    baseline_score = _mean_score(_scored_open_items(user_id, org_id=oid, engagement_id=engagement_id))

    pid = new_id()
    ts = now()
    c = get_conn()
    c.execute(
        """
        INSERT INTO remediation_plans (
            id, user_id, engagement_id, org_id, group_key, title, cve, status,
            vulns_removed, assets_affected, asset_ids_json, internet_exposed_assets,
            business_critical_assets, agent_patchable_assets, kev, quick_win,
            critical_high_count, estimated_risk_reduction_pct, attack_paths_disrupted,
            business_critical_paths_disrupted, verified_attack_paths_disrupted,
            disruption_band, explanation,
            campaign_id, risk_before, risk_after, approved_at, approved_by, measured_at,
            created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, 'draft', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, ?, NULL, NULL, '', NULL, ?, ?)
        """,
        (
            pid, user_id, engagement_id, oid, group_key, group["title"], group["cve"],
            group["vulns_removed"], group["assets_affected"], json.dumps(sorted(asset_ids)),
            group["internet_exposed_assets"], len(biz_critical_ids), len(patchable_ids),
            1 if group["kev"] else 0, 1 if group["quick_win"] else 0, group["critical_high_count"],
            group["estimated_risk_reduction_pct"], group["attack_paths_disrupted"],
            group["business_critical_paths_disrupted"], group["verified_attack_paths_disrupted"],
            band, explanation,
            baseline_score, ts, ts,
        ),
    )
    c.commit()
    audit("remediation_plan_create", user_id, {"id": pid, "group_key": group_key, "title": group["title"], "org_id": oid})
    try:
        from app.services.evidence import record_evidence

        record_evidence(
            user_id,
            entity_type="remediation_plan",
            entity_id=pid,
            # The disruption band and risk-reduction estimate are computed
            # from real inventory/graph data (asset counts, business
            # criticality, agent coverage) -- "derived", not a human
            # attestation and not a guess.
            source="derived",
            confidence=0.8,
            summary=f"{band} disruption band for '{group['title']}': "
            f"{group['assets_affected']} assets, {len(biz_critical_ids)} business-critical, "
            f"{len(patchable_ids)} agent-patchable",
            detail={
                "disruption_band": band,
                "assets_affected": group["assets_affected"],
                "business_critical_assets": len(biz_critical_ids),
                "agent_patchable_assets": len(patchable_ids),
                "attack_paths_disrupted": group["attack_paths_disrupted"],
                "verified_attack_paths_disrupted": group["verified_attack_paths_disrupted"],
                "estimated_risk_reduction_pct": group["estimated_risk_reduction_pct"],
            },
            org_id=oid,
        )
    except Exception:
        pass  # evidence recording is best-effort — never block plan creation
    return get_plan(user_id, pid)


def list_plans(
    user_id: str,
    *,
    org_id: str | None = None,
    engagement_id: str | None = None,
    status: str | None = None,
) -> list[dict[str, Any]]:
    from app.tenancy import tenant_visibility_sql

    c = get_conn()
    where, args = tenant_visibility_sql(user_id, org_id=org_id)
    q = f"SELECT * FROM remediation_plans WHERE {where}"
    if engagement_id:
        q += " AND engagement_id = ?"
        args.append(engagement_id)
    if status:
        q += " AND status = ?"
        args.append(status)
    q += " ORDER BY created_at DESC LIMIT 500"
    return [row_to_dict(r) for r in c.execute(q, args).fetchall()]


def get_plan(user_id: str, plan_id: str) -> dict[str, Any] | None:
    from app.tenancy import row_visible_to_user

    c = get_conn()
    row = c.execute("SELECT * FROM remediation_plans WHERE id = ?", (plan_id,)).fetchone()
    d = row_to_dict(row) if row else None
    if d and not row_visible_to_user(user_id, d):
        return None
    return d


def approve_plan(user_id: str, plan_id: str) -> dict[str, Any] | None:
    plan = get_plan(user_id, plan_id)
    if not plan:
        return None
    if plan["status"] != "draft":
        raise ValueError(f"Plan is already '{plan['status']}' -- only a draft plan can be approved.")
    c = get_conn()
    ts = now()
    c.execute(
        "UPDATE remediation_plans SET status = 'approved', approved_at = ?, approved_by = ?, updated_at = ? WHERE id = ?",
        (ts, user_id, ts, plan_id),
    )
    c.commit()
    audit("remediation_plan_approve", user_id, {"id": plan_id})
    return get_plan(user_id, plan_id)


def reject_plan(user_id: str, plan_id: str) -> dict[str, Any] | None:
    plan = get_plan(user_id, plan_id)
    if not plan:
        return None
    if plan["status"] not in ("draft", "approved"):
        raise ValueError(f"Plan is already '{plan['status']}' -- cannot reject.")
    c = get_conn()
    ts = now()
    c.execute("UPDATE remediation_plans SET status = 'rejected', updated_at = ? WHERE id = ?", (ts, plan_id))
    c.commit()
    audit("remediation_plan_reject", user_id, {"id": plan_id})
    return get_plan(user_id, plan_id)


def link_campaign(user_id: str, plan_id: str, campaign_id: str) -> dict[str, Any] | None:
    """Attach a REAL, already-created Patch Campaign to an approved plan,
    moving it to 'executing'. This module never creates the campaign
    itself -- see the module docstring for why."""
    from app.agents import get_campaign

    plan = get_plan(user_id, plan_id)
    if not plan:
        return None
    if plan["status"] != "approved":
        raise ValueError(f"Plan must be 'approved' before linking a campaign (currently '{plan['status']}').")
    campaign = get_campaign(user_id, campaign_id)
    if not campaign:
        raise ValueError("Campaign not found or not visible to this user.")
    c = get_conn()
    ts = now()
    c.execute(
        "UPDATE remediation_plans SET status = 'executing', campaign_id = ?, updated_at = ? WHERE id = ?",
        (campaign_id, ts, plan_id),
    )
    c.commit()
    audit("remediation_plan_link_campaign", user_id, {"id": plan_id, "campaign_id": campaign_id})
    return get_plan(user_id, plan_id)


def remeasure_plan(user_id: str, plan_id: str, *, org_id: str | None = None, engagement_id: str | None = None) -> dict[str, Any] | None:
    """Recompute the real organizational risk score right now and record it
    as this plan's risk_after -- an honest "what's the risk today", not a
    simulated projection. Moves an executing/approved plan to 'measured'."""
    from app.services.risk_priority import compute_org_risk_score

    plan = get_plan(user_id, plan_id)
    if not plan:
        return None
    if plan["status"] not in ("executing", "approved", "verified"):
        raise ValueError(f"Plan must be approved or executing before it can be remeasured (currently '{plan['status']}').")
    current = compute_org_risk_score(user_id, org_id=org_id, engagement_id=engagement_id)
    c = get_conn()
    ts = now()
    c.execute(
        "UPDATE remediation_plans SET status = 'measured', risk_after = ?, measured_at = ?, updated_at = ? WHERE id = ?",
        (current["score"], ts, ts, plan_id),
    )
    c.commit()
    audit("remediation_plan_remeasure", user_id, {"id": plan_id, "risk_after": current["score"]})
    return get_plan(user_id, plan_id)


def delete_plan(user_id: str, plan_id: str) -> bool:
    plan = get_plan(user_id, plan_id)
    if not plan:
        return False
    c = get_conn()
    cur = c.execute("DELETE FROM remediation_plans WHERE id = ?", (plan_id,))
    c.commit()
    if cur.rowcount:
        audit("remediation_plan_delete", user_id, {"id": plan_id})
        return True
    return False
