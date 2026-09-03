"""API routes for the risk prioritization engine — "what to fix first",
the organizational risk score, the risk-reduction simulator, and the
attack-path graph.

See app/services/risk_priority.py for the scoring/ranking/simulation logic,
app/services/risk_snapshots.py for the before/after campaign tracking, and
app/services/attack_graph.py for the graph/path computation (declaring an
asset dependency is a separate route, on the assets resource — see
POST /api/assets/{asset_id}/dependencies in app/enterprise_api.py). This
module is intentionally thin: it just authenticates the request and calls
through, same pattern as the other *_api.py routers.
"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from app.auth import AuthUser
from app.commercial_api import require_user
from app.services.attack_graph import build_graph, compute_attack_paths
from app.services.remediation import (
    approve_plan,
    create_plan,
    delete_plan,
    get_plan,
    link_campaign,
    list_plans,
    reject_plan,
    remeasure_plan,
)
from app.services.risk_priority import compute_org_risk_score, compute_priority_list, compute_risk_simulation

router = APIRouter(prefix="/api/risk", tags=["risk-priority"])


@router.get("/priority")
async def get_priority_list(user: Annotated[AuthUser, Depends(require_user)], limit: int = 25):
    """Ranked 'what to fix first' list across this user's open findings."""
    return compute_priority_list(user.id, limit=limit)


@router.get("/organizational-score")
async def get_organizational_score(user: Annotated[AuthUser, Depends(require_user)]):
    """The single headline exposure number — mean risk score across every
    open finding. Same formula as /priority, just aggregated."""
    return compute_org_risk_score(user.id)


@router.get("/simulate")
async def get_risk_simulation(user: Annotated[AuthUser, Depends(require_user)], limit: int = 10):
    """"If you fix these, here's the estimated impact" — grouped findings
    ranked by estimated risk-reduction contribution, plus the combined
    reduction of doing the top 3."""
    return compute_risk_simulation(user.id, limit=limit)


@router.get("/attack-graph")
async def get_attack_graph(user: Annotated[AuthUser, Depends(require_user)]):
    """Raw node/edge list — Asset, Software, Vulnerability, Internet
    exposure, web-facing assets tagged as Application, Identity (only when
    an asset has service_accounts set), plus connects_to edges (declared or
    inferred — see app/services/attack_graph.py for what each source means)."""
    return build_graph(user.id)


@router.get("/attack-paths")
async def get_attack_paths(
    user: Annotated[AuthUser, Depends(require_user)],
    limit: int = 25,
    max_depth: int = 4,
):
    """Ranked Internet -> ... -> asset routes, each with a real attack_path_risk
    (vuln_risk x exposure_confidence x business_impact x path_length_factor)."""
    return compute_attack_paths(user.id, limit=limit, max_depth=max_depth)


# --- Remediation Intelligence --------------------------------------------
# A Remediation Plan is a frozen, comparable snapshot of one Risk Reduction
# Simulator group -- see app/services/remediation.py for the full pipeline
# this closes: graph -> risk engine -> top remediation -> plan -> approval
# -> (real) patch campaign -> verification -> remeasured risk.


class RemediationPlanCreate(BaseModel):
    group_key: str = Field(min_length=1)


class RemediationPlanLinkCampaign(BaseModel):
    campaign_id: str = Field(min_length=1)


@router.post("/remediation-plans")
async def remediation_plan_create(req: RemediationPlanCreate, user: Annotated[AuthUser, Depends(require_user)]):
    """Snapshot a live simulator group (by its group_key, from GET
    /api/risk/simulate) into a persisted, comparable plan."""
    try:
        return create_plan(user.id, req.group_key)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e


@router.get("/remediation-plans")
async def remediation_plan_list(user: Annotated[AuthUser, Depends(require_user)], status: str | None = None):
    return {"plans": list_plans(user.id, status=status)}


@router.get("/remediation-plans/{plan_id}")
async def remediation_plan_get(plan_id: str, user: Annotated[AuthUser, Depends(require_user)]):
    plan = get_plan(user.id, plan_id)
    if not plan:
        raise HTTPException(status_code=404, detail="Remediation plan not found")
    return plan


@router.post("/remediation-plans/{plan_id}/approve")
async def remediation_plan_approve(plan_id: str, user: Annotated[AuthUser, Depends(require_user)]):
    try:
        plan = approve_plan(user.id, plan_id)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e
    if not plan:
        raise HTTPException(status_code=404, detail="Remediation plan not found")
    return plan


@router.post("/remediation-plans/{plan_id}/reject")
async def remediation_plan_reject(plan_id: str, user: Annotated[AuthUser, Depends(require_user)]):
    try:
        plan = reject_plan(user.id, plan_id)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e
    if not plan:
        raise HTTPException(status_code=404, detail="Remediation plan not found")
    return plan


@router.post("/remediation-plans/{plan_id}/link-campaign")
async def remediation_plan_link_campaign(plan_id: str, req: RemediationPlanLinkCampaign, user: Annotated[AuthUser, Depends(require_user)]):
    """Link an already-created Patch Campaign (see POST
    /api/agents/campaigns) to an approved plan. This route never creates a
    campaign itself -- see app/services/remediation.py's module docstring
    for why."""
    try:
        plan = link_campaign(user.id, plan_id, req.campaign_id)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e
    if not plan:
        raise HTTPException(status_code=404, detail="Remediation plan not found")
    return plan


@router.post("/remediation-plans/{plan_id}/remeasure")
async def remediation_plan_remeasure(plan_id: str, user: Annotated[AuthUser, Depends(require_user)]):
    """Recompute the real organizational risk score right now and record it
    as this plan's risk_after -- an honest snapshot, not a projection."""
    try:
        plan = remeasure_plan(user.id, plan_id)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e
    if not plan:
        raise HTTPException(status_code=404, detail="Remediation plan not found")
    return plan


@router.delete("/remediation-plans/{plan_id}")
async def remediation_plan_delete(plan_id: str, user: Annotated[AuthUser, Depends(require_user)]):
    if not delete_plan(user.id, plan_id):
        raise HTTPException(status_code=404, detail="Remediation plan not found")
    return {"ok": True}
