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

from fastapi import APIRouter, Depends

from app.auth import AuthUser
from app.commercial_api import require_user
from app.services.attack_graph import build_graph, compute_attack_paths
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
