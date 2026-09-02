"""API routes for the risk prioritization engine — "what to fix first",
the organizational risk score, and the risk-reduction simulator.

See app/services/risk_priority.py for the scoring/ranking/simulation logic
and app/services/risk_snapshots.py for the before/after campaign tracking.
This module is intentionally thin: it just authenticates the request and
calls through, same pattern as the other *_api.py routers.
"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends

from app.auth import AuthUser
from app.commercial_api import require_user
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
