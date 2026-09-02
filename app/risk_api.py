"""API routes for the risk prioritization engine — "what to fix first".

See app/services/risk_priority.py for the scoring/ranking logic. This
module is intentionally thin: it just authenticates the request and calls
through, same pattern as the other *_api.py routers.
"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends

from app.auth import AuthUser
from app.commercial_api import require_user
from app.services.risk_priority import compute_priority_list

router = APIRouter(prefix="/api/risk", tags=["risk-priority"])


@router.get("/priority")
async def get_priority_list(user: Annotated[AuthUser, Depends(require_user)], limit: int = 25):
    """Ranked 'what to fix first' list across this user's open findings."""
    return compute_priority_list(user.id, limit=limit)
