"""API routes for the Canonical Control Registry -- see
app/services/canonical_controls.py for the cross-framework engine this
exposes. Thin router: authenticate, call through, return.
"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException

from app.auth import AuthUser
from app.commercial_api import require_user
from app.services.canonical_controls import (
    canonical_controls_for,
    compute_all_canonical_statuses,
    compute_canonical_status,
    get_canonical_control,
    list_canonical_controls,
)

router = APIRouter(prefix="/api/canonical-controls", tags=["canonical-controls"])


@router.get("")
async def api_list_canonical_controls(_user: Annotated[AuthUser, Depends(require_user)]):
    """The static registry -- every canonical control and its cross-framework
    mapping, independent of any one user's assessment data."""
    return {"canonical_controls": list_canonical_controls()}


@router.get("/status")
async def api_all_canonical_statuses(user: Annotated[AuthUser, Depends(require_user)]):
    """Real per-canonical-control status computed from this user's actual
    latest assessment in each mapped framework -- 'implement once, satisfied
    in N frameworks' backed by real scored data, not a theoretical mapping."""
    return {"statuses": compute_all_canonical_statuses(user.id)}


@router.get("/for-control")
async def api_canonical_controls_for(
    framework_id: str, control_id: str, _user: Annotated[AuthUser, Depends(require_user)]
):
    """Reverse lookup: which canonical control(s) does this specific
    framework control belong to? Powers 'this also satisfies N other
    frameworks' shown inline next to a single control."""
    return {"canonical_controls": canonical_controls_for(framework_id, control_id)}


@router.get("/{canonical_id}")
async def api_get_canonical_control(canonical_id: str, _user: Annotated[AuthUser, Depends(require_user)]):
    result = get_canonical_control(canonical_id)
    if not result:
        raise HTTPException(status_code=404, detail="Canonical control not found")
    return result


@router.get("/{canonical_id}/status")
async def api_canonical_control_status(canonical_id: str, user: Annotated[AuthUser, Depends(require_user)]):
    """Real cross-framework status for one canonical control, computed from
    this user's actual assessments (never a static/theoretical claim)."""
    result = compute_canonical_status(user.id, canonical_id)
    if not result:
        raise HTTPException(status_code=404, detail="Canonical control not found")
    return result
