"""API routes for the Canonical Control Registry -- see
app/services/canonical_controls.py for the cross-framework engine this
exposes. Thin router: authenticate, call through, return.
"""

from __future__ import annotations

import time
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException
from starlette.concurrency import run_in_threadpool

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

# Short TTL cache — soft-poll / Mission Control must not re-scan every assessment
# on every tick (was blocking the asyncio event loop → false "Server offline").
_STATUS_CACHE: dict[str, tuple[float, list[dict[str, Any]]]] = {}
_STATUS_TTL_SEC = 8.0


def _cached_all_statuses(user_id: str) -> list[dict[str, Any]]:
    now = time.monotonic()
    hit = _STATUS_CACHE.get(user_id)
    if hit and (now - hit[0]) < _STATUS_TTL_SEC:
        return hit[1]
    rows = compute_all_canonical_statuses(user_id)
    _STATUS_CACHE[user_id] = (now, rows)
    return rows


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
    statuses = await run_in_threadpool(_cached_all_statuses, user.id)
    return {"statuses": statuses}


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
    result = await run_in_threadpool(compute_canonical_status, user.id, canonical_id)
    if not result:
        raise HTTPException(status_code=404, detail="Canonical control not found")
    return result
