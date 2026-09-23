"""Phase completion + remaining Phase 2–5 APIs."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from app.auth import AuthUser
from app.commercial_api import require_user
from app.checklist_board import all_checklists_board
from app.phase_board import all_phases_board
from app.rbac import require_perm
from app.service_impact import services_affected_by_vuln
from app.toxic_combos import compute_toxic_combinations

router = APIRouter(tags=["phases"])


class WhiteLabelIn(BaseModel):
    name: str = Field(default="", max_length=80)
    accent: str = Field(default="", max_length=20)


@router.get("/api/phases")
async def api_phases():
    return all_phases_board()


@router.get("/api/checklists")
async def api_checklists():
    return all_checklists_board()


@router.get("/api/exposure/toxic")
async def api_toxic(user: Annotated[AuthUser, Depends(require_user)]):
    return compute_toxic_combinations(user.id)


@router.get("/api/services/affected")
async def api_services_affected(
    user: Annotated[AuthUser, Depends(require_user)],
    vuln_id: str | None = None,
):
    return services_affected_by_vuln(user.id, vuln_id=vuln_id)


@router.post("/api/mssp/{org_id}/white-label")
async def api_white_label(
    org_id: str,
    body: WhiteLabelIn,
    user: Annotated[AuthUser, Depends(require_user)],
):
    require_perm(user, "org.manage", org_id=org_id)
    from app.mssp import set_white_label

    return set_white_label(org_id, name=body.name, accent=body.accent)


@router.get("/api/mssp/{org_id}/central-soc")
async def api_central_soc(org_id: str, user: Annotated[AuthUser, Depends(require_user)]):
    require_perm(user, "workspace.read", org_id=org_id)
    from app.mssp import can_access_child, central_soc_summary, is_mssp_parent

    if not (is_mssp_parent(org_id) or can_access_child(org_id, org_id)):
        raise HTTPException(status_code=404, detail="org not found")
    return central_soc_summary(org_id)
