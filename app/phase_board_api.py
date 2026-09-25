"""Phase completion + remaining Phase 2–5 APIs."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from app.auth import AuthUser
from app.commercial_api import require_user
from app.checklist_board import all_checklists_board
from app.phase_board import all_phases_board
from app.total_phase_board import total_phase_board
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


@router.get("/api/phases/total")
async def api_total_phases():
    return total_phase_board()


@router.post("/api/launch/loop")
async def api_launch_loop(user: Annotated[AuthUser, Depends(require_user)]):
    from app.launch_loop import run_launch_loop

    return run_launch_loop(user.id)


@router.get("/api/exposure/toxic")
async def api_toxic(user: Annotated[AuthUser, Depends(require_user)]):
    return compute_toxic_combinations(user.id)


class EasmDiscoverIn(BaseModel):
    seeds: list[str] = Field(default_factory=list)
    include_cert_sans: bool = False


@router.post("/api/easm/discover")
async def api_easm_discover(
    user: Annotated[AuthUser, Depends(require_user)],
    body: EasmDiscoverIn | None = None,
):
    from app.easm import discover_attack_surface

    req = body or EasmDiscoverIn()
    return discover_attack_surface(
        user.id,
        extra_seeds=req.seeds,
        include_cert_sans=req.include_cert_sans,
    )


@router.get("/api/easm/status")
async def api_easm_status(_user: Annotated[AuthUser, Depends(require_user)]):
    from app.easm import easm_status

    return easm_status()


@router.get("/api/exposure/changes")
async def api_host_changes(user: Annotated[AuthUser, Depends(require_user)]):
    from app.host_change import list_host_changes

    return list_host_changes(user.id)


@router.get("/api/decisions/drawer")
async def api_decision_drawer(
    user: Annotated[AuthUser, Depends(require_user)],
    kind: str = "risk",
    target_id: str = "",
):
    from app.decision_drawer import build_decision_drawer

    return build_decision_drawer(user.id, kind=kind, target_id=target_id)


@router.get("/api/command-center/pulse")
async def api_command_center_pulse(user: Annotated[AuthUser, Depends(require_user)]):
    from app.command_center_pulse import command_center_pulse

    return command_center_pulse(user.id)


@router.get("/api/compliance/why")
async def api_compliance_why(user: Annotated[AuthUser, Depends(require_user)]):
    from app.controls.live_compliance import explain_live_compliance

    return explain_live_compliance(user.id)


@router.get("/api/truth/indicators")
async def api_truth_indicators(user: Annotated[AuthUser, Depends(require_user)]):
    from app.control_truth import truth_indicators

    return truth_indicators(user.id)


@router.get("/api/compliance/profile")
async def api_compliance_profile(user: Annotated[AuthUser, Depends(require_user)]):
    from app.nist_profile import organizational_profile

    return organizational_profile(user.id)


class OrgProfileIn(BaseModel):
    target_percent: float | None = None
    current_tier: int | None = None
    target_tier: int | None = None


@router.post("/api/compliance/profile")
async def api_set_compliance_profile(
    user: Annotated[AuthUser, Depends(require_user)],
    body: OrgProfileIn | None = None,
):
    from app.nist_profile import organizational_profile, set_org_profile

    req = body or OrgProfileIn()
    set_org_profile(
        user.id,
        target_percent=req.target_percent,
        current_tier=req.current_tier,
        target_tier=req.target_tier,
    )
    return organizational_profile(user.id)


@router.get("/api/launch/plan")
async def api_launch_plan():
    from app.launch_plan import launch_plan_board

    return launch_plan_board()


@router.get("/api/launch/complete")
async def api_launch_complete():
    from app.launch_complete import launch_complete_board

    return launch_complete_board()


@router.get("/api/launch/agent-parity")
async def api_agent_parity():
    from app.agent_parity import agent_parity_status

    return agent_parity_status()


@router.get("/api/incidents/{incident_id}/timeline")
async def api_incident_timeline(
    incident_id: str, user: Annotated[AuthUser, Depends(require_user)]
):
    from app.incident_timeline import incident_timeline

    row = incident_timeline(user.id, incident_id)
    if not row:
        raise HTTPException(status_code=404, detail="Incident not found")
    return row


@router.get("/api/ops/restart-recovery")
async def api_restart_recovery(_user: Annotated[AuthUser, Depends(require_user)]):
    from app.restart_recovery import restart_recovery_status

    return restart_recovery_status()


@router.get("/api/ops/measured")
async def api_measured_ops(_user: Annotated[AuthUser, Depends(require_user)]):
    from app.measured_ops import measured_ops_board

    return measured_ops_board()


@router.get("/api/ops/perf-hardening")
async def api_perf_hardening(_user: Annotated[AuthUser, Depends(require_user)]):
    from app.perf_hardening import perf_hardening_board

    return perf_hardening_board()


@router.get("/api/services/graph")
async def api_service_graph(user: Annotated[AuthUser, Depends(require_user)]):
    from app.service_impact import service_graph

    return service_graph(user.id)


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
