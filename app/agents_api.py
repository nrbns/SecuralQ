"""SecuraIQ native agent API — enrollment (user-authed) + check-in (agent-authed).

Mounted at /api/agents.
"""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Depends, Header, HTTPException
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel, Field

from app.agents import (
    approve_command,
    authenticate_agent,
    checkin,
    delete_agent,
    enroll_agent,
    get_agent,
    list_agents,
    list_commands,
    list_pending_commands,
    list_threats,
    record_threat_detections,
    reject_command,
    report_command_result,
    request_command,
    revoke_agent,
)
from app.auth import AuthUser
from app.commercial_api import require_user
from app.config import settings
from app.db import audit
from app.paths import resource_root

router = APIRouter(prefix="/api/agents", tags=["securaiq-agent"])

# resource_root() (not Path(__file__).parent.parent) so this also resolves
# correctly in a packaged .exe: PyInstaller archives this module's source
# inside the bundle rather than leaving it as a real file next to a real
# "scripts" folder, so __file__-relative lookup silently 404'd the install
# scripts in a built EXE even though it worked when run from source. The
# packaging spec (packaging/securaiq.spec) bundles exactly these four
# files under "scripts/" in the onedir output; resource_root() points at
# that same bundled root in a frozen build and at the repo root otherwise.
_SCRIPTS_DIR = resource_root() / "scripts"
_AGENT_SCRIPT_PATH = _SCRIPTS_DIR / "securaiq_agent.py"
_INSTALLER_PATHS = {
    "linux": (_SCRIPTS_DIR / "install_agent_linux.sh", "text/x-shellscript", "install_agent_linux.sh"),
    "macos": (_SCRIPTS_DIR / "install_agent_macos.sh", "text/x-shellscript", "install_agent_macos.sh"),
    "windows": (_SCRIPTS_DIR / "install_agent_windows.ps1", "text/plain", "install_agent_windows.ps1"),
}


class EnrollRequest(BaseModel):
    name: str = Field(default="", max_length=120)


class ThreatDetection(BaseModel):
    severity: str = "medium"
    category: str = "behavioral"
    title: str = "Suspicious activity detected"
    detail: str = ""
    target: str = ""
    hash: str = ""


class ThreatReport(BaseModel):
    detections: list[ThreatDetection] = Field(default_factory=list)


class CommandCreate(BaseModel):
    # patch_package payload shape: {"manager": "apt|winget|brew|pip",
    # "package": "<name>", "target_version": "<optional>"}
    kind: str = "patch_package"
    payload: dict[str, Any] = Field(default_factory=dict)


class CommandResultReport(BaseModel):
    status: str = "done"
    result: dict[str, Any] = Field(default_factory=dict)


class CommandReject(BaseModel):
    reason: str = ""


class CheckinPayload(BaseModel):
    hostname: str = ""
    ip: str = ""
    os: str = ""
    os_version: str = ""
    agent_version: str = ""
    listening_ports: list[int] = Field(default_factory=list)
    processes: list[dict[str, Any]] = Field(default_factory=list)
    packages: list[dict[str, Any]] = Field(default_factory=list)
    file_integrity: list[dict[str, Any]] = Field(default_factory=list)
    uptime_sec: float | None = None


def _parse_agent_bearer(value: str | None) -> tuple[str, str]:
    """Agent auth header: `Authorization: Bearer <agent_id>.<agent_key>`."""
    raw = (value or "").strip()
    if raw.lower().startswith("bearer "):
        raw = raw[7:].strip()
    if "." not in raw:
        return "", ""
    aid, _, key = raw.partition(".")
    return aid, key


@router.post("/enroll")
async def api_enroll_agent(req: EnrollRequest, user: Annotated[AuthUser, Depends(require_user)]):
    """Create a new agent identity. Returns the install one-liner + raw key ONCE."""
    result = enroll_agent(user.id, name=req.name)
    audit("agent_enroll", user.id, {"agent_id": result["agent_id"], "name": req.name})
    token = f"{result['agent_id']}.{result['agent_key']}"
    return {
        "agent_id": result["agent_id"],
        "agent_token": token,
        "install_hint": (
            "Manual (foreground, for testing):\n"
            f"  curl -fsSL <this-server-url>/api/agents/install-script -o securaiq_agent.py\n"
            f"  python3 securaiq_agent.py --server <this-server-url> --token {token}\n"
            "\n"
            "As a persistent service (starts on boot, auto-restarts — like a Wazuh agent):\n"
            "  Linux:   curl -fsSL <this-server-url>/api/agents/install-script -o securaiq_agent.py && "
            "curl -fsSL <this-server-url>/api/agents/install-script/linux -o install_agent_linux.sh && "
            f"chmod +x install_agent_linux.sh && sudo ./install_agent_linux.sh --server <this-server-url> --token {token}\n"
            "  macOS:   same as Linux but with install-script/macos and install_agent_macos.sh\n"
            "  Windows (elevated PowerShell):\n"
            "    curl -fsSL <this-server-url>/api/agents/install-script -o securaiq_agent.py\n"
            "    curl -fsSL <this-server-url>/api/agents/install-script/windows -o install_agent_windows.ps1\n"
            f"    .\\install_agent_windows.ps1 -Server <this-server-url> -Token {token}\n"
            "\n"
            "Save this token now — it is shown only once and cannot be recovered."
        ),
    }


@router.get("/install-script")
async def api_agent_install_script():
    """Serve the real agent script — no auth required, contains no secrets."""
    if not _AGENT_SCRIPT_PATH.is_file():
        raise HTTPException(status_code=404, detail="Agent script not found on this server")
    return PlainTextResponse(
        _AGENT_SCRIPT_PATH.read_text(encoding="utf-8"),
        media_type="text/x-python",
        headers={"Content-Disposition": "attachment; filename=securaiq_agent.py"},
    )


@router.get("/install-script/{platform}")
async def api_agent_install_script_platform(platform: str):
    """Serve a persistent-service installer (systemd / launchd / Scheduled
    Task) for the given platform — no auth required, contains no secrets
    (the enrollment token is supplied separately by whoever runs it)."""
    entry = _INSTALLER_PATHS.get(platform.lower())
    if not entry:
        raise HTTPException(status_code=404, detail=f"Unknown platform '{platform}'. Use linux, macos, or windows.")
    path, media_type, filename = entry
    if not path.is_file():
        raise HTTPException(status_code=404, detail="Installer script not found on this server")
    return PlainTextResponse(
        path.read_text(encoding="utf-8"),
        media_type=media_type,
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


@router.get("")
async def api_list_agents(user: Annotated[AuthUser, Depends(require_user)]):
    return {"agents": list_agents(user.id)}


@router.get("/threats")
async def api_list_all_threats(user: Annotated[AuthUser, Depends(require_user)], limit: int = 200):
    # Registered before /{agent_id} on purpose — a single literal path
    # segment would otherwise be swallowed by the dynamic agent_id route.
    return {"threats": list_threats(user.id, limit=limit)}


@router.get("/commands/pending")
async def api_list_pending_commands(user: Annotated[AuthUser, Depends(require_user)], limit: int = 200):
    # Registered before /{agent_id} on purpose — same reason as /threats above.
    return {"commands": list_pending_commands(user.id, limit=limit)}


@router.get("/{agent_id}")
async def api_get_agent(agent_id: str, user: Annotated[AuthUser, Depends(require_user)]):
    agent = get_agent(agent_id)
    if not agent or agent.get("user_id") != user.id:
        raise HTTPException(status_code=404, detail="Agent not found")
    return agent


@router.post("/{agent_id}/revoke")
async def api_revoke_agent(agent_id: str, user: Annotated[AuthUser, Depends(require_user)]):
    ok = revoke_agent(user.id, agent_id)
    if not ok:
        raise HTTPException(status_code=404, detail="Agent not found")
    audit("agent_revoke", user.id, {"agent_id": agent_id})
    return {"ok": True}


@router.delete("/{agent_id}")
async def api_delete_agent(agent_id: str, user: Annotated[AuthUser, Depends(require_user)]):
    ok = delete_agent(user.id, agent_id)
    if not ok:
        raise HTTPException(status_code=404, detail="Agent not found")
    audit("agent_delete", user.id, {"agent_id": agent_id})
    return {"ok": True}


@router.post("/checkin")
async def api_agent_checkin(
    payload: CheckinPayload,
    authorization: Annotated[str | None, Header(alias="Authorization")] = None,
):
    """Real telemetry check-in from an installed agent. Agent-token auth only
    (no user session) — this is what runs unattended on a monitored server."""
    agent_id, raw_key = _parse_agent_bearer(authorization)
    if not agent_id or not raw_key:
        raise HTTPException(status_code=401, detail="Missing or malformed agent token")
    agent = authenticate_agent(agent_id, raw_key)
    if not agent:
        raise HTTPException(status_code=401, detail="Invalid or revoked agent token")
    result = checkin(agent_id, payload.model_dump())
    if not result.get("ok"):
        raise HTTPException(status_code=400, detail=result.get("error") or "Check-in failed")
    return result


@router.post("/threat")
async def api_agent_threat(
    payload: ThreatReport,
    authorization: Annotated[str | None, Header(alias="Authorization")] = None,
):
    """Real-time threat/malware detections from an agent's SecuraIQ Sentinel
    watcher — a live push, not a check-in field, so it reaches the SOC and
    creates a finding/incident the moment it's ingested."""
    agent_id, raw_key = _parse_agent_bearer(authorization)
    if not agent_id or not raw_key:
        raise HTTPException(status_code=401, detail="Missing or malformed agent token")
    agent = authenticate_agent(agent_id, raw_key)
    if not agent:
        raise HTTPException(status_code=401, detail="Invalid or revoked agent token")
    result = record_threat_detections(agent_id, [d.model_dump() for d in payload.detections])
    if not result.get("ok"):
        raise HTTPException(status_code=400, detail=result.get("error") or "Threat report failed")
    return result


@router.get("/{agent_id}/threats")
async def api_list_agent_threats(
    agent_id: str, user: Annotated[AuthUser, Depends(require_user)], limit: int = 100
):
    agent = get_agent(agent_id)
    if not agent or agent.get("user_id") != user.id:
        raise HTTPException(status_code=404, detail="Agent not found")
    return {"threats": list_threats(user.id, agent_id=agent_id, limit=limit)}


@router.post("/{agent_id}/commands")
async def api_queue_agent_command(
    agent_id: str, req: CommandCreate, user: Annotated[AuthUser, Depends(require_user)]
):
    """Request a command for this agent — lands in 'pending_approval', not
    delivered yet. A second call to the approve endpoint is required before
    it is ever handed to the agent (see api_approve_agent_command below)."""
    try:
        result = request_command(user.id, agent_id, kind=req.kind, payload=req.payload, requested_by=user.id)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    audit("agent_command_request", user.id, {"agent_id": agent_id, "kind": req.kind, "payload": req.payload})
    return result


@router.get("/{agent_id}/commands")
async def api_list_agent_commands(
    agent_id: str, user: Annotated[AuthUser, Depends(require_user)], limit: int = 100
):
    agent = get_agent(agent_id)
    if not agent or agent.get("user_id") != user.id:
        raise HTTPException(status_code=404, detail="Agent not found")
    return {"commands": list_commands(user.id, agent_id, limit=limit)}


def _require_admin_for_approval(user: AuthUser) -> None:
    """Approving/rejecting a queued OS-package-manager command is the real
    approval gate for patch execution, so once RBAC/auth is turned on it is
    restricted to admins — same inline-check convention as the rest of the
    codebase (e.g. app/commercial_api.py). In local/lab mode (auth disabled)
    the synthetic local user is already role="admin", so this never blocks
    normal solo-operator usage."""
    if settings.auth_enabled and user.role != "admin" and user.id != "local":
        raise HTTPException(status_code=403, detail="Admin role required to approve or reject agent commands")


@router.post("/{agent_id}/commands/{command_id}/approve")
async def api_approve_agent_command(
    agent_id: str, command_id: str, user: Annotated[AuthUser, Depends(require_user)]
):
    _require_admin_for_approval(user)
    try:
        result = approve_command(user.id, agent_id, command_id, approver_id=user.id)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return result


@router.post("/{agent_id}/commands/{command_id}/reject")
async def api_reject_agent_command(
    agent_id: str, command_id: str, req: CommandReject, user: Annotated[AuthUser, Depends(require_user)]
):
    _require_admin_for_approval(user)
    try:
        result = reject_command(user.id, agent_id, command_id, approver_id=user.id, reason=req.reason)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return result


@router.post("/commands/{command_id}/result")
async def api_report_command_result(
    command_id: str,
    req: CommandResultReport,
    authorization: Annotated[str | None, Header(alias="Authorization")] = None,
):
    """Agent reports the outcome of a command it executed — agent-token auth
    only, same as /checkin and /threat (this runs unattended, no user
    session)."""
    agent_id, raw_key = _parse_agent_bearer(authorization)
    if not agent_id or not raw_key:
        raise HTTPException(status_code=401, detail="Missing or malformed agent token")
    agent = authenticate_agent(agent_id, raw_key)
    if not agent:
        raise HTTPException(status_code=401, detail="Invalid or revoked agent token")
    result = report_command_result(agent_id, command_id, status=req.status, result=req.result)
    if not result.get("ok"):
        raise HTTPException(status_code=404, detail=result.get("error") or "Unknown command")
    return result
