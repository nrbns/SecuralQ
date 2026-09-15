"""SecuraIQ native agent API — enrollment (user-authed) + check-in (agent-authed).

Mounted at /api/agents.
"""

from __future__ import annotations

from pathlib import Path
from typing import Annotated, Any

from fastapi import APIRouter, Depends, Header, HTTPException, Request
from fastapi.responses import FileResponse, PlainTextResponse
from pydantic import BaseModel, Field, ValidationError

from app.agent_auth import parse_agent_bearer, verify_replay_and_signature
from app.agents import (
    ack_command,
    approve_campaign,
    approve_command,
    authenticate_agent,
    agent_visible_to_user,
    checkin,
    create_campaign,
    create_enroll_token,
    delete_agent,
    enroll_agent,
    enroll_agent_with_token,
    get_agent,
    get_campaign,
    list_agents,
    list_campaigns,
    list_commands,
    list_pending_commands,
    list_threats,
    record_threat_detections,
    reject_campaign,
    reject_command,
    report_command_result,
    request_agent_upgrade,
    request_command,
    request_enable_defender_command,
    request_enable_firewall_command,
    request_disable_ssh_root_command,
    revoke_agent,
    revoke_enroll_token,
)
from app.auth import AuthUser
from app.commercial_api import require_user
from app.config import settings
from app.db import audit
from app.paths import project_root, resource_root
from app.rbac import require_perm
from app.tenancy import optional_org_header, resolve_request_org

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
_PACKAGE_DIR = project_root() / "dist" / "agent-packages"
_PACKAGE_SUFFIXES = (".exe", ".zip", ".tar.gz", ".dmg", ".tgz", ".msi", ".deb", ".rpm")

def _org_for(user: AuthUser, header_org: str | None) -> str | None:
    try:
        return resolve_request_org(user, header_org=header_org)
    except Exception:
        return (header_org or "").strip() or None


class EnrollRequest(BaseModel):
    name: str = Field(default="", max_length=120)
    org_id: str | None = None


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


class CampaignCreate(BaseModel):
    name: str = Field(default="", max_length=160)
    manager: str
    package: str
    target_version: str = ""
    # Flat list = single-ring campaign (all targets in ring 0). For a phased
    # rollout (lab -> staging -> production), pass `rings` instead: an
    # ordered list of agent-id lists. Ring 0 is requested immediately; each
    # later ring is only created once the prior ring's success rate clears
    # ring_threshold_pct (see app.agents._maybe_advance_campaign_ring).
    agent_ids: list[str] = Field(default_factory=list)
    rings: list[list[str]] | None = None
    ring_threshold_pct: float = 100
    # Maintenance window: an approved+queued command still won't be handed
    # to its agent outside this window. Hours are UTC, 0-23; -1 means "no
    # window" (always eligible). window_days uses Python weekday() (Mon=0..
    # Sun=6); empty means every day.
    window_start_hour: int = -1
    window_end_hour: int = -1
    window_days: list[int] = Field(default_factory=list)


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
    # Deep telemetry (task #140) -- each is the collector's own
    # {"collected": bool, "reason": str, ...} shape from
    # scripts/securaiq_agent.py; a field simply absent from an older agent's
    # check-in defaults to {} rather than erroring the whole check-in, and
    # the UI treats "no such key" the same as "collected: false".
    services: dict[str, Any] = Field(default_factory=dict)
    local_users: dict[str, Any] = Field(default_factory=dict)
    local_groups: dict[str, Any] = Field(default_factory=dict)
    hardware: dict[str, Any] = Field(default_factory=dict)
    network: dict[str, Any] = Field(default_factory=dict)
    firewall_status: dict[str, Any] = Field(default_factory=dict)
    disk_encryption_status: dict[str, Any] = Field(default_factory=dict)
    defender_status: dict[str, Any] = Field(default_factory=dict)
    startup_apps: dict[str, Any] = Field(default_factory=dict)
    ssh_config: dict[str, Any] = Field(default_factory=dict)
    # Phase 3 Rust/Python — bounded recent security log sample (optional).
    security_logs: dict[str, Any] = Field(default_factory=dict)
    # REALTIME Task D — optional offline buffer / sequence recovery (ignored by older agents).
    sequence: int | None = None
    buffered_events: list[dict[str, Any]] = Field(default_factory=list)
    request_missing_from: int | None = None


def _parse_agent_bearer(value: str | None) -> tuple[str, str]:
    return parse_agent_bearer(value)


def _org(user: AuthUser, header_org: str | None = None) -> str | None:
    return resolve_request_org(user, header_org=header_org)


def _visible_agent(user: AuthUser, agent_id: str, *, org_id: str | None = None) -> dict[str, Any]:
    agent = get_agent(agent_id)
    if not agent or not agent_visible_to_user(user.id, agent):
        raise HTTPException(status_code=404, detail="Agent not found")
    if org_id and (agent.get("org_id") or "") != org_id:
        raise HTTPException(status_code=404, detail="Agent not found")
    return agent


def _ssl_client_headers(request: Request | None) -> tuple[str | None, str | None]:
    if request is None:
        return None, None
    verify = request.headers.get("X-SSL-Client-Verify") or request.headers.get("x-ssl-client-verify")
    fp = request.headers.get("X-SSL-Client-Fingerprint") or request.headers.get(
        "x-ssl-client-fingerprint"
    )
    return verify, fp


def _authenticate_agent_request(
    authorization: str | None,
    *,
    body: bytes,
    ts: str | None = None,
    nonce: str | None = None,
    sig: str | None = None,
    request: Request | None = None,
    ssl_client_verify: str | None = None,
    ssl_client_fingerprint: str | None = None,
) -> dict[str, Any]:
    agent_id, raw_key = parse_agent_bearer(authorization)
    if not agent_id or not raw_key:
        raise HTTPException(status_code=401, detail="Missing or malformed agent token")
    agent = authenticate_agent(agent_id, raw_key)
    if not agent:
        raise HTTPException(status_code=401, detail="Invalid or revoked agent token")
    err = verify_replay_and_signature(agent, ts_header=ts, nonce=nonce, sig=sig, body=body)
    if err:
        raise HTTPException(status_code=401, detail=err)
    if ssl_client_verify is None and ssl_client_fingerprint is None and request is not None:
        ssl_client_verify, ssl_client_fingerprint = _ssl_client_headers(request)
    try:
        from app.agent_certs import verify_proxy_client_cert

        mtls_err = verify_proxy_client_cert(
            agent,
            client_verify=ssl_client_verify,
            client_fingerprint=ssl_client_fingerprint,
        )
        if mtls_err:
            raise HTTPException(status_code=401, detail=mtls_err)
    except HTTPException:
        raise
    except Exception:
        pass
    return agent


@router.post("/enroll")
async def api_enroll_agent(
    req: EnrollRequest,
    user: Annotated[AuthUser, Depends(require_user)],
    header_org: Annotated[str | None, Depends(optional_org_header)] = None,
):
    """Create a new agent identity. Returns the install one-liner + raw key ONCE."""
    oid = _org_for(user, req.org_id or header_org)
    require_perm(user, "agent.write", org_id=oid)
    try:
        result = enroll_agent(user.id, name=req.name, org_id=oid)
    except ValueError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    audit("agent_enroll", user.id, {"agent_id": result["agent_id"], "name": req.name, "org_id": oid})
    token = f"{result['agent_id']}.{result['agent_key']}"
    return {
        "agent_id": result["agent_id"],
        "agent_token": token,
        "org_id": result.get("org_id"),
        "install_hint": (
            "Save this token now — it is shown only once and cannot be recovered.\n"
            "\n"
            "Preferred — download a package from Agents → packages (no separate install scripts):\n"
            "  Windows:  SecuraIQ-Agent-*-windows-x64.exe\n"
            f"             .\\SecuraIQ-Agent.exe --server <this-server-url> --token {token}\n"
            "             Or unzip the .zip and run .\\install.ps1 -Server <url> -Token <token> (Scheduled Task).\n"
            "  Linux:    tar -xzf SecuraIQ-Agent-*-linux-*.tar.gz && cd SecuraIQ-Agent-*-linux-* &&\n"
            f"             sudo ./install.sh --server <this-server-url> --token {token}\n"
            "  macOS:    same with *-macos-*.tar.gz (+ .dmg when built on Mac/CI).\n"
            "\n"
            "Developer fallback (Python + raw install scripts — optional):\n"
            f"  python3 securaiq_agent.py --server <this-server-url> --token {token}\n"
            "  Scripts: GET /api/agents/install-script/{windows|linux|macos}\n"
        ),
        **({"mtls": result["mtls"]} if result.get("mtls") else {}),
    }


class EnrollTokenRequest(BaseModel):
    org_id: str | None = None
    ttl_sec: int = Field(default=3600, ge=60, le=604800)
    max_uses: int = Field(default=1, ge=1, le=500)
    name_hint: str = ""


class EnrollByTokenRequest(BaseModel):
    token: str
    hostname: str = ""
    platform: str = ""
    name: str = ""


@router.post("/enroll-tokens")
async def api_create_enroll_token(
    req: EnrollTokenRequest,
    user: Annotated[AuthUser, Depends(require_user)],
    header_org: Annotated[str | None, Depends(optional_org_header)] = None,
):
    """Dashboard: issue a short-lived enrollment token (shown once)."""
    oid = _org_for(user, req.org_id or header_org)
    require_perm(user, "agent.write", org_id=oid)
    try:
        result = create_enroll_token(
            user.id,
            org_id=oid,
            ttl_sec=req.ttl_sec,
            max_uses=req.max_uses,
            name_hint=req.name_hint,
        )
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    audit(
        "agent_enroll_token_create",
        user.id,
        {"token_id": result["token_id"], "org_id": oid, "max_uses": req.max_uses},
    )
    return result


@router.post("/enroll-tokens/{token_id}/revoke")
async def api_revoke_enroll_token(
    token_id: str,
    user: Annotated[AuthUser, Depends(require_user)],
):
    require_perm(user, "agent.write")
    if not revoke_enroll_token(user.id, token_id):
        raise HTTPException(status_code=404, detail="Enrollment token not found")
    audit("agent_enroll_token_revoke", user.id, {"token_id": token_id})
    return {"ok": True}


@router.post("/enroll-by-token")
async def api_enroll_by_token(req: EnrollByTokenRequest):
    """Agent/installer path: consume enrollment token → agent_id + agent_key once."""
    try:
        result = enroll_agent_with_token(
            req.token,
            hostname=req.hostname,
            platform=req.platform,
            name=req.name,
        )
    except ValueError as exc:
        msg = str(exc)
        code = 409 if "limit" in msg.lower() or "quota" in msg.lower() else 400
        raise HTTPException(status_code=code, detail=msg) from exc
    token = f"{result['agent_id']}.{result['agent_key']}"
    audit(
        "agent_enroll_by_token",
        result.get("org_id") or "system",
        {"agent_id": result["agent_id"], "hostname": req.hostname, "platform": req.platform},
    )
    return {
        "agent_id": result["agent_id"],
        "agent_token": token,
        "org_id": result.get("org_id"),
        "hostname": result.get("hostname"),
        "platform": result.get("platform"),
        **({"mtls": result["mtls"]} if result.get("mtls") else {}),
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
    """Developer fallback: serve persistent-service installers (systemd / launchd /
    Scheduled Task). Prefer packaged .exe/.zip/.tar.gz from /api/agents/packages —
    those archives already embed install.ps1 / install.sh. No secrets in these files.
    """
    entry = _INSTALLER_PATHS.get(platform.lower())
    if not entry:
        raise HTTPException(status_code=404, detail=f"Unknown platform '{platform}'. Use linux, macos, or windows.")
    path, media_type, filename = entry
    if not path.is_file():
        raise HTTPException(status_code=404, detail="Installer script not found on this server")
    return PlainTextResponse(
        path.read_text(encoding="utf-8"),
        media_type=media_type,
        headers={
            "Content-Disposition": f"attachment; filename={filename}",
            "X-SecuraIQ-Install-Path": "developer_fallback",
        },
    )


def _classify_package(name: str) -> dict[str, str]:
    lower = name.lower()
    os_name = "unknown"
    kind = "archive"
    if "windows" in lower or lower.endswith(".exe"):
        os_name = "windows"
    elif "linux" in lower:
        os_name = "linux"
    elif "macos" in lower or "darwin" in lower:
        os_name = "macos"
    if lower.endswith(".exe"):
        kind = "exe"
    elif lower.endswith(".msi"):
        kind = "msi"
        os_name = "windows"
    elif lower.endswith(".deb"):
        kind = "deb"
        os_name = "linux"
    elif lower.endswith(".rpm"):
        kind = "rpm"
        os_name = "linux"
    elif lower.endswith(".dmg"):
        kind = "dmg"
    elif lower.endswith(".tar.gz") or lower.endswith(".tgz"):
        kind = "tar"
    elif lower.endswith(".zip"):
        kind = "zip"
    return {"os": os_name, "kind": kind}


def _list_built_packages() -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    if not _PACKAGE_DIR.is_dir():
        return out
    for path in sorted(_PACKAGE_DIR.iterdir()):
        if not path.is_file():
            continue
        name = path.name
        if name.startswith("_") or name.startswith("."):
            continue
        if not any(name.lower().endswith(suf) for suf in _PACKAGE_SUFFIXES):
            continue
        meta = _classify_package(name)
        kind = meta["kind"]
        label = name
        if kind == "exe":
            label = f"Windows agent (.exe) — {name}"
        elif kind == "msi":
            label = f"Windows MSI (WiX scaffold) — {name}"
        elif kind == "zip":
            label = f"Windows package (.zip + install.ps1) — {name}"
        elif kind == "deb":
            label = f"Debian/Ubuntu .deb — {name}"
        elif kind == "rpm":
            label = f"RHEL/Fedora .rpm — {name}"
        elif kind == "tar":
            label = f"{meta['os'].title()} package (.tar.gz) — {name}"
        elif kind == "dmg":
            label = f"macOS disk image (.dmg) — {name}"
        out.append(
            {
                "filename": name,
                "os": meta["os"],
                "kind": kind,
                "size_bytes": path.stat().st_size,
                "download_url": f"/api/agents/packages/{name}",
                "built": True,
                "primary": True,
                "label": label,
            }
        )
    return out


@router.get("/packages")
async def api_agent_packages(user: Annotated[AuthUser, Depends(require_user)]):
    """Package-first catalog: built .exe / .zip / .tar.gz / .dmg, plus developer script fallbacks.

    Built packages come from dist/agent-packages/ (see scripts/build_agent_packages.py).
    Raw install_agent_*.ps1/sh and securaiq_agent.py remain available for labs without a
    native build, but are marked developer_fallback — not the primary install path.
    """
    require_perm(user, "agent.read", org_id=_org_for(user, None))
    packages = _list_built_packages()
    scripts = [
        {
            "filename": "securaiq_agent.py",
            "os": "all",
            "kind": "script",
            "download_url": "/api/agents/install-script",
            "built": _AGENT_SCRIPT_PATH.is_file(),
            "label": "Developer: Python agent script",
            "primary": False,
            "role": "developer_fallback",
        },
        {
            "filename": "install_agent_windows.ps1",
            "os": "windows",
            "kind": "installer",
            "download_url": "/api/agents/install-script/windows",
            "built": (_INSTALLER_PATHS["windows"][0]).is_file(),
            "label": "Developer: Windows install script",
            "primary": False,
            "role": "developer_fallback",
        },
        {
            "filename": "install_agent_linux.sh",
            "os": "linux",
            "kind": "installer",
            "download_url": "/api/agents/install-script/linux",
            "built": (_INSTALLER_PATHS["linux"][0]).is_file(),
            "label": "Developer: Linux install script",
            "primary": False,
            "role": "developer_fallback",
        },
        {
            "filename": "install_agent_macos.sh",
            "os": "macos",
            "kind": "installer",
            "download_url": "/api/agents/install-script/macos",
            "built": (_INSTALLER_PATHS["macos"][0]).is_file(),
            "label": "Developer: macOS install script",
            "primary": False,
            "role": "developer_fallback",
        },
    ]
    by_os = {"windows": [], "linux": [], "macos": [], "all": []}
    for p in packages + scripts:
        by_os.setdefault(p.get("os") or "unknown", []).append(p)

    dmg_available = any(p.get("kind") == "dmg" for p in packages)
    online = 0
    total = 0
    try:
        fleet = list_agents(user.id)
        total = len(fleet)
        online = sum(1 for a in fleet if (a.get("status") or "") == "online")
    except Exception:
        pass

    notes = [
        "Prefer packaged .exe / .zip / .tar.gz (install.ps1 / install.sh are inside the archive). Raw install_agent_* scripts are developer fallback only.",
        "Windows .exe builds on Windows/CI; Linux/macOS native binaries need matching OS or CI.",
        "Enroll first (token once), download the OS package, then set SECURAIQ_SERVER + SECURAIQ_TOKEN (or pass --server / --token).",
    ]
    if dmg_available:
        notes.insert(
            1,
            "macOS .dmg is available in this catalog — unsigned builds may need Gatekeeper Open Anyway.",
        )
    else:
        notes.insert(
            1,
            "macOS .dmg is not present on this server (requires macOS or CI macos-latest). Use the .tar.gz package (includes install.sh).",
        )

    return {
        "packages": packages,
        "scripts": scripts,
        "by_os": by_os,
        "package_dir": str(_PACKAGE_DIR),
        "package_dir_exists": _PACKAGE_DIR.is_dir(),
        "build_hint": "python scripts/build_agent_packages.py",
        "dmg_available": dmg_available,
        "install_path": "package",
        "realtime": {
            "sse": "/api/realtime",
            "agent_websocket": "/api/agents/ws",
            "http_fallback": "/api/agents/gateway/wait + /api/agents/checkin",
            "fleet_online": online,
            "fleet_total": total,
        },
        "notes": notes,
        "roadmap_packages": {
            "windows": [
                {
                    "kind": "msi",
                    "label": "Windows MSI (WiX scaffold; Authenticode = CI)",
                    "built": any(p.get("kind") == "msi" for p in packages),
                    "build_hint": "scripts/packaging/build_msi.ps1",
                },
                {"kind": "exe", "label": "Windows EXE bootstrapper", "built": any(p.get("kind") == "exe" for p in packages)},
            ],
            "linux": [
                {
                    "kind": "deb",
                    "label": "Debian/Ubuntu .deb scaffold",
                    "built": any(p.get("kind") == "deb" for p in packages),
                    "build_hint": "scripts/packaging/build_deb.sh",
                },
                {
                    "kind": "rpm",
                    "label": "RHEL/Fedora .rpm scaffold (fpm)",
                    "built": any(p.get("kind") == "rpm" for p in packages),
                    "build_hint": "scripts/packaging/build_rpm.sh",
                },
                {"kind": "tar", "label": "Universal .tar.gz", "built": any(p.get("kind") == "tar" and p.get("os") == "linux" for p in packages)},
            ],
            "macos": [
                {"kind": "pkg", "label": "macOS .pkg — coming soon", "built": False},
                {"kind": "dmg", "label": "macOS .dmg", "built": dmg_available},
            ],
        },
        "deploy": {
            "enroll_token_url": "/api/agents/enroll-tokens",
            "enroll_by_token_url": "/api/agents/enroll-by-token",
            "license_validate_url": "/api/licenses/validate",
            "agent_license_validate_url": "/api/agents/license/validate",
            "updates_latest_url": "/api/agents/updates/latest",
            "bootstrap_note": (
                "Generate a short-lived enrollment token (not a permanent org secret). "
                "Installer calls enroll-by-token once; permanent agent_id.agent_key is issued; "
                "discard the bootstrap token after use."
            ),
            "activation_note": (
                "Local registry/config caches activation state only. "
                "Agents re-validate via POST /api/agents/license/validate; "
                "dashboards use POST /api/licenses/validate — never trust a local license file as SoT."
            ),
        },
    }


@router.get("/packages/{filename}")
async def api_agent_package_download(filename: str):
    """Download a built agent artifact from dist/agent-packages (no secrets)."""
    safe = Path(filename).name
    if safe != filename or ".." in filename or "/" in filename or "\\" in filename:
        raise HTTPException(status_code=400, detail="Invalid filename")
    if not any(safe.lower().endswith(suf) for suf in _PACKAGE_SUFFIXES):
        raise HTTPException(status_code=400, detail="Unsupported package type")
    path = (_PACKAGE_DIR / safe).resolve()
    try:
        path.relative_to(_PACKAGE_DIR.resolve())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="Invalid path") from exc
    if not path.is_file():
        raise HTTPException(
            status_code=404,
            detail=f"Package not found. Build with: python scripts/build_agent_packages.py  (looking in {_PACKAGE_DIR})",
        )
    media = "application/octet-stream"
    if safe.lower().endswith(".exe"):
        media = "application/vnd.microsoft.portable-executable"
    elif safe.lower().endswith(".msi"):
        media = "application/x-msi"
    elif safe.lower().endswith(".deb"):
        media = "application/vnd.debian.binary-package"
    elif safe.lower().endswith(".rpm"):
        media = "application/x-rpm"
    elif safe.lower().endswith(".zip"):
        media = "application/zip"
    elif safe.lower().endswith(".dmg"):
        media = "application/x-apple-diskimage"
    elif safe.lower().endswith(".tar.gz") or safe.lower().endswith(".tgz"):
        media = "application/gzip"
    return FileResponse(path, media_type=media, filename=safe)


@router.get("/updates/latest")
async def api_agents_updates_latest(
    user: Annotated[AuthUser, Depends(require_user)],
    platform: str = "all",
):
    """Signed agent update metadata (sha256 + optional Ed25519 + previous_sha256)."""
    require_perm(user, "agent.read")
    from app.agent_updates import get_latest_update

    latest = get_latest_update(platform=(platform or "all").strip().lower() or "all")
    if not latest:
        raise HTTPException(status_code=404, detail="No update metadata available")
    return {"update": latest}


class PublishUpdateRequest(BaseModel):
    version: str = ""
    notes: str = ""
    previous_sha256: str = ""
    platform: str = "all"
    # When set, publish a built package from dist/agent-packages/ instead of the script.
    filename: str = ""


@router.post("/updates/publish")
async def api_agents_updates_publish(
    req: PublishUpdateRequest,
    user: Annotated[AuthUser, Depends(require_user)],
):
    """Publish signed update metadata (script or package artifact)."""
    require_perm(user, "agent.write")
    from app.agent_updates import publish_package_release, publish_script_release
    from app.config import settings as _settings

    version = (req.version or "").strip()
    if not version:
        import re
        from app.paths import resource_root

        text = (resource_root() / "scripts" / "securaiq_agent.py").read_text(encoding="utf-8")
        m = re.search(r'AGENT_VERSION\s*=\s*"([^"]+)"', text)
        version = m.group(1) if m else "unknown"
    platform = (req.platform or "all").strip().lower() or "all"
    try:
        if (req.filename or "").strip():
            fn = req.filename.strip().lower()
            inferred = platform
            if platform == "all":
                if "linux" in fn or fn.endswith((".deb", ".rpm")):
                    inferred = "linux"
                elif "macos" in fn or "darwin" in fn or fn.endswith(".dmg"):
                    inferred = "macos"
                else:
                    inferred = "windows"
            row = publish_package_release(
                filename=req.filename.strip(),
                version=version,
                platform=inferred,
                notes=req.notes,
                previous_sha256=req.previous_sha256,
            )
        else:
            row = publish_script_release(
                version=version,
                notes=req.notes,
                previous_sha256=req.previous_sha256,
                platform=platform,
            )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    audit(
        "agent_update_publish",
        user.id,
        {"version": version, "id": row.get("id"), "filename": req.filename or None},
    )
    pub = (getattr(_settings, "agent_ed25519_public_key", "") or "").strip()
    if not pub:
        pub = (getattr(_settings, "license_ed25519_public_key", "") or "").strip()
    return {"update": row, "signing_public_key": pub or None}


@router.post("/license/validate")
async def api_agent_license_validate(
    request: Request,
    authorization: Annotated[str | None, Header(alias="Authorization")] = None,
    x_securaiq_ts: Annotated[str | None, Header(alias="X-SecuraIQ-Ts")] = None,
    x_securaiq_nonce: Annotated[str | None, Header(alias="X-SecuraIQ-Nonce")] = None,
    x_securaiq_sig: Annotated[str | None, Header(alias="X-SecuraIQ-Sig")] = None,
):
    """Agent-authenticated license validation (state cache only; server remains SoT)."""
    agent = _authenticate_agent_request(
        authorization,
        body=b"",
        ts=x_securaiq_ts,
        nonce=x_securaiq_nonce,
        sig=x_securaiq_sig,
        request=request,
    )
    from app.license_service import validate_license

    result = validate_license(agent.get("user_id") or "local", org_id=agent.get("org_id"))
    cache = dict(result.get("activation_cache") or {})
    cache["agent_id"] = agent.get("id")
    result = {**result, "activation_cache": cache, "agent_id": agent.get("id")}
    audit(
        "agent_license_validate",
        agent.get("user_id") or "local",
        {"agent_id": agent.get("id"), "mode": result.get("mode"), "valid": result.get("valid")},
    )
    return result


@router.get("")
async def api_list_agents(
    user: Annotated[AuthUser, Depends(require_user)],
    header_org: Annotated[str | None, Depends(optional_org_header)] = None,
):
    oid = _org_for(user, header_org)
    require_perm(user, "agent.read", org_id=oid)
    return {"agents": list_agents(user.id, org_id=oid)}


@router.get("/threats")
async def api_list_all_threats(
    user: Annotated[AuthUser, Depends(require_user)],
    limit: int = 200,
    header_org: Annotated[str | None, Depends(optional_org_header)] = None,
):
    # Registered before /{agent_id} on purpose — a single literal path
    # segment would otherwise be swallowed by the dynamic agent_id route.
    oid = _org_for(user, header_org)
    require_perm(user, "agent.read", org_id=oid)
    return {"threats": list_threats(user.id, limit=limit, org_id=oid)}


@router.get("/commands/pending")
async def api_list_pending_commands(
    user: Annotated[AuthUser, Depends(require_user)],
    limit: int = 200,
    header_org: Annotated[str | None, Depends(optional_org_header)] = None,
):
    # Registered before /{agent_id} on purpose — same reason as /threats above.
    oid = _org_for(user, header_org)
    require_perm(user, "agent.read", org_id=oid)
    return {"commands": list_pending_commands(user.id, limit=limit, org_id=oid)}


@router.post("/campaigns")
async def api_create_campaign(
    req: CampaignCreate,
    user: Annotated[AuthUser, Depends(require_user)],
    header_org: Annotated[str | None, Depends(optional_org_header)] = None,
):
    """Create a patch campaign targeting multiple agents with one shared
    package+manager upgrade. Each targeted agent gets its own
    'pending_approval' command — nothing is queued for delivery until those
    are approved (individually or via /campaigns/{id}/approve)."""
    oid = _org_for(user, header_org)
    require_perm(user, "agent.command", org_id=oid)
    try:
        from app.license_service import require_premium_feature

        require_premium_feature(user.id, "remediation", org_id=oid)
    except ValueError as exc:
        raise HTTPException(status_code=402, detail=str(exc)) from exc
    try:
        result = create_campaign(
            user.id,
            name=req.name,
            manager=req.manager,
            package=req.package,
            target_version=req.target_version,
            agent_ids=req.agent_ids,
            rings=req.rings,
            ring_threshold_pct=req.ring_threshold_pct,
            window_start_hour=req.window_start_hour,
            window_end_hour=req.window_end_hour,
            window_days=req.window_days,
            requested_by=user.id,
            org_id=oid,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return result


@router.get("/campaigns")
async def api_list_campaigns(
    user: Annotated[AuthUser, Depends(require_user)],
    limit: int = 100,
    header_org: Annotated[str | None, Depends(optional_org_header)] = None,
):
    oid = _org_for(user, header_org)
    require_perm(user, "agent.read", org_id=oid)
    return {"campaigns": list_campaigns(user.id, limit=limit, org_id=oid)}


@router.get("/campaigns/{campaign_id}")
async def api_get_campaign(
    campaign_id: str,
    user: Annotated[AuthUser, Depends(require_user)],
    header_org: Annotated[str | None, Depends(optional_org_header)] = None,
):
    oid = _org_for(user, header_org)
    require_perm(user, "agent.read", org_id=oid)
    campaign = get_campaign(user.id, campaign_id)
    if not campaign:
        raise HTTPException(status_code=404, detail="Campaign not found")
    return campaign


@router.post("/campaigns/{campaign_id}/approve")
async def api_approve_campaign(
    campaign_id: str,
    user: Annotated[AuthUser, Depends(require_user)],
    header_org: Annotated[str | None, Depends(optional_org_header)] = None,
):
    oid = _org_for(user, header_org)
    _require_admin_for_approval(user, org_id=oid)
    try:
        result = approve_campaign(user.id, campaign_id, approver_id=user.id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    return result


@router.post("/campaigns/{campaign_id}/reject")
async def api_reject_campaign(
    campaign_id: str, req: CommandReject, user: Annotated[AuthUser, Depends(require_user)]
):
    _require_admin_for_approval(user)
    try:
        result = reject_campaign(user.id, campaign_id, approver_id=user.id, reason=req.reason)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    return result


@router.get("/{agent_id}")
async def api_get_agent(agent_id: str, user: Annotated[AuthUser, Depends(require_user)]):
    agent = get_agent(agent_id)
    if not agent_visible_to_user(user.id, agent):
        raise HTTPException(status_code=404, detail="Agent not found")
    require_perm(user, "agent.read", org_id=agent.get("org_id"))
    view = dict(agent)
    view.pop("key_hash", None)
    view.pop("key_enc", None)
    # Keep fingerprint/expiry for UI; drop bulky PEM from default GET
    view.pop("certificate_pem", None)
    view.pop("certificate_public_key_pem", None)
    try:
        from app.agent_certs import agent_cert_summary

        view["mtls"] = agent_cert_summary(agent)
    except Exception:
        view["mtls"] = None
    return view


@router.post("/{agent_id}/revoke")
async def api_revoke_agent(agent_id: str, user: Annotated[AuthUser, Depends(require_user)]):
    agent = get_agent(agent_id)
    if not agent_visible_to_user(user.id, agent):
        raise HTTPException(status_code=404, detail="Agent not found")
    require_perm(user, "agent.write", org_id=agent.get("org_id") if agent else None)
    ok = revoke_agent(user.id, agent_id)
    if not ok:
        raise HTTPException(status_code=404, detail="Agent not found")
    audit("agent_revoke", user.id, {"agent_id": agent_id})
    return {"ok": True}


class CertRotateBody(BaseModel):
    days: int | None = Field(default=None, ge=7, le=365)
    force: bool = False


@router.get("/{agent_id}/certificate")
async def api_agent_certificate_summary(
    agent_id: str, user: Annotated[AuthUser, Depends(require_user)]
):
    from app.agent_certs import agent_cert_summary

    agent = get_agent(agent_id)
    if not agent_visible_to_user(user.id, agent):
        raise HTTPException(status_code=404, detail="Agent not found")
    require_perm(user, "agent.read", org_id=agent.get("org_id") if agent else None)
    return agent_cert_summary(agent) or {"has_certificate": False}


@router.get("/{agent_id}/timeline")
async def api_agent_timeline(
    agent_id: str,
    user: Annotated[AuthUser, Depends(require_user)],
    limit: int = 80,
):
    """SSE-friendly merged timeline: commands + control_results + evidence."""
    from app.agent_timeline import build_agent_timeline

    agent = get_agent(agent_id)
    if not agent_visible_to_user(user.id, agent):
        raise HTTPException(status_code=404, detail="Agent not found")
    require_perm(user, "agent.read", org_id=agent.get("org_id") if agent else None)
    return build_agent_timeline(user.id, agent_id, limit=limit)


@router.post("/{agent_id}/certificate/issue")
async def api_agent_certificate_issue(
    agent_id: str,
    user: Annotated[AuthUser, Depends(require_user)],
    body: CertRotateBody | None = None,
):
    from app.agent_certs import issue_agent_client_certificate, mtls_enabled
    from app.config import settings as _settings

    agent = get_agent(agent_id)
    if not agent_visible_to_user(user.id, agent):
        raise HTTPException(status_code=404, detail="Agent not found")
    require_perm(user, "agent.write", org_id=agent.get("org_id") if agent else None)
    if not mtls_enabled():
        raise HTTPException(status_code=400, detail="AGENT_MTLS_ENABLED is false")
    days = (body.days if body and body.days else None) or int(
        getattr(_settings, "agent_mtls_cert_days", 60) or 60
    )
    issued = issue_agent_client_certificate(agent_id, days=days)
    audit("agent_cert_issue", user.id, {"agent_id": agent_id, "fingerprint": issued.get("fingerprint")})
    return {"ok": True, "mtls": issued}


@router.post("/{agent_id}/certificate/rotate")
async def api_agent_certificate_rotate(
    agent_id: str,
    user: Annotated[AuthUser, Depends(require_user)],
    body: CertRotateBody | None = None,
):
    from app.agent_certs import mtls_enabled, rotate_agent_client_certificate

    agent = get_agent(agent_id)
    if not agent_visible_to_user(user.id, agent):
        raise HTTPException(status_code=404, detail="Agent not found")
    require_perm(user, "agent.write", org_id=agent.get("org_id") if agent else None)
    if not mtls_enabled():
        raise HTTPException(status_code=400, detail="AGENT_MTLS_ENABLED is false")
    out = rotate_agent_client_certificate(
        agent_id,
        days=body.days if body else None,
        reason="operator_rotate",
        rotated_by=user.id,
    )
    audit("agent_cert_rotate", user.id, {"agent_id": agent_id})
    return out


@router.post("/{agent_id}/certificate/renew")
async def api_agent_certificate_renew(
    agent_id: str,
    user: Annotated[AuthUser, Depends(require_user)],
    body: CertRotateBody | None = None,
):
    from app.agent_certs import mtls_enabled, renew_agent_client_certificate

    agent = get_agent(agent_id)
    if not agent_visible_to_user(user.id, agent):
        raise HTTPException(status_code=404, detail="Agent not found")
    require_perm(user, "agent.write", org_id=agent.get("org_id") if agent else None)
    if not mtls_enabled():
        raise HTTPException(status_code=400, detail="AGENT_MTLS_ENABLED is false")
    out = renew_agent_client_certificate(
        agent_id,
        days=body.days if body else None,
        force=bool(body.force) if body else False,
        renewed_by=user.id,
    )
    audit("agent_cert_renew", user.id, {"agent_id": agent_id, "renewed": out.get("renewed")})
    return out


@router.post("/{agent_id}/certificate/revoke")
async def api_agent_certificate_revoke(
    agent_id: str, user: Annotated[AuthUser, Depends(require_user)]
):
    from app.agent_certs import revoke_agent_certificate

    agent = get_agent(agent_id)
    if not agent_visible_to_user(user.id, agent):
        raise HTTPException(status_code=404, detail="Agent not found")
    require_perm(user, "agent.write", org_id=agent.get("org_id") if agent else None)
    out = revoke_agent_certificate(agent_id, reason="operator_revoke", revoked_by=user.id)
    if not out.get("ok"):
        raise HTTPException(status_code=404, detail=out.get("error") or "not found")
    audit("agent_cert_revoke", user.id, {"agent_id": agent_id})
    return out


@router.delete("/{agent_id}")
async def api_delete_agent(agent_id: str, user: Annotated[AuthUser, Depends(require_user)]):
    agent = get_agent(agent_id)
    if not agent_visible_to_user(user.id, agent):
        raise HTTPException(status_code=404, detail="Agent not found")
    require_perm(user, "agent.write", org_id=agent.get("org_id") if agent else None)
    ok = delete_agent(user.id, agent_id)
    if not ok:
        raise HTTPException(status_code=404, detail="Agent not found")
    audit("agent_delete", user.id, {"agent_id": agent_id})
    return {"ok": True}


@router.post("/checkin")
async def api_agent_checkin(
    request: Request,
    authorization: Annotated[str | None, Header(alias="Authorization")] = None,
    x_securaiq_ts: Annotated[str | None, Header(alias="X-SecuraIQ-Ts")] = None,
    x_securaiq_nonce: Annotated[str | None, Header(alias="X-SecuraIQ-Nonce")] = None,
    x_securaiq_sig: Annotated[str | None, Header(alias="X-SecuraIQ-Sig")] = None,
):
    """Real telemetry check-in from an installed agent. Agent-token auth only
    (no user session) — this is what runs unattended on a monitored server.

    Replay/HMAC verification uses the raw request body so agent-computed
    ``X-SecuraIQ-Sig`` matches what the server checks.
    """
    body = await request.body()
    try:
        payload = CheckinPayload.model_validate_json(body or b"{}")
    except ValidationError as exc:
        raise HTTPException(status_code=422, detail=exc.errors()) from exc
    agent = _authenticate_agent_request(
        authorization,
        body=body,
        ts=x_securaiq_ts,
        nonce=x_securaiq_nonce,
        sig=x_securaiq_sig,
        request=request,
    )
    result = checkin(str(agent["id"]), payload.model_dump())
    if not result.get("ok"):
        raise HTTPException(status_code=400, detail=result.get("error") or "Check-in failed")
    return result


@router.post("/threat")
async def api_agent_threat(
    request: Request,
    payload: ThreatReport,
    authorization: Annotated[str | None, Header(alias="Authorization")] = None,
):
    """Real-time threat/malware detections from an agent's SecuraIQ Sentinel
    watcher — a live push, not a check-in field, so it reaches the SOC and
    creates a finding/incident the moment it's ingested."""
    agent = _authenticate_agent_request(
        authorization,
        body=payload.model_dump_json().encode("utf-8"),
        request=request,
    )
    result = record_threat_detections(str(agent["id"]), [d.model_dump() for d in payload.detections])
    if not result.get("ok"):
        raise HTTPException(status_code=400, detail=result.get("error") or "Threat report failed")
    return result


@router.get("/{agent_id}/threats")
async def api_list_agent_threats(
    agent_id: str, user: Annotated[AuthUser, Depends(require_user)], limit: int = 100
):
    agent = get_agent(agent_id)
    if not agent_visible_to_user(user.id, agent):
        raise HTTPException(status_code=404, detail="Agent not found")
    require_perm(user, "agent.read", org_id=agent.get("org_id") if agent else None)
    return {"threats": list_threats(user.id, agent_id=agent_id, limit=limit)}


@router.post("/{agent_id}/commands")
async def api_queue_agent_command(
    agent_id: str, req: CommandCreate, user: Annotated[AuthUser, Depends(require_user)]
):
    """Request a command for this agent — lands in 'pending_approval', not
    delivered yet. A second call to the approve endpoint is required before
    it is ever handed to the agent (see api_approve_agent_command below)."""
    agent = get_agent(agent_id)
    require_perm(user, "agent.command", org_id=agent.get("org_id") if agent else None)
    try:
        result = request_command(user.id, agent_id, kind=req.kind, payload=req.payload, requested_by=user.id)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    audit("agent_command_request", user.id, {"agent_id": agent_id, "kind": req.kind, "payload": req.payload})
    return result


@router.post("/{agent_id}/commands/upgrade")
async def api_request_agent_upgrade(agent_id: str, user: Annotated[AuthUser, Depends(require_user)]):
    """Request a self-upgrade for this agent. Same pending_approval gate as
    any other command -- computes the server's current agent-script sha256
    now and attaches it to the command so the agent verifies it's fetching
    exactly what was approved (see request_agent_upgrade)."""
    agent = get_agent(agent_id)
    require_perm(user, "agent.command", org_id=agent.get("org_id") if agent else None)
    try:
        result = request_agent_upgrade(user.id, agent_id, requested_by=user.id)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    audit("agent_upgrade_request", user.id, {"agent_id": agent_id})
    return result


class EnableFirewallRequest(BaseModel):
    remediation_id: str = ""


@router.post("/{agent_id}/commands/enable-firewall")
async def api_request_enable_firewall(
    agent_id: str,
    user: Annotated[AuthUser, Depends(require_user)],
    req: EnableFirewallRequest | None = None,
):
    """Request enable_firewall for this agent (pending_approval only).

    Lab/owned systems: operator still must approve before the agent runs
    fixed argv firewall enable. Never auto-executed on host_firewall FAIL.
    """
    agent = get_agent(agent_id)
    require_perm(user, "agent.command", org_id=agent.get("org_id") if agent else None)
    body = req or EnableFirewallRequest()
    try:
        result = request_enable_firewall_command(
            user.id,
            agent_id,
            remediation_id=body.remediation_id,
            requested_by=user.id,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    audit(
        "agent_enable_firewall_request",
        user.id,
        {"agent_id": agent_id, "remediation_id": body.remediation_id or None},
    )
    return result


class EnableDefenderRequest(BaseModel):
    remediation_id: str = ""


@router.post("/{agent_id}/commands/enable-defender")
async def api_request_enable_defender(
    agent_id: str,
    user: Annotated[AuthUser, Depends(require_user)],
    req: EnableDefenderRequest | None = None,
):
    """Request enable_defender for this agent (pending_approval only).

    Lab/owned Windows systems: operator still must approve before the agent
    runs fixed argv Set-MpPreference. Never auto-executed on host_defender FAIL.
    """
    agent = get_agent(agent_id)
    require_perm(user, "agent.command", org_id=agent.get("org_id") if agent else None)
    body = req or EnableDefenderRequest()
    try:
        result = request_enable_defender_command(
            user.id,
            agent_id,
            remediation_id=body.remediation_id,
            requested_by=user.id,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    audit(
        "agent_enable_defender_request",
        user.id,
        {"agent_id": agent_id, "remediation_id": body.remediation_id or None},
    )
    return result


class DisableSshRootRequest(BaseModel):
    remediation_id: str = ""


@router.post("/{agent_id}/commands/disable-ssh-root")
async def api_request_disable_ssh_root(
    agent_id: str,
    user: Annotated[AuthUser, Depends(require_user)],
    req: DisableSshRootRequest | None = None,
):
    """Request disable_ssh_root for this agent (pending_approval only).

    Lab/owned Linux/macOS: operator must approve before the agent rewrites
    sshd_config PermitRootLogin. Never auto-executed on host_ssh_root FAIL.
    """
    agent = get_agent(agent_id)
    require_perm(user, "agent.command", org_id=agent.get("org_id") if agent else None)
    body = req or DisableSshRootRequest()
    try:
        result = request_disable_ssh_root_command(
            user.id,
            agent_id,
            remediation_id=body.remediation_id,
            requested_by=user.id,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    audit(
        "agent_disable_ssh_root_request",
        user.id,
        {"agent_id": agent_id, "remediation_id": body.remediation_id or None},
    )
    return result


@router.get("/{agent_id}/commands")
async def api_list_agent_commands(
    agent_id: str, user: Annotated[AuthUser, Depends(require_user)], limit: int = 100
):
    agent = get_agent(agent_id)
    if not agent_visible_to_user(user.id, agent):
        raise HTTPException(status_code=404, detail="Agent not found")
    require_perm(user, "agent.read", org_id=agent.get("org_id") if agent else None)
    return {"commands": list_commands(user.id, agent_id, limit=limit)}


def _require_admin_for_approval(user: AuthUser, *, org_id: str | None = None) -> None:
    """Approving/rejecting a queued OS-package-manager command is the real
    approval gate for patch execution. Prefer agent.approve RBAC; keep legacy
    admin role check as a floor when AUTH is enabled."""
    try:
        require_perm(user, "agent.approve", org_id=org_id)
        return
    except HTTPException:
        if settings.auth_enabled and user.role != "admin" and user.id != "local":
            raise
        if not settings.auth_enabled or user.id == "local" or user.role == "admin":
            return
        raise


@router.post("/{agent_id}/commands/{command_id}/approve")
async def api_approve_agent_command(
    agent_id: str, command_id: str, user: Annotated[AuthUser, Depends(require_user)]
):
    agent = get_agent(agent_id)
    _require_admin_for_approval(user, org_id=agent.get("org_id") if agent else None)
    try:
        result = approve_command(user.id, agent_id, command_id, approver_id=user.id)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return result


@router.post("/{agent_id}/commands/{command_id}/reject")
async def api_reject_agent_command(
    agent_id: str, command_id: str, req: CommandReject, user: Annotated[AuthUser, Depends(require_user)]
):
    agent = get_agent(agent_id)
    _require_admin_for_approval(user, org_id=agent.get("org_id") if agent else None)
    try:
        result = reject_command(user.id, agent_id, command_id, approver_id=user.id, reason=req.reason)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return result


@router.post("/commands/{command_id}/result")
async def api_report_command_result(
    command_id: str,
    request: Request,
    authorization: Annotated[str | None, Header(alias="Authorization")] = None,
    x_securaiq_ts: Annotated[str | None, Header(alias="X-SecuraIQ-Ts")] = None,
    x_securaiq_nonce: Annotated[str | None, Header(alias="X-SecuraIQ-Nonce")] = None,
    x_securaiq_sig: Annotated[str | None, Header(alias="X-SecuraIQ-Sig")] = None,
):
    """Agent reports the outcome of a command it executed — agent-token auth
    only, same as /checkin and /threat (this runs unattended, no user
    session)."""
    body = await request.body()
    try:
        req = CommandResultReport.model_validate_json(body or b"{}")
    except ValidationError as exc:
        raise HTTPException(status_code=422, detail=exc.errors()) from exc
    agent = _authenticate_agent_request(
        authorization,
        body=body,
        ts=x_securaiq_ts,
        nonce=x_securaiq_nonce,
        sig=x_securaiq_sig,
        request=request,
    )
    result = report_command_result(str(agent["id"]), command_id, status=req.status, result=req.result)
    if not result.get("ok"):
        raise HTTPException(status_code=404, detail=result.get("error") or "Unknown command")
    return result


@router.post("/commands/{command_id}/ack")
async def api_ack_command(
    command_id: str,
    request: Request,
    authorization: Annotated[str | None, Header(alias="Authorization")] = None,
    x_securaiq_ts: Annotated[str | None, Header(alias="X-SecuraIQ-Ts")] = None,
    x_securaiq_nonce: Annotated[str | None, Header(alias="X-SecuraIQ-Nonce")] = None,
    x_securaiq_sig: Annotated[str | None, Header(alias="X-SecuraIQ-Sig")] = None,
):
    body = await request.body()
    agent = _authenticate_agent_request(
        authorization,
        body=body,
        ts=x_securaiq_ts,
        nonce=x_securaiq_nonce,
        sig=x_securaiq_sig,
        request=request,
    )
    result = ack_command(str(agent["id"]), command_id)
    if not result.get("ok"):
        raise HTTPException(status_code=404, detail=result.get("error") or "Unknown command")
    return result
