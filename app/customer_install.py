"""Customer / other-device install truth — what actually works from another host."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from fastapi import APIRouter

_ROOT = Path(__file__).resolve().parents[1]
router = APIRouter(tags=["install"])


def _fn(fid: str, ok: bool, note: str) -> dict[str, Any]:
    return {"id": fid, "ok": bool(ok), "note": note}


def customer_install_board() -> dict[str, Any]:
    from app.platform_info import agent_deploy_info, platform_info

    info = platform_info()
    deploy = agent_deploy_info()
    scripts = {
        "agent_py": (_ROOT / "scripts" / "securaiq_agent.py").is_file(),
        "windows": (_ROOT / "scripts" / "install_agent_windows.ps1").is_file(),
        "linux": (_ROOT / "scripts" / "install_agent_linux.sh").is_file(),
        "macos": (_ROOT / "scripts" / "install_agent_macos.sh").is_file(),
        "start_lan_win": (_ROOT / "start_lan.cmd").is_file(),
        "start_lan_sh": (_ROOT / "start_lan.sh").is_file(),
    }
    packages: list[str] = []
    try:
        from app.agents_api import list_built_packages

        packages = [p.get("filename") or "" for p in list_built_packages()]
    except Exception:
        packages = []

    pulse_ok = False
    why_ok = False
    launch_ok = False
    loop_ok = False
    # Import-only — do not run Why/pulse boards here; those lock SQLite and time out on phones.
    try:
        from app.command_center_pulse import command_center_pulse  # noqa: F401

        pulse_ok = callable(command_center_pulse)
    except Exception:
        pass
    try:
        from app.control_truth import control_detail  # noqa: F401

        why_ok = callable(control_detail)
    except Exception:
        pass
    try:
        from app.launch_complete import launch_complete_board  # noqa: F401

        launch_ok = callable(launch_complete_board)
    except Exception:
        pass
    try:
        from app.launch_loop import run_launch_loop  # noqa: F401

        loop_ok = callable(run_launch_loop)
    except Exception:
        pass

    lan_mode = bool(info.get("lan_mode"))
    reachable = bool(deploy.get("reachable_from_other_hosts"))
    functions = [
        _fn("lan_bind", lan_mode, "HOST=0.0.0.0 — required for phones / other PCs. Start with start_lan or python run.py --lan."),
        _fn(
            "other_host_url",
            reachable,
            deploy.get("warning")
            or f"Other devices must open {deploy.get('server_url')} — never localhost on the other device.",
        ),
        _fn("agent_scripts", all(scripts[k] for k in ("agent_py", "windows", "linux", "macos")), "Install scripts present."),
        _fn(
            "agent_packages",
            bool(packages),
            "Native packages in dist/agent-packages/" if packages else "No built .exe/.zip yet — other PCs need Python or a built package.",
        ),
        _fn("command_center", pulse_ok, "Pulse / truth board."),
        _fn("control_why", why_ok, "Control Why / document vs observation."),
        _fn("launch_complete", launch_ok, "Lab engineering board."),
        _fn("golden_loop", loop_ok, "P0-01 launch loop module present."),
    ]
    ready = lan_mode and reachable and all(
        f["ok"] for f in functions if f["id"] not in {"agent_packages"}
    )
    return {
        "ok": ready,
        "customer_ready": ready,
        "lan_mode": lan_mode,
        "reachable_from_other_hosts": reachable,
        "server_url": deploy.get("server_url"),
        "lan_urls": info.get("lan_urls") or [],
        "local_url": info.get("local_url"),
        "deploy": deploy,
        "scripts": scripts,
        "packages": packages,
        "functions": functions,
        "other_device": {
            "open": deploy.get("server_url") if reachable else None,
            "never": "http://127.0.0.1:8080 or localhost on the other phone/PC",
            "start_host": "Windows: .\\start_lan.cmd   Linux/macOS: ./start_lan.sh   or   python run.py --lan",
            "agent_server": deploy.get("server_url") if reachable else "http://<this-host-lan-ip>:8080",
        },
        "still_ops": [
            "ev_signed_installers",
            "live_idp",
            "c3pao",
            "http_5k",
        ],
        "disclaimer": (
            "customer_ready means this host is bound for LAN and core functions import. "
            "It is not EV-signed, not a public-internet expose, and not C3PAO."
        ),
    }


@router.get("/api/install/customer-check")
async def api_customer_install_check():
    return customer_install_board()
