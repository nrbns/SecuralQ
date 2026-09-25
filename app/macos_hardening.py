"""macOS hardening collectors — Gatekeeper, SIP, sharing, XProtect.

Parsers are OS-independent so lab tests run on Windows. Live collection
only executes platform tools on Darwin.
"""

from __future__ import annotations

import platform
from typing import Any


def parse_gatekeeper(text: str) -> bool | None:
    t = (text or "").lower()
    if "assessments enabled" in t or "enabled" in t:
        return True
    if "disabled" in t:
        return False
    return None


def parse_sip(text: str) -> bool | None:
    t = (text or "").lower()
    if "enabled" in t:
        return True
    if "disabled" in t:
        return False
    return None


def parse_remote_login(text: str) -> bool | None:
    t = (text or "").lower()
    if "on" in t or "enabled" in t:
        return True
    if "off" in t or "disabled" in t:
        return False
    return None


def parse_xprotect(text: str) -> str:
    for line in (text or "").splitlines():
        line = line.strip()
        if line and not line.startswith("("):
            return line[:80]
    return (text or "").strip()[:80]


def _run(cmd: list[str], timeout: int = 8) -> tuple[bool, str]:
    import subprocess

    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except FileNotFoundError:
        return False, ""
    except Exception:
        return False, ""
    return out.returncode == 0, (out.stdout or "")


def collect_macos_hardening(*, runner=None) -> dict[str, Any]:
    """Collect live macOS hardening. ``runner(cmd, timeout) -> (ok, stdout)``."""
    system = platform.system().lower()
    if system != "darwin":
        return {
            "collected": False,
            "reason": f"Not applicable on {system}",
            "os": system,
            "gatekeeper_enabled": None,
            "sip_enabled": None,
            "remote_login": None,
            "xprotect_version": "",
        }
    run = runner or _run

    gk_ok, gk_out = run(["spctl", "--status"], 8)
    sip_ok, sip_out = run(["csrutil", "status"], 8)
    rl_ok, rl_out = run(["systemsetup", "-getremotelogin"], 8)
    xp_ok, xp_out = run(
        ["defaults", "read", "/Library/Apple/System/Library/CoreServices/XProtect.bundle/Contents/Info", "CFBundleShortVersionString"],
        8,
    )
    return {
        "collected": True,
        "reason": "",
        "os": "darwin",
        "gatekeeper_enabled": parse_gatekeeper(gk_out) if gk_ok else None,
        "sip_enabled": parse_sip(sip_out) if sip_ok else None,
        "remote_login": parse_remote_login(rl_out) if rl_ok else None,
        "xprotect_version": parse_xprotect(xp_out) if xp_ok else "",
        "filevault": "see disk_encryption_status",
        "application_firewall": "see firewall_status",
    }
