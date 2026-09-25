"""Cross-OS check-in contract — same keys, honest collected=false."""

from __future__ import annotations

from pathlib import Path
from typing import Any

CHECKIN_KEYS = (
    "firewall_status",
    "disk_encryption_status",
    "packages",
    "services",
    "file_integrity",
    "listening_ports",
    "hostname",
    "os",
)

_ROOT = Path(__file__).resolve().parents[1]


def _collected_block(value: Any) -> dict[str, Any]:
    if isinstance(value, dict):
        if "collected" in value:
            return {
                "collected": bool(value.get("collected")),
                "reason": value.get("reason") or "",
            }
        return {"collected": True, "reason": ""}
    if value in (None, "", [], {}):
        return {"collected": False, "reason": "absent"}
    return {"collected": True, "reason": ""}


def inspect_checkin(payload: dict[str, Any] | None) -> dict[str, Any]:
    body = payload if isinstance(payload, dict) else {}
    fields = {k: _collected_block(body.get(k)) for k in CHECKIN_KEYS}
    return {
        "ok": True,
        "fields": fields,
        "present": sum(1 for f in fields.values() if f["collected"]),
        "total": len(CHECKIN_KEYS),
        "note": "Missing collectors must report collected=false with a reason — never invent telemetry.",
    }


def agent_parity_status() -> dict[str, Any]:
    py = _ROOT.joinpath("scripts", "securaiq_agent.py").is_file()
    rust = {
        "windows": _ROOT.joinpath("securaiq-agent", "src", "platform", "deep", "windows.rs").is_file(),
        "linux": _ROOT.joinpath("securaiq-agent", "src", "platform", "deep", "linux.rs").is_file(),
        "macos": _ROOT.joinpath("securaiq-agent", "src", "platform", "deep", "macos.rs").is_file(),
    }
    return {
        "ok": py and all(rust.values()),
        "lab": True,
        "python_agent": py,
        "rust_collectors": rust,
        "contract_keys": list(CHECKIN_KEYS),
        "macos_live": False,
        "disclaimer": "Schema parity is in-repo. macOS M1/M2 live enroll remains ops.",
    }
