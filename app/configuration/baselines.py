"""Seeded configuration baselines (code/JSON) for observe/drift.

Control IDs are explicit and must match entries in
``app.services.control_testing._CONTROL_TEST_MAP`` (CMMC L2 / NIST 800-171
host mappings). This is not a certification checklist.
"""

from __future__ import annotations

from copy import deepcopy
from typing import Any

# Explicit control mappings used by live host tests (firewall / Defender / SSH).
_CTRL_FIREWALL = [
    {"framework_id": "cmmc_l2", "control_id": "SC.L2-3.13.1"},
    {"framework_id": "nist_800_171", "control_id": "3.13.1"},
]
_CTRL_DEFENDER = [
    {"framework_id": "cmmc_l2", "control_id": "SI.L2-3.14.2"},
    {"framework_id": "nist_800_171", "control_id": "3.14.2"},
]
_CTRL_SSH_ROOT = [
    {"framework_id": "cmmc_l2", "control_id": "AC.L2-3.1.5"},
    {"framework_id": "nist_800_171", "control_id": "3.1.5"},
]

BASELINE_CMMC_WINDOWS_WORKSTATION: dict[str, Any] = {
    "id": "cmmc_windows_workstation",
    "name": "CMMC Windows Workstation",
    "description": (
        "Minimal host-configuration baseline for authorized lab / owned Windows "
        "workstations — operating-effectiveness signals only, not CMMC certification "
        "or SPRS scoring."
    ),
    "framework_hint": "cmmc_l2",
    "settings": {
        "firewall.enabled": {
            "expected": True,
            "os_scope": "any",
            "source_keys": ["firewall_status"],
            "control_ids": list(_CTRL_FIREWALL),
            "summary": "Host firewall must be enabled",
        },
        "defender.enabled": {
            "expected": True,
            "os_scope": "windows",
            "source_keys": ["defender_status"],
            "control_ids": list(_CTRL_DEFENDER),
            "summary": "Windows Defender / antivirus protection must be enabled",
        },
        "ssh.permit_root_login": {
            "expected": False,
            "os_scope": "linux",
            "source_keys": ["ssh_config"],
            "control_ids": list(_CTRL_SSH_ROOT),
            "summary": "SSH PermitRootLogin must not be yes",
        },
    },
}

_BASELINES: dict[str, dict[str, Any]] = {
    BASELINE_CMMC_WINDOWS_WORKSTATION["id"]: BASELINE_CMMC_WINDOWS_WORKSTATION,
}


def list_baselines() -> list[dict[str, Any]]:
    return [deepcopy(b) for b in _BASELINES.values()]


def get_baseline(baseline_id: str) -> dict[str, Any] | None:
    b = _BASELINES.get((baseline_id or "").strip())
    return deepcopy(b) if b else None


def default_baseline_id() -> str:
    return BASELINE_CMMC_WINDOWS_WORKSTATION["id"]
