"""Curated Control Test Registry — single source of truth for live tests.

Explicit bindings only (no fuzzy AI mappings). ``control_testing`` derives
``_CONTROL_TEST_MAP`` from this module. Operating-effectiveness signals only —
not CMMC certification or SPRS scoring.
"""

from __future__ import annotations

from copy import deepcopy
from typing import Any, Literal

Frequency = Literal["on_change", "daily", "on_demand", "checkin"]
Verifiability = Literal["machine", "partial", "human", "unknown"]

# ---------------------------------------------------------------------------
# Test name constants (imported by control_testing for stable string IDs)
# ---------------------------------------------------------------------------

TEST_ASSET_INVENTORY = "asset_inventory"
TEST_VULNERABILITY_MANAGEMENT = "vulnerability_management"
TEST_PATCH_MANAGEMENT = "patch_management"
TEST_HOST_FIREWALL = "host_firewall"
TEST_HOST_DEFENDER = "host_defender"
TEST_HOST_SSH_ROOT = "host_ssh_root"
TEST_FIPS_REMOTE_ACCESS = "fips_remote_access_tooling"

_HOST_TELEMETRY_TESTS = frozenset(
    {TEST_HOST_FIREWALL, TEST_HOST_DEFENDER, TEST_HOST_SSH_ROOT}
)

# Primary framework control ids when publishing from a single agent check-in.
# Prefer CMMC L2 so Control Center (cmmc_l2) KPIs/events align with the live UI.
_HOST_TEST_PRIMARY_CONTROLS: dict[str, tuple[str, str]] = {
    TEST_HOST_FIREWALL: ("cmmc_l2", "SC.L2-3.13.1"),
    TEST_HOST_DEFENDER: ("cmmc_l2", "SI.L2-3.14.2"),
    TEST_HOST_SSH_ROOT: ("cmmc_l2", "AC.L2-3.1.5"),
}


def _entry(
    test_name: str,
    *,
    data_sources: list[str],
    expected_state: dict[str, Any],
    frequency: Frequency,
    verifiability: Verifiability,
    control_bindings: list[tuple[str, str]],
    remediation_hint: str = "",
) -> dict[str, Any]:
    return {
        "test_name": test_name,
        "data_sources": list(data_sources),
        "expected_state": dict(expected_state),
        "frequency": frequency,
        "verifiability": verifiability,
        "control_bindings": list(control_bindings),
        "remediation_hint": remediation_hint,
    }


# Curated definitions — bindings match the historical explicit map exactly.
CONTROL_TEST_REGISTRY: list[dict[str, Any]] = [
    _entry(
        TEST_ASSET_INVENTORY,
        data_sources=["enterprise.assets", "agents.list"],
        expected_state={"min_assets": 1, "agent_coverage_pct_hint": 30},
        frequency="on_demand",
        verifiability="partial",
        control_bindings=[
            ("cis_controls", "CIS-1"),
            ("iso27001", "A.5.9"),
            ("nist_csf", "ID.AM-01"),
        ],
        remediation_hint="Enroll assets and agents so inventory is continuously confirmed.",
    ),
    _entry(
        TEST_VULNERABILITY_MANAGEMENT,
        data_sources=["enterprise.vulnerabilities"],
        expected_state={"critical_sla_days": 30, "high_sla_days": 60},
        frequency="daily",
        verifiability="machine",
        control_bindings=[
            ("cis_controls", "CIS-7"),
            ("iso27001", "A.8.8"),
            ("nist_csf", "ID.RA-01"),
            ("nist_800_53", "RA-5"),
            ("nist_800_171", "3.11.2"),
            ("cmmc_l2", "RA.L2-3.11.2"),
            ("pci_dss", "6.3"),
            ("pci_dss", "11.3"),
        ],
        remediation_hint="Track and remediate critical/high findings within SLA windows.",
    ),
    _entry(
        TEST_PATCH_MANAGEMENT,
        data_sources=["enterprise.patch_inventory", "agents.packages"],
        expected_state={"healthy_patch_pct_hint": 90},
        frequency="daily",
        verifiability="machine",
        control_bindings=[
            ("cis_controls", "CIS-7"),
            ("iso27001", "A.8.8"),
            ("nist_csf", "PR.PS-02"),
            ("nist_800_53", "SI-2"),
            ("nist_800_171", "3.14.1"),
            ("cmmc_l2", "SI.L2-3.14.1"),
        ],
        remediation_hint="Apply missing patches via approved agent patch_package commands.",
    ),
    _entry(
        TEST_HOST_FIREWALL,
        data_sources=["securaiq_agent.firewall_status"],
        expected_state={"firewall_enabled": True},
        frequency="checkin",
        verifiability="machine",
        control_bindings=[
            ("cis_controls", "CIS-12"),
            ("nist_csf", "PR.IR-01"),
            ("iso27001", "A.8.20"),
            ("nist_800_53", "SC-7"),
            ("nist_800_171", "3.13.1"),
            ("nist_800_171", "3.4.7"),
            ("cmmc_l2", "SC.L2-3.13.1"),
            ("cmmc_l2", "CM.L2-3.4.2"),
        ],
        remediation_hint=(
            "Enable the host firewall (ufw/firewalld/Windows Firewall). "
            "Optional approved agent command: enable_firewall (never auto-executed)."
        ),
    ),
    _entry(
        TEST_HOST_DEFENDER,
        data_sources=["securaiq_agent.defender_status"],
        expected_state={"defender_enabled": True},
        frequency="checkin",
        verifiability="machine",
        control_bindings=[
            ("cis_controls", "CIS-10"),
            ("iso27001", "A.8.7"),
            ("nist_800_53", "SI-3"),
            ("nist_800_171", "3.14.2"),
            ("cmmc_l2", "SI.L2-3.14.2"),
        ],
        remediation_hint=(
            "Enable Microsoft Defender realtime protection on Windows hosts. "
            "Optional approved agent command: enable_defender "
            "(POST /api/agents/{id}/commands/enable-defender; never auto-executed)."
        ),
    ),
    _entry(
        TEST_HOST_SSH_ROOT,
        data_sources=["securaiq_agent.ssh_config"],
        expected_state={"permit_root_login": False},
        frequency="checkin",
        verifiability="machine",
        control_bindings=[
            ("cis_controls", "CIS-4"),
            ("nist_csf", "PR.PS-01"),
            ("iso27001", "A.8.9"),
            ("nist_800_53", "CM-6"),
            ("nist_800_171", "3.1.5"),
            ("cmmc_l2", "AC.L2-3.1.5"),
        ],
        remediation_hint="Set PermitRootLogin no (or prohibit-password) in sshd_config.",
    ),
    _entry(
        TEST_FIPS_REMOTE_ACCESS,
        data_sources=["enterprise.software_inventory"],
        expected_state={"no_non_fips_remote_access_tools": True},
        frequency="on_change",
        verifiability="partial",
        control_bindings=[
            ("cmmc_l2", "AC.L2-3.1.13"),
            ("cmmc_l2", "SC.L2-3.13.11"),
            ("nist_800_171", "3.1.13"),
            ("nist_800_171", "3.13.11"),
        ],
        remediation_hint=(
            "Replace known non-FIPS-validated remote-access/RMM tooling when CUI "
            "remote access requires validated crypto (signal only — not FIPS certification)."
        ),
    ),
]


def list_registry() -> list[dict[str, Any]]:
    return [deepcopy(e) for e in CONTROL_TEST_REGISTRY]


def get_test_entry(test_name: str) -> dict[str, Any] | None:
    name = (test_name or "").strip()
    for e in CONTROL_TEST_REGISTRY:
        if e["test_name"] == name:
            return deepcopy(e)
    return None


def build_control_test_map() -> dict[tuple[str, str], list[str]]:
    """Derive (framework_id, control_id) → [test_name, ...] from the registry.

    Preserves multi-test bindings (e.g. CIS-7 → vuln + patch) in registry order.
    """
    out: dict[tuple[str, str], list[str]] = {}
    for entry in CONTROL_TEST_REGISTRY:
        name = entry["test_name"]
        for fid, cid in entry.get("control_bindings") or []:
            key = (str(fid), str(cid))
            bucket = out.setdefault(key, [])
            if name not in bucket:
                bucket.append(name)
    return out


def tests_for_control(framework_id: str, control_id: str) -> list[str]:
    return list(build_control_test_map().get((framework_id, control_id), []))


def control_bindings_for_test(test_name: str) -> list[dict[str, str]]:
    entry = get_test_entry(test_name)
    if not entry:
        return []
    return [
        {"framework_id": fid, "control_id": cid}
        for fid, cid in (entry.get("control_bindings") or [])
    ]


def remediation_hint_for_test(test_name: str) -> str:
    entry = get_test_entry(test_name)
    return str((entry or {}).get("remediation_hint") or "")
