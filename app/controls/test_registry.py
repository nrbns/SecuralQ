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
TEST_HOST_DISK_ENCRYPTION = "host_disk_encryption"
TEST_HOST_RISKY_LISTENERS = "host_risky_listeners"
TEST_FIPS_REMOTE_ACCESS = "fips_remote_access_tooling"

_HOST_TELEMETRY_TESTS = frozenset(
    {
        TEST_HOST_FIREWALL,
        TEST_HOST_DEFENDER,
        TEST_HOST_SSH_ROOT,
        TEST_HOST_DISK_ENCRYPTION,
        TEST_HOST_RISKY_LISTENERS,
    }
)

# Primary framework control ids when publishing from a single agent check-in.
# Prefer CMMC L2 so Control Center (cmmc_l2) KPIs/events align with the live UI.
_HOST_TEST_PRIMARY_CONTROLS: dict[str, tuple[str, str]] = {
    TEST_HOST_FIREWALL: ("cmmc_l2", "SC.L2-3.13.1"),
    TEST_HOST_DEFENDER: ("cmmc_l2", "SI.L2-3.14.2"),
    TEST_HOST_SSH_ROOT: ("cmmc_l2", "AC.L2-3.1.5"),
    TEST_HOST_DISK_ENCRYPTION: ("cmmc_l2", "SC.L2-3.13.16"),
    TEST_HOST_RISKY_LISTENERS: ("cmmc_l2", "SC.L2-3.13.6"),
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
    name: str = "",
    description: str = "",
    applicability: dict[str, Any] | None = None,
    pass_condition: str = "",
    fail_condition: str = "",
    risk_weight: float = 1.0,
    evidence_rule: str = "",
    verification_rule: str = "",
) -> dict[str, Any]:
    """Configurable control-test definition (Phase 13 / immediate task #4)."""
    display = name or test_name.replace("_", " ").title()
    return {
        "test_name": test_name,
        "name": display,
        "description": description or remediation_hint or display,
        "data_sources": list(data_sources),
        "expected_state": dict(expected_state),
        "frequency": frequency,
        "verifiability": verifiability,
        "control_bindings": list(control_bindings),
        "remediation_hint": remediation_hint,
        "applicability": dict(applicability or {"os": ["windows", "linux", "macos"]}),
        "pass_condition": pass_condition,
        "fail_condition": fail_condition,
        "risk_weight": float(risk_weight),
        "evidence_rule": evidence_rule
        or "Record observed agent telemetry snippet + PASS/FAIL/UNKNOWN with provenance.",
        "verification_rule": verification_rule
        or "Independent next check-in must re-observe PASS — never trust command JSON alone.",
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
            ("dpdp_rules_2025", "Rule-Inventory"),
            ("dpdp_act_2023", "Act-8"),
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
            ("dpdp_rules_2025", "Rule-6"),
            ("dpdp_act_2023", "Act-8"),
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
        name="Host Firewall Enabled",
        description="Host firewall must be enabled (ufw/firewalld/Windows Firewall).",
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
            ("dpdp_rules_2025", "Rule-6-Access"),
            ("dpdp_rules_2025", "Rule-6"),
        ],
        remediation_hint=(
            "Enable the host firewall (ufw/firewalld/Windows Firewall). "
            "Optional approved agent command: enable_firewall (never auto-executed)."
        ),
        pass_condition="firewall_status.enabled is true (or equivalent OS signal).",
        fail_condition="firewall_status collected and enabled is false.",
        risk_weight=1.2,
        applicability={"os": ["windows", "linux", "macos"]},
        evidence_rule="Observed firewall_status snippet from agent check-in.",
        verification_rule="Next check-in must show firewall enabled — not command JSON.",
    ),
    _entry(
        TEST_HOST_DEFENDER,
        name="Endpoint AV / Defender",
        description="Microsoft Defender (or equivalent) realtime protection enabled on Windows.",
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
            ("dpdp_rules_2025", "Rule-6"),
        ],
        remediation_hint=(
            "Enable Microsoft Defender realtime protection on Windows hosts. "
            "Optional approved agent command: enable_defender "
            "(POST /api/agents/{id}/commands/enable-defender; never auto-executed)."
        ),
        pass_condition="defender_status.enabled is true on Windows.",
        fail_condition="Windows host with defender_status collected and enabled false.",
        risk_weight=1.4,
        applicability={"os": ["windows"]},
        evidence_rule="Observed defender_status from agent check-in.",
        verification_rule="Next check-in must show Defender enabled — not command JSON.",
    ),
    _entry(
        TEST_HOST_SSH_ROOT,
        name="SSH Root Login Disabled",
        description="sshd PermitRootLogin must not allow password/root login.",
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
        remediation_hint=(
            "Request approved disable_ssh_root (PermitRootLogin no), "
            "then verify on next check-in — never auto-executed."
        ),
        pass_condition="ssh_config.permit_root_login is false / no / prohibit-password.",
        fail_condition="ssh_config collected and permit_root_login allows root.",
        risk_weight=1.3,
        applicability={"os": ["linux", "macos"]},
        evidence_rule="Observed ssh_config snippet from agent check-in.",
        verification_rule="Next check-in must show PermitRootLogin denied — not command JSON.",
    ),
    _entry(
        TEST_HOST_DISK_ENCRYPTION,
        name="Full-Disk Encryption",
        description="BitLocker / LUKS / FileVault enabled on the system volume.",
        data_sources=["securaiq_agent.disk_encryption_status"],
        expected_state={"encrypted": True},
        frequency="checkin",
        verifiability="machine",
        control_bindings=[
            ("cis_controls", "CIS-3"),
            ("nist_csf", "PR.DS-01"),
            ("iso27001", "A.8.24"),
            ("nist_800_53", "SC-28"),
            ("nist_800_171", "3.13.16"),
            ("cmmc_l2", "SC.L2-3.13.16"),
            ("dpdp_rules_2025", "Rule-6-Encryption"),
            ("dpdp_rules_2025", "Rule-6"),
            ("dpdp_act_2023", "Act-8"),
        ],
        remediation_hint=(
            "Enable full-disk encryption (BitLocker / LUKS / FileVault) on the host, "
            "then wait for the next agent check-in. UNKNOWN when not collected — "
            "never invent PASS. No auto-remediation."
        ),
        pass_condition="disk_encryption_status.collected and encrypted is true.",
        fail_condition="disk_encryption_status.collected and encrypted is false.",
        risk_weight=1.5,
        applicability={"os": ["windows", "linux", "macos"]},
        evidence_rule="Observed disk_encryption_status (backend/volumes) from agent.",
        verification_rule="Next check-in must re-observe encrypted=true — no auto rem command.",
    ),
    _entry(
        TEST_HOST_RISKY_LISTENERS,
        name="High-Risk Listening Ports",
        description=(
            "Agent-reported listening ports must not include known high-risk services "
            "(RDP, Redis, Docker API, etc.). Signal only — not full network exposure proof."
        ),
        data_sources=["securaiq_agent.listening_ports"],
        expected_state={"no_risky_listeners": True},
        frequency="checkin",
        verifiability="partial",
        control_bindings=[
            ("cis_controls", "CIS-12"),
            ("nist_csf", "PR.IR-01"),
            ("iso27001", "A.8.20"),
            ("nist_800_53", "SC-7"),
            ("nist_800_171", "3.13.6"),
            ("cmmc_l2", "SC.L2-3.13.6"),
            ("dpdp_rules_2025", "Rule-6-Access"),
        ],
        remediation_hint=(
            "Stop or bind high-risk listeners to localhost / restrict with host firewall. "
            "Partial signal from port list only — not internet-exposure proof. No auto-remediation."
        ),
        pass_condition="listening_ports collected and contains none of the curated risky port set.",
        fail_condition="listening_ports includes a curated high-risk port (e.g. 3389, 6379).",
        risk_weight=1.1,
        applicability={"os": ["windows", "linux", "macos"]},
        evidence_rule="Observed listening_ports list + matched risky port labels.",
        verification_rule="Next check-in must show risky ports cleared — observe-only.",
    ),
    _entry(
        TEST_FIPS_REMOTE_ACCESS,
        name="FIPS Remote-Access Tooling Signal",
        description="Heuristic check for known non-FIPS remote-access/RMM tools in software inventory.",
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
        pass_condition="No known non-FIPS RMM/remote-access tools in software inventory.",
        fail_condition="Inventory lists a curated non-FIPS remote-access tool.",
        risk_weight=0.8,
        applicability={"os": ["windows", "linux", "macos"]},
    ),
]


_CUSTOM_CACHE: list[dict[str, Any]] | None = None


def load_custom_registry_overrides(*, force: bool = False) -> list[dict[str, Any]]:
    """Load optional JSON overrides from data/controls/custom_tests.json.

    Admins can add/extend control_bindings for existing test_names without
    editing Python. New test_names appear in the registry for catalog/UI but
    still need an evaluator in control_testing to execute.
    """
    global _CUSTOM_CACHE
    import json
    import os
    from copy import deepcopy
    from pathlib import Path

    if _CUSTOM_CACHE is not None and not force:
        return [deepcopy(e) for e in _CUSTOM_CACHE]

    # Late import path helper — keep module import light
    from app.paths import project_root

    out: list[dict[str, Any]] = []
    env = (os.environ.get("SECURAIQ_CONTROL_REGISTRY_PATH") or "").strip()
    candidates = []
    if env:
        candidates.append(Path(env))
    candidates.append(project_root() / "data" / "controls" / "custom_tests.json")

    for path in candidates:
        if not path.is_file():
            continue
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            continue
        rows = raw.get("tests") if isinstance(raw, dict) else raw
        if not isinstance(rows, list):
            continue
        for row in rows:
            if not isinstance(row, dict):
                continue
            name = str(row.get("test_name") or "").strip()
            if not name:
                continue
            bindings_raw = row.get("control_bindings") or []
            bindings: list[tuple[str, str]] = []
            for b in bindings_raw:
                if isinstance(b, (list, tuple)) and len(b) >= 2:
                    bindings.append((str(b[0]), str(b[1])))
                elif isinstance(b, dict) and b.get("framework_id") and b.get("control_id"):
                    bindings.append((str(b["framework_id"]), str(b["control_id"])))
            display_name = str(row.get("name") or "").strip()
            out.append(
                _entry(
                    name,
                    data_sources=list(row.get("data_sources") or ["securaiq_agent"]),
                    expected_state=dict(row.get("expected_state") or {}),
                    frequency=row.get("frequency") or "on_demand",  # type: ignore[arg-type]
                    verifiability=row.get("verifiability") or "partial",  # type: ignore[arg-type]
                    control_bindings=bindings,
                    remediation_hint=str(row.get("remediation_hint") or ""),
                    name=display_name,
                    description=str(row.get("description") or ""),
                    applicability=row.get("applicability")
                    if isinstance(row.get("applicability"), dict)
                    else None,
                    pass_condition=str(row.get("pass_condition") or ""),
                    fail_condition=str(row.get("fail_condition") or ""),
                    risk_weight=float(row.get("risk_weight") or 1.0),
                    evidence_rule=str(row.get("evidence_rule") or ""),
                    verification_rule=str(row.get("verification_rule") or ""),
                )
            )
        break  # first existing file wins
    _CUSTOM_CACHE = out
    return [deepcopy(e) for e in out]


def effective_registry() -> list[dict[str, Any]]:
    """Curated registry + optional custom JSON overrides (bindings merge by test_name)."""
    by_name: dict[str, dict[str, Any]] = {}
    for e in CONTROL_TEST_REGISTRY:
        by_name[e["test_name"]] = deepcopy(e)
    for e in load_custom_registry_overrides():
        name = e["test_name"]
        if name not in by_name:
            by_name[name] = e
            continue
        base = by_name[name]
        # Merge bindings; allow custom remediation / expected_state overlays.
        seen = {(fid, cid) for fid, cid in (base.get("control_bindings") or [])}
        for fid, cid in e.get("control_bindings") or []:
            if (fid, cid) not in seen:
                base.setdefault("control_bindings", []).append((fid, cid))
                seen.add((fid, cid))
        if e.get("remediation_hint"):
            base["remediation_hint"] = e["remediation_hint"]
        if e.get("expected_state"):
            base["expected_state"] = {**(base.get("expected_state") or {}), **e["expected_state"]}
        by_name[name] = base
    return list(by_name.values())


def list_registry() -> list[dict[str, Any]]:
    return effective_registry()


def get_test_entry(test_name: str) -> dict[str, Any] | None:
    name = (test_name or "").strip()
    for e in effective_registry():
        if e["test_name"] == name:
            return deepcopy(e)
    return None


def build_control_test_map() -> dict[tuple[str, str], list[str]]:
    """Derive (framework_id, control_id) → [test_name, ...] from the registry.

    Preserves multi-test bindings (e.g. CIS-7 → vuln + patch) in registry order.
    """
    out: dict[tuple[str, str], list[str]] = {}
    for entry in effective_registry():
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


def risk_weight_for_test(test_name: str) -> float:
    entry = get_test_entry(test_name)
    try:
        return float((entry or {}).get("risk_weight") or 1.0)
    except (TypeError, ValueError):
        return 1.0


def reload_registry(*, force: bool = True) -> list[dict[str, Any]]:
    """Clear custom override cache and return effective registry (ops/tests)."""
    global _CUSTOM_CACHE
    _CUSTOM_CACHE = None
    if force:
        pass  # cache already cleared
    return effective_registry()
