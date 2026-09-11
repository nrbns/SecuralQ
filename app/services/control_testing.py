"""Live Control Testing — a control's status computed directly from real
product data (assets, vulnerabilities, patch inventory, agent host
telemetry), independent of the pasted-evidence heuristic in
app.gap_analysis.score_control_against_evidence.

This is deliberately additive and separate, not a replacement:
  - app.gap_analysis's keyword-matched scoring answers "does the evidence
    text a human pasted in describe this control?" -- a proxy for policy/
    procedure documentation.
  - This module answers a narrower, harder question for a small number of
    controls: "does SecuraIQ's own real telemetry show this control is
    actually operating?" -- e.g. is there a real asset inventory, are open
    critical/high vulnerabilities within SLA, is the patch-compliance rate
    healthy, is the host firewall enabled on enrolled agents.

A control is only ever mapped to a live test here via an EXPLICIT
(framework_id, control_id) -> test-name table derived from
``app.controls.test_registry`` (single source of truth), never fuzzy
keyword matching -- a live test result is a specific factual claim about
a specific control, so the mapping itself must be as precise as everything
else in this product's evidence model. Adding a wrong mapping would be
exactly the kind of "AI invents a relationship" mistake this product's
whole evidence philosophy exists to prevent.

Inventory/vuln/patch results record to the Evidence Store with
source="derived". Host-telemetry tests (RT-10) record source="observed"
from securaiq_agent check-in payloads. None of this is a compliance
certification — only an operating-effectiveness signal.
"""

from __future__ import annotations

from typing import Any

from app.controls.test_registry import (
    TEST_ASSET_INVENTORY,
    TEST_FIPS_REMOTE_ACCESS,
    TEST_HOST_DEFENDER,
    TEST_HOST_DISK_ENCRYPTION,
    TEST_HOST_FIREWALL,
    TEST_HOST_SSH_ROOT,
    TEST_PATCH_MANAGEMENT,
    TEST_VULNERABILITY_MANAGEMENT,
    _HOST_TELEMETRY_TESTS,
    _HOST_TEST_PRIMARY_CONTROLS,
    build_control_test_map,
)
from app.db import now

# Derived from app.controls.test_registry — keep import name for callers/tests.
_CONTROL_TEST_MAP: dict[tuple[str, str], list[str]] = build_control_test_map()

# SLA windows (days) a critical/high open vulnerability may age before the
# vulnerability-management test considers it a real breach, not just "still
# being worked". These are reasonable defaults, not a claim any specific
# framework mandates them.
_CRITICAL_SLA_DAYS = 30
_HIGH_SLA_DAYS = 60


def controls_with_live_tests(framework_id: str) -> set[str]:
    """Which control ids in this framework have at least one live test --
    lets the UI show a 'Live tested' badge without running the tests."""
    return {cid for (fid, cid) in _CONTROL_TEST_MAP if fid == framework_id}


def _test_asset_inventory(user_id: str) -> dict[str, Any]:
    from app.agents import list_agents
    from app.enterprise import list_assets

    assets = list_assets(user_id)
    total = len(assets)
    if total == 0:
        return {
            "test": TEST_ASSET_INVENTORY,
            "status": "fail",
            "summary": "No assets recorded -- no evidence an asset inventory exists.",
            "detail": {"total_assets": 0, "agent_covered": 0, "coverage_pct": None},
        }

    agent_asset_ids = set()
    try:
        for a in list_agents(user_id):
            if a.get("asset_id") and a.get("status") in ("online", "offline"):
                agent_asset_ids.add(a["asset_id"])
    except Exception:
        pass
    covered = sum(1 for a in assets if a.get("id") in agent_asset_ids)
    coverage_pct = round(covered / total * 100, 1) if total else None

    if coverage_pct is not None and coverage_pct >= 30:
        status = "pass"
        summary = f"{total} assets recorded, {covered} ({coverage_pct}%) actively confirmed by an installed agent -- a maintained, not just declared, inventory."
    else:
        status = "partial"
        summary = f"{total} assets recorded, but only {covered} ({coverage_pct or 0}%) are actively confirmed by an installed agent -- inventory may be manually declared rather than continuously maintained."

    return {
        "test": TEST_ASSET_INVENTORY,
        "status": status,
        "summary": summary,
        "detail": {"total_assets": total, "agent_covered": covered, "coverage_pct": coverage_pct},
    }


def _test_vulnerability_management(user_id: str) -> dict[str, Any]:
    from app.enterprise import list_vulnerabilities

    all_vulns = list_vulnerabilities(user_id)
    if not all_vulns:
        return {
            "test": TEST_VULNERABILITY_MANAGEMENT,
            "status": "fail",
            "summary": "No vulnerabilities recorded at all -- no evidence a vulnerability identification process exists yet.",
            "detail": {"total": 0, "open": 0, "resolved": 0, "sla_breaches": 0},
        }

    open_vulns = [v for v in all_vulns if (v.get("status") or "").lower() == "open"]
    resolved = [v for v in all_vulns if (v.get("status") or "").lower() in ("resolved", "closed", "fixed")]

    ts = now()
    breaches = []
    for v in open_vulns:
        sev = (v.get("severity") or "").lower()
        created = v.get("created_at")
        if sev not in ("critical", "high") or not created:
            continue
        age_days = (ts - float(created)) / 86400.0
        sla = _CRITICAL_SLA_DAYS if sev == "critical" else _HIGH_SLA_DAYS
        if age_days > sla:
            breaches.append({"vuln_id": v.get("id"), "severity": sev, "age_days": round(age_days, 1), "sla_days": sla})

    if not breaches:
        status = "pass"
        summary = f"{len(all_vulns)} findings tracked ({len(open_vulns)} open, {len(resolved)} resolved); no critical/high finding exceeds its remediation SLA."
    elif len(breaches) <= max(2, len(open_vulns) // 10):
        status = "partial"
        summary = f"{len(breaches)} of {len(open_vulns)} open critical/high findings exceed remediation SLA ({_CRITICAL_SLA_DAYS}d critical / {_HIGH_SLA_DAYS}d high)."
    else:
        status = "fail"
        summary = f"{len(breaches)} of {len(open_vulns)} open critical/high findings exceed remediation SLA -- remediation is not keeping pace with discovery."

    return {
        "test": TEST_VULNERABILITY_MANAGEMENT,
        "status": status,
        "summary": summary,
        "detail": {"total": len(all_vulns), "open": len(open_vulns), "resolved": len(resolved), "sla_breaches": len(breaches), "breach_examples": breaches[:5]},
    }


def _test_patch_management(user_id: str) -> dict[str, Any]:
    from app.services.executive_dashboard import _patch_compliance

    patch = _patch_compliance(user_id)
    pct = patch.get("pct")
    if pct is None:
        return {
            "test": TEST_PATCH_MANAGEMENT,
            "status": "fail",
            "summary": "No software inventory recorded -- no evidence a patch-management process is tracked.",
            "detail": patch,
        }
    if pct >= 90:
        status = "pass"
    elif pct >= 70:
        status = "partial"
    else:
        status = "fail"
    summary = f"{patch.get('up_to_date', 0)} / {patch.get('total', 0)} tracked installations up to date ({pct}%)."
    return {"test": TEST_PATCH_MANAGEMENT, "status": status, "summary": summary, "detail": patch}


def _test_fips_remote_access(user_id: str) -> dict[str, Any]:
    from app.services.fips_tooling import scan_remote_access_tooling

    result = scan_remote_access_tooling(user_id)
    return {
        "test": TEST_FIPS_REMOTE_ACCESS,
        "status": result["status"],
        "summary": result["summary"],
        "detail": {
            "risky_findings": result["risky_findings"],
            "fips_friendly_findings": result["fips_friendly_findings"],
            "checked_products": result["checked_products"],
        },
    }


def _online_agent_rows(user_id: str) -> list[dict[str, Any]]:
    """Online agents visible to the user, with parsed last_payload."""
    from app.agents import list_agents

    out: list[dict[str, Any]] = []
    try:
        agents = list_agents(user_id)
    except Exception:
        return out
    for a in agents:
        if (a.get("status") or "") != "online":
            continue
        payload = a.get("last_payload") if isinstance(a.get("last_payload"), dict) else {}
        out.append(
            {
                "agent_id": a.get("id") or "",
                "asset_id": a.get("asset_id") or "",
                "hostname": a.get("hostname") or "",
                "os": a.get("os") or "",
                "last_checkin": a.get("last_checkin"),
                "payload": payload,
            }
        )
    return out


def _provenance(
    *,
    test_id: str,
    agent_id: str = "",
    asset_id: str = "",
    observed: Any = None,
    collected_at: Any = None,
    confidence: float = 0.8,
) -> dict[str, Any]:
    return {
        "test_id": test_id,
        "source": "securaiq_agent",
        "agent_id": agent_id or "",
        "asset_id": asset_id or "",
        "observed": observed,
        "collected_at": collected_at,
        "confidence": confidence,
    }


def _truthy_enabled(val: Any) -> bool | None:
    """Parse enabled flags from agent collectors (bool / string). None if absent."""
    if val is None:
        return None
    if isinstance(val, bool):
        return val
    s = str(val).strip().lower()
    if s in ("1", "true", "yes", "enabled", "active", "on", "running"):
        return True
    if s in ("0", "false", "no", "disabled", "inactive", "off", "not running"):
        return False
    return None


def evaluate_host_firewall_payload(
    payload: dict[str, Any],
    *,
    agent_id: str = "",
    asset_id: str = "",
    collected_at: Any = None,
) -> dict[str, Any]:
    """Single-agent host_firewall verdict from a check-in / last_payload dict."""
    fw = payload.get("firewall_status") if isinstance(payload.get("firewall_status"), dict) else {}
    collected = bool(fw.get("collected"))
    enabled = _truthy_enabled(fw.get("enabled"))
    snippet = {
        "collected": collected,
        "enabled": fw.get("enabled"),
        "backend": fw.get("backend"),
        "reason": (fw.get("reason") or "")[:200],
    }
    prov = _provenance(
        test_id=TEST_HOST_FIREWALL,
        agent_id=agent_id,
        asset_id=asset_id,
        observed=snippet,
        collected_at=collected_at,
        confidence=0.9 if collected and enabled is not None else 0.4,
    )
    if not collected or enabled is None:
        return {
            "test": TEST_HOST_FIREWALL,
            "status": "unknown",
            "summary": "Host firewall status not collected by agent telemetry.",
            "detail": {**snippet, **prov},
            **prov,
        }
    if enabled:
        return {
            "test": TEST_HOST_FIREWALL,
            "status": "pass",
            "summary": f"Host firewall enabled ({fw.get('backend') or 'unknown backend'}).",
            "detail": {**snippet, **prov},
            **prov,
        }
    return {
        "test": TEST_HOST_FIREWALL,
        "status": "fail",
        "summary": f"Host firewall collected but disabled ({fw.get('backend') or 'unknown backend'}).",
        "detail": {**snippet, **prov},
        **prov,
    }


def evaluate_host_defender_payload(
    payload: dict[str, Any],
    *,
    agent_id: str = "",
    asset_id: str = "",
    collected_at: Any = None,
    os_name: str = "",
) -> dict[str, Any]:
    """Windows Defender realtime/antivirus from agent telemetry; unknown off-Windows."""
    os_l = (os_name or str(payload.get("os") or "")).lower()
    def_st = payload.get("defender_status") if isinstance(payload.get("defender_status"), dict) else {}
    collected = bool(def_st.get("collected"))
    # Agent may expose enabled, or antivirus_enabled + realtime_protection_enabled.
    rt = _truthy_enabled(def_st.get("realtime_protection_enabled"))
    av = _truthy_enabled(def_st.get("antivirus_enabled"))
    top = _truthy_enabled(def_st.get("enabled"))
    if top is not None:
        enabled = top
    elif rt is not None or av is not None:
        # FAIL if either collected flag is explicitly false; PASS only when both true
        # (or the one present is true).
        flags = [f for f in (rt, av) if f is not None]
        enabled = all(flags) if flags else None
    else:
        enabled = None
    snippet = {
        "collected": collected,
        "enabled": enabled,
        "antivirus_enabled": def_st.get("antivirus_enabled"),
        "realtime_protection_enabled": def_st.get("realtime_protection_enabled"),
        "reason": (def_st.get("reason") or "")[:200],
        "os": os_l,
    }
    prov = _provenance(
        test_id=TEST_HOST_DEFENDER,
        agent_id=agent_id,
        asset_id=asset_id,
        observed=snippet,
        collected_at=collected_at,
        confidence=0.9 if collected and enabled is not None else 0.35,
    )
    if os_l and "win" not in os_l and collected is False:
        return {
            "test": TEST_HOST_DEFENDER,
            "status": "unknown",
            "summary": "Windows Defender check not applicable on non-Windows hosts.",
            "detail": {**snippet, **prov},
            **prov,
        }
    if not collected or enabled is None:
        return {
            "test": TEST_HOST_DEFENDER,
            "status": "unknown",
            "summary": "Windows Defender status not collected by agent telemetry.",
            "detail": {**snippet, **prov},
            **prov,
        }
    if enabled:
        return {
            "test": TEST_HOST_DEFENDER,
            "status": "pass",
            "summary": "Windows Defender antivirus/realtime protection enabled.",
            "detail": {**snippet, **prov},
            **prov,
        }
    return {
        "test": TEST_HOST_DEFENDER,
        "status": "fail",
        "summary": "Windows Defender antivirus or realtime protection disabled.",
        "detail": {**snippet, **prov},
        **prov,
    }


def _ssh_permit_root_login(settings: dict[str, Any]) -> str | None:
    if not isinstance(settings, dict):
        return None
    for k, v in settings.items():
        if str(k).lower() == "permitrootlogin":
            return str(v).strip().lower()
    return None


def evaluate_host_ssh_root_payload(
    payload: dict[str, Any],
    *,
    agent_id: str = "",
    asset_id: str = "",
    collected_at: Any = None,
) -> dict[str, Any]:
    """FAIL when ssh_config shows PermitRootLogin yes (or equivalent)."""
    ssh = payload.get("ssh_config") if isinstance(payload.get("ssh_config"), dict) else {}
    collected = bool(ssh.get("collected"))
    settings = ssh.get("settings") if isinstance(ssh.get("settings"), dict) else {}
    value = _ssh_permit_root_login(settings)
    snippet = {
        "collected": collected,
        "path": ssh.get("path"),
        "PermitRootLogin": value,
        "reason": (ssh.get("reason") or "")[:200],
    }
    prov = _provenance(
        test_id=TEST_HOST_SSH_ROOT,
        agent_id=agent_id,
        asset_id=asset_id,
        observed=snippet,
        collected_at=collected_at,
        confidence=0.9 if collected and value is not None else 0.4,
    )
    if not collected:
        return {
            "test": TEST_HOST_SSH_ROOT,
            "status": "unknown",
            "summary": "SSH config not collected by agent telemetry.",
            "detail": {**snippet, **prov},
            **prov,
        }
    if value is None:
        return {
            "test": TEST_HOST_SSH_ROOT,
            "status": "unknown",
            "summary": "SSH config collected but PermitRootLogin not present.",
            "detail": {**snippet, **prov},
            **prov,
        }
    # OpenSSH: "yes" allows password root login; treat as FAIL. Other values
    # (no, prohibit-password, without-password, forced-commands-only) PASS.
    if value in ("yes", "true", "1"):
        return {
            "test": TEST_HOST_SSH_ROOT,
            "status": "fail",
            "summary": f"SSH PermitRootLogin is '{value}' — root login via SSH is permitted.",
            "detail": {**snippet, **prov},
            **prov,
        }
    return {
        "test": TEST_HOST_SSH_ROOT,
        "status": "pass",
        "summary": f"SSH PermitRootLogin is '{value}' — root login not broadly permitted.",
        "detail": {**snippet, **prov},
        **prov,
    }


def evaluate_host_disk_encryption_payload(
    payload: dict[str, Any],
    *,
    agent_id: str = "",
    asset_id: str = "",
    collected_at: Any = None,
) -> dict[str, Any]:
    """Single-agent host_disk_encryption from disk_encryption_status telemetry.

    PASS when collected and encrypted is truthy; FAIL when collected and
    explicitly not encrypted; UNKNOWN when not collected or undecided.
    Never invents BitLocker/LUKS/FileVault PASS.
    """
    de = (
        payload.get("disk_encryption_status")
        if isinstance(payload.get("disk_encryption_status"), dict)
        else {}
    )
    collected = bool(de.get("collected"))
    encrypted = _truthy_enabled(de.get("encrypted"))
    snippet = {
        "collected": collected,
        "encrypted": de.get("encrypted"),
        "backend": de.get("backend") or de.get("method") or de.get("type"),
        "volumes": de.get("volumes"),
        "reason": (de.get("reason") or "")[:200],
    }
    prov = _provenance(
        test_id=TEST_HOST_DISK_ENCRYPTION,
        agent_id=agent_id,
        asset_id=asset_id,
        observed=snippet,
        collected_at=collected_at,
        confidence=0.9 if collected and encrypted is not None else 0.4,
    )
    if not collected or encrypted is None:
        return {
            "test": TEST_HOST_DISK_ENCRYPTION,
            "status": "unknown",
            "summary": "Disk encryption status not collected by agent telemetry.",
            "detail": {**snippet, **prov},
            **prov,
        }
    if encrypted:
        return {
            "test": TEST_HOST_DISK_ENCRYPTION,
            "status": "pass",
            "summary": (
                f"Disk encryption enabled "
                f"({snippet.get('backend') or 'unknown backend'})."
            ),
            "detail": {**snippet, **prov},
            **prov,
        }
    return {
        "test": TEST_HOST_DISK_ENCRYPTION,
        "status": "fail",
        "summary": (
            f"Disk encryption collected but not enabled "
            f"({snippet.get('backend') or 'unknown backend'})."
        ),
        "detail": {**snippet, **prov},
        **prov,
    }


_HOST_EVALUATORS = {
    TEST_HOST_FIREWALL: evaluate_host_firewall_payload,
    TEST_HOST_DEFENDER: evaluate_host_defender_payload,
    TEST_HOST_SSH_ROOT: evaluate_host_ssh_root_payload,
    TEST_HOST_DISK_ENCRYPTION: evaluate_host_disk_encryption_payload,
}


def _aggregate_host_test(user_id: str, test_name: str) -> dict[str, Any]:
    """Roll up per-agent host verdicts for Continuous Compliance.

    FAIL if any online agent with a decisive signal fails; PASS only when
    at least one decisive signal exists and none fail; UNKNOWN when no
    online agent has collected the signal.
    """
    rows = _online_agent_rows(user_id)
    per_agent: list[dict[str, Any]] = []
    fails = 0
    passes = 0
    unknowns = 0
    evaluator = _HOST_EVALUATORS[test_name]
    for row in rows:
        kwargs: dict[str, Any] = {
            "agent_id": row["agent_id"],
            "asset_id": row["asset_id"],
            "collected_at": row.get("last_checkin"),
        }
        if test_name == TEST_HOST_DEFENDER:
            kwargs["os_name"] = row.get("os") or ""
        r = evaluator(row["payload"], **kwargs)
        per_agent.append(
            {
                "agent_id": row["agent_id"],
                "asset_id": row["asset_id"],
                "hostname": row.get("hostname"),
                "status": r.get("status"),
                "summary": r.get("summary"),
            }
        )
        st = (r.get("status") or "").lower()
        if st == "fail":
            fails += 1
        elif st == "pass":
            passes += 1
        else:
            unknowns += 1

    detail = {
        "online_agents": len(rows),
        "failing_agents": fails,
        "passing_agents": passes,
        "unknown_agents": unknowns,
        "agents": per_agent[:25],
        "test_id": test_name,
        "source": "securaiq_agent",
        "confidence": 0.85 if (fails or passes) else 0.3,
    }
    if fails:
        return {
            "test": test_name,
            "status": "fail",
            "summary": f"{fails} of {len(rows)} online agent(s) failed `{test_name}` live host check.",
            "detail": detail,
        }
    if passes:
        return {
            "test": test_name,
            "status": "pass",
            "summary": f"{passes} online agent(s) passed `{test_name}`; no decisive failures.",
            "detail": detail,
        }
    return {
        "test": test_name,
        "status": "unknown",
        "summary": f"No online agent telemetry for `{test_name}` yet.",
        "detail": detail,
    }


def _test_host_firewall(user_id: str) -> dict[str, Any]:
    return _aggregate_host_test(user_id, TEST_HOST_FIREWALL)


def _test_host_defender(user_id: str) -> dict[str, Any]:
    return _aggregate_host_test(user_id, TEST_HOST_DEFENDER)


def _test_host_ssh_root(user_id: str) -> dict[str, Any]:
    return _aggregate_host_test(user_id, TEST_HOST_SSH_ROOT)


def _test_host_disk_encryption(user_id: str) -> dict[str, Any]:
    return _aggregate_host_test(user_id, TEST_HOST_DISK_ENCRYPTION)


_TEST_FUNCS = {
    TEST_ASSET_INVENTORY: _test_asset_inventory,
    TEST_VULNERABILITY_MANAGEMENT: _test_vulnerability_management,
    TEST_PATCH_MANAGEMENT: _test_patch_management,
    TEST_FIPS_REMOTE_ACCESS: _test_fips_remote_access,
    TEST_HOST_FIREWALL: _test_host_firewall,
    TEST_HOST_DEFENDER: _test_host_defender,
    TEST_HOST_SSH_ROOT: _test_host_ssh_root,
    TEST_HOST_DISK_ENCRYPTION: _test_host_disk_encryption,
}


def run_live_test(user_id: str, test_name: str) -> dict[str, Any] | None:
    """Run one named test. Returns None for an unknown test name rather
    than raising, so a caller iterating a control's mapped tests can skip
    anything unrecognized without special-casing."""
    fn = _TEST_FUNCS.get(test_name)
    if not fn:
        return None
    result = fn(user_id)
    result["tested_at"] = now()
    return result


def run_live_tests_for_control(user_id: str, framework_id: str, control_id: str, *, record_evidence: bool = True) -> list[dict[str, Any]]:
    """Every live test mapped to this control, each run fresh (not cached)
    and each optionally recorded to the Evidence Store."""
    test_names = _CONTROL_TEST_MAP.get((framework_id, control_id), [])
    results = []
    for name in test_names:
        r = run_live_test(user_id, name)
        if not r:
            continue
        results.append(r)
        if record_evidence and (r.get("status") or "").lower() != "unknown":
            try:
                from app.services.evidence import record_evidence as _record

                is_host = name in _HOST_TELEMETRY_TESTS
                _record(
                    user_id,
                    entity_type="control_test",
                    entity_id=f"{framework_id}:{control_id}",
                    source="observed" if is_host else "derived",
                    confidence=0.9 if r["status"] == "pass" else 0.7,
                    summary=f"{name}: {r['summary']}",
                    detail={"framework_id": framework_id, "control_id": control_id, **r},
                )
            except Exception:
                pass  # evidence recording is best-effort — never block the test result
    return results


def run_live_tests_for_framework(user_id: str, framework_id: str, *, record_evidence: bool = True) -> dict[str, list[dict[str, Any]]]:
    """Every control in this framework that has a mapped live test, each
    tested fresh. Returns {control_id: [test_result, ...]}."""
    control_ids = controls_with_live_tests(framework_id)
    out: dict[str, list[dict[str, Any]]] = {}
    for cid in sorted(control_ids):
        out[cid] = run_live_tests_for_control(user_id, framework_id, cid, record_evidence=record_evidence)
    return out


def mapped_framework_ids() -> list[str]:
    """Framework ids that have at least one curated live-test mapping."""
    return sorted({fid for (fid, _cid) in _CONTROL_TEST_MAP})


def _failure_risk_score(test_result: dict[str, Any]) -> float:
    """Heuristic risk weight for ranking live fails — higher = fix first.
    Uses only numbers already present on the test result detail; does not
    invent business impact currency values."""
    status = (test_result.get("status") or "").lower()
    base = 90.0 if status == "fail" else 55.0 if status == "partial" else 0.0
    detail = test_result.get("detail") or {}
    test = test_result.get("test") or ""
    if test == TEST_VULNERABILITY_MANAGEMENT:
        base += min(40.0, float(detail.get("sla_breaches") or 0) * 8.0)
        base += min(20.0, float(detail.get("open") or 0) * 0.5)
    elif test == TEST_PATCH_MANAGEMENT:
        pct = detail.get("pct")
        if pct is None:
            base += 25.0
        else:
            base += max(0.0, (90.0 - float(pct)) * 0.6)
    elif test == TEST_ASSET_INVENTORY:
        if int(detail.get("total_assets") or 0) == 0:
            base += 30.0
        else:
            cov = detail.get("coverage_pct")
            if cov is not None:
                base += max(0.0, (30.0 - float(cov)) * 0.5)
    elif test == TEST_HOST_FIREWALL:
        base += min(25.0, float(detail.get("failing_agents") or 1) * 8.0)
    elif test == TEST_HOST_DEFENDER:
        base += min(30.0, float(detail.get("failing_agents") or 1) * 10.0)
    elif test == TEST_HOST_SSH_ROOT:
        base += min(28.0, float(detail.get("failing_agents") or 1) * 9.0)
    elif test == TEST_HOST_DISK_ENCRYPTION:
        base += min(30.0, float(detail.get("failing_agents") or 1) * 10.0)
    elif test == TEST_FIPS_REMOTE_ACCESS:
        base += min(30.0, float(len(detail.get("risky_findings") or [])) * 10.0)
    return round(min(99.0, base), 1)


def list_live_control_failures(
    user_id: str,
    *,
    framework_ids: list[str] | None = None,
    record_evidence: bool = True,
    include_partial: bool = True,
) -> dict[str, Any]:
    """Run curated live tests and return a risk-ranked fail/partial queue.

    This is the continuous-compliance signal path: telemetry → control test
    → evidence (optional) → ranked gaps ready for remediation. Only controls
    in `_CONTROL_TEST_MAP` are tested — never fuzzy-inferred mappings.
    """
    from app.gap_analysis import load_framework

    fids = framework_ids or mapped_framework_ids()
    failures: list[dict[str, Any]] = []
    tested = 0
    passing = 0
    partial = 0
    failing = 0
    unknown = 0
    evaluated_at = now()

    for fid in fids:
        try:
            fw = load_framework(fid)
        except ValueError:
            continue
        control_titles = {c["id"]: c.get("title") or c["id"] for c in fw.get("controls") or []}
        results_by_control = run_live_tests_for_framework(user_id, fid, record_evidence=record_evidence)
        for cid, tests in results_by_control.items():
            for t in tests:
                tested += 1
                st = (t.get("status") or "").lower()
                if st == "pass":
                    passing += 1
                    continue
                if st == "unknown":
                    unknown += 1
                    continue
                if st == "partial":
                    partial += 1
                    if not include_partial:
                        continue
                elif st == "fail":
                    failing += 1
                else:
                    continue
                risk = _failure_risk_score(t)
                fix_hint = "Investigate control evidence"
                ws = "frameworks"
                if t.get("test") == TEST_PATCH_MANAGEMENT:
                    fix_hint = "Open Software & patches / create patch campaign"
                    ws = "software"
                elif t.get("test") == TEST_VULNERABILITY_MANAGEMENT:
                    fix_hint = "Triage open critical/high findings and remediate"
                    ws = "vulns"
                elif t.get("test") == TEST_ASSET_INVENTORY:
                    fix_hint = "Enroll agents or refresh asset inventory"
                    ws = "assets"
                elif t.get("test") == TEST_HOST_FIREWALL:
                    fix_hint = (
                        "Request approved enable_firewall on the failing agent "
                        "(Agents detail or Control Center), then verify on next check-in"
                    )
                    ws = "agents"
                elif t.get("test") == TEST_HOST_DEFENDER:
                    fix_hint = (
                        "Request approved enable_defender on the failing Windows host, "
                        "then verify on next check-in"
                    )
                    ws = "agents"
                elif t.get("test") == TEST_HOST_SSH_ROOT:
                    fix_hint = "Set PermitRootLogin no (or prohibit-password) in sshd_config"
                    ws = "agents"
                elif t.get("test") == TEST_HOST_DISK_ENCRYPTION:
                    fix_hint = (
                        "Enable full-disk encryption (BitLocker / LUKS / FileVault), "
                        "then verify on next agent check-in — no auto-remediation"
                    )
                    ws = "agents"
                failures.append(
                    {
                        "framework_id": fid,
                        "framework_name": fw.get("name") or fid,
                        "control_id": cid,
                        "title": control_titles.get(cid, cid),
                        "test": t.get("test"),
                        "status": st,
                        "summary": t.get("summary") or "",
                        "detail": t.get("detail") or {},
                        "tested_at": t.get("tested_at") or evaluated_at,
                        "risk_score": risk,
                        "why": [
                            f"Live test `{t.get('test')}` status={st}",
                            t.get("summary") or "",
                        ],
                        "fix_hint": fix_hint,
                        "workspace": ws,
                    }
                )

    failures.sort(
        key=lambda x: (
            0 if x["status"] == "fail" else 1,
            -float(x["risk_score"]),
            x["framework_id"],
            x["control_id"],
            x["test"] or "",
        )
    )
    return {
        "evaluated_at": evaluated_at,
        "frameworks_tested": len(fids),
        "controls_with_tests": sum(1 for _ in _CONTROL_TEST_MAP),
        "tests_run": tested,
        "passing": passing,
        "partial": partial,
        "failing": failing,
        "unknown": unknown,
        "failures": failures,
        "disclaimer": (
            "Live control tests are telemetry signals that help assess operating effectiveness — "
            "not a certification that you are compliant with any framework."
        ),
    }


def _last_agent_host_status(user_id: str, agent_id: str, test_name: str) -> str | None:
    """Most recent observed status for this agent+test from the Evidence Store."""
    try:
        from app.services.evidence import get_evidence_for

        rows = get_evidence_for(
            user_id,
            entity_type="agent_host_control",
            entity_id=f"{agent_id}:{test_name}",
            limit=5,
        )
    except Exception:
        return None
    if not rows:
        return None
    # Prefer most recently seen
    rows = sorted(rows, key=lambda r: float(r.get("last_seen") or 0), reverse=True)
    for row in rows:
        detail = row.get("detail") or {}
        st = (detail.get("status") or "").lower()
        if st in ("fail", "pass", "unknown", "partial"):
            return st
        # Fallback: parse from summary prefix "host_firewall:fail — ..."
        summary = row.get("summary") or ""
        for token in ("fail", "pass", "unknown", "partial"):
            if f"{test_name}:{token}" in summary.lower() or summary.lower().startswith(f"{token}:"):
                return token
    return None


def _record_host_control_evidence(
    user_id: str,
    *,
    agent_id: str,
    result: dict[str, Any],
    force: bool = False,
) -> dict[str, Any] | None:
    """Record observed evidence on status change, or always on FAIL (idempotent)."""
    test_name = result.get("test") or ""
    status = (result.get("status") or "").lower()
    if status == "unknown" and not force:
        return None
    prev = _last_agent_host_status(user_id, agent_id, test_name)
    # Avoid spam: PASS only when status changed (or first decisive record);
    # FAIL always (fingerprint folds re-observations into hit_count).
    if status == "pass" and prev == "pass" and not force:
        return None
    if status == "pass" and prev is None and not force:
        # First PASS with no prior FAIL — still record once for baseline evidence.
        pass
    elif status not in ("fail", "pass"):
        return None

    try:
        from app.services.evidence import record_evidence as _record

        summary = f"{test_name}:{status} — {result.get('summary') or ''}"
        return _record(
            user_id,
            entity_type="agent_host_control",
            entity_id=f"{agent_id}:{test_name}",
            source="observed",
            confidence=float(result.get("confidence") or 0.85),
            summary=summary[:500],
            detail={
                "status": status,
                "test": test_name,
                "agent_id": agent_id,
                "asset_id": result.get("asset_id") or "",
                "observed": result.get("observed") or (result.get("detail") or {}).get("observed"),
                "collected_at": result.get("collected_at"),
                "source": "securaiq_agent",
                "test_id": test_name,
            },
            created_by="securaiq_agent",
        )
    except Exception:
        return None


def _mapped_control_ids_for_test(test_name: str) -> list[dict[str, str]]:
    return [
        {"framework_id": fid, "control_id": cid}
        for (fid, cid), names in _CONTROL_TEST_MAP.items()
        if test_name in names
    ]


def _ensure_host_firewall_remediation(
    user_id: str,
    *,
    agent_id: str,
    hostname: str,
    result: dict[str, Any],
) -> dict[str, Any] | None:
    """RT-11 — ensure an open gap remediation exists for host_firewall FAIL.

    Reuses enterprise.create_remediation (gap remediations). Manual approve
    path: open Remediations workspace → assign owner → mark done after
    firewall is re-enabled and the next check-in publishes PASS.
    """
    try:
        from app.enterprise import create_remediation, list_remediations, update_remediation
    except Exception:
        return None

    marker = f"host_firewall:{agent_id}"
    title = f"Enable host firewall on {hostname or agent_id[:8]}"
    try:
        open_rems = list_remediations(user_id, status="open")
    except Exception:
        open_rems = []
    for rem in open_rems:
        notes = rem.get("notes") or ""
        rec = rem.get("recommendation") or ""
        if marker in notes or marker in rec or (
            rem.get("control_id") == "CIS-12" and agent_id[:8] in (rem.get("title") or "")
        ):
            return rem

    primary = _HOST_TEST_PRIMARY_CONTROLS.get(TEST_HOST_FIREWALL, ("cis_controls", "CIS-12"))
    recommendation = (
        f"{result.get('summary') or 'Host firewall disabled.'} "
        f"[{marker}] Enable the host firewall (ufw/firewalld/Windows Firewall), "
        f"then wait for the next SecuraIQ agent check-in to verify PASS. "
        f"Operator may request approved agent command kind=enable_firewall "
        f"(POST /api/agents/{{id}}/commands/enable-firewall) then approve "
        f"(pending_approval → queued) — never auto-executed."
    )
    try:
        rem = create_remediation(
            user_id,
            control_id=primary[1],
            title=title[:300],
            recommendation=recommendation[:2000],
        )
        rid = rem.get("id")
        if rid:
            try:
                update_remediation(user_id, rid, {"notes": marker})
            except Exception:
                pass
        try:
            from app.realtime_bus import publish

            publish(
                event_type="remediation.recommended",
                type="remediation.recommended",
                user_id=user_id,
                agent_id=agent_id,
                test=TEST_HOST_FIREWALL,
                remediation_id=rid,
                title=title,
                recommendation=recommendation[:500],
                auto_execute=False,
                source="rt11_host_firewall",
            )
        except Exception:
            pass
        return rem
    except Exception:
        # Fallback: publish remediation-needed only (no DB row).
        try:
            from app.realtime_bus import publish

            publish(
                type="remediation",
                id=f"needed:{marker}",
                user_id=user_id,
                agent_id=agent_id,
                status="needed",
                title=title,
                test=TEST_HOST_FIREWALL,
            )
        except Exception:
            pass
        return None


def _close_host_firewall_remediation(user_id: str, agent_id: str) -> None:
    """Mark matching open host_firewall remediation done after PASS verify."""
    try:
        from app.enterprise import list_remediations, update_remediation

        marker = f"host_firewall:{agent_id}"
        for rem in list_remediations(user_id, status="open"):
            notes = rem.get("notes") or ""
            rec = rem.get("recommendation") or ""
            if marker in notes or marker in rec:
                update_remediation(user_id, rem["id"], {"status": "done"})
    except Exception:
        pass


def evaluate_agent_host_controls(
    user_id: str,
    agent_id: str,
    payload: dict[str, Any],
    *,
    asset_id: str = "",
) -> dict[str, Any]:
    """RT-10/11 — run host firewall / Defender / SSH / disk encryption for one agent.

    Publishes compliance (+ optional risk) events and records observed evidence
    on FAIL/PASS transitions. Never raises to callers (check-in must stay up).
    """
    out: dict[str, Any] = {"ok": True, "results": [], "evidence_ids": [], "events": []}
    if not user_id or not agent_id:
        return {"ok": False, "error": "user_id and agent_id required", "results": []}

    try:
        collected_at = now()
        asset = asset_id or ""
        hostname = str(payload.get("hostname") or "")
        os_name = str(payload.get("os") or "")

        evaluators = (
            (TEST_HOST_FIREWALL, lambda: evaluate_host_firewall_payload(
                payload, agent_id=agent_id, asset_id=asset, collected_at=collected_at
            )),
            (TEST_HOST_DEFENDER, lambda: evaluate_host_defender_payload(
                payload, agent_id=agent_id, asset_id=asset, collected_at=collected_at, os_name=os_name
            )),
            (TEST_HOST_SSH_ROOT, lambda: evaluate_host_ssh_root_payload(
                payload, agent_id=agent_id, asset_id=asset, collected_at=collected_at
            )),
            (TEST_HOST_DISK_ENCRYPTION, lambda: evaluate_host_disk_encryption_payload(
                payload, agent_id=agent_id, asset_id=asset, collected_at=collected_at
            )),
        )

        for test_name, fn in evaluators:
            try:
                prev = _last_agent_host_status(user_id, agent_id, test_name)
                result = fn()
                result["tested_at"] = collected_at
                out["results"].append(result)
                status = (result.get("status") or "").lower()
                if status == "unknown":
                    continue

                evidence = _record_host_control_evidence(
                    user_id, agent_id=agent_id, result=result, force=(status == "fail")
                )
                evidence_ids = [evidence["id"]] if evidence and evidence.get("id") else []
                if evidence_ids:
                    out["evidence_ids"].extend(evidence_ids)

                primary = _HOST_TEST_PRIMARY_CONTROLS.get(test_name)
                control_ids = _mapped_control_ids_for_test(test_name)
                # Persist for Control Center summary KPIs (cmmc_l2 + all bindings).
                try:
                    from app.controls.results import record_test_result

                    for binding in control_ids:
                        fid = str(binding.get("framework_id") or "").strip()
                        cid = str(binding.get("control_id") or "").strip()
                        if not fid or not cid:
                            continue
                        record_test_result(
                            user_id,
                            fid,
                            cid,
                            test_name=test_name,
                            status=status,
                            summary=str(result.get("summary") or "")[:500],
                            detail={
                                "agent_id": agent_id,
                                "asset_id": asset,
                                **(result.get("detail") or {}),
                            },
                            tested_at=collected_at,
                        )
                except Exception:
                    pass
                try:
                    from app.realtime_bus import publish

                    publish(
                        type="compliance",
                        status=status,
                        test=test_name,
                        control_ids=control_ids,
                        control_id=primary[1] if primary else None,
                        framework_id=primary[0] if primary else None,
                        evidence_ids=evidence_ids,
                        agent_id=agent_id,
                        asset_id=asset,
                        user_id=user_id,
                        summary=result.get("summary") or "",
                        source="securaiq_agent",
                    )
                    out["events"].append({"type": "compliance", "status": status, "test": test_name})
                except Exception:
                    pass

                # Dual-write dotted control.* for Control Center / event_processor
                if status in ("fail", "pass"):
                    status_event = "control.failed" if status == "fail" else "control.passed"
                    try:
                        from app.realtime_bus import publish

                        publish(
                            event_type=status_event,
                            type=status_event,
                            status=status,
                            test=test_name,
                            control_ids=control_ids,
                            control_id=primary[1] if primary else None,
                            framework_id=primary[0] if primary else None,
                            evidence_ids=evidence_ids,
                            agent_id=agent_id,
                            asset_id=asset,
                            user_id=user_id,
                            summary=result.get("summary") or "",
                            detail=result.get("detail") or {},
                            source="securaiq_agent",
                        )
                        out["events"].append({"type": status_event, "status": status, "test": test_name})
                    except Exception:
                        pass

                if status == "fail":
                    try:
                        from app.realtime_bus import publish

                        publish(
                            type="risk",
                            severity="medium" if test_name != TEST_HOST_DEFENDER else "high",
                            title=f"Host control FAIL: {test_name}",
                            summary=result.get("summary") or "",
                            agent_id=agent_id,
                            asset_id=asset,
                            user_id=user_id,
                            test=test_name,
                            reason="host_control_fail",
                            evidence_ids=evidence_ids,
                        )
                        out["events"].append({"type": "risk", "test": test_name})
                    except Exception:
                        pass

                    # Org risk delta (previous_score / score_delta when known)
                    try:
                        from app.event_processor import _maybe_publish_org_risk

                        _maybe_publish_org_risk(
                            user_id, reason=f"host_control_fail:{test_name}"
                        )
                        out["events"].append({"type": "risk.changed", "test": test_name})
                    except Exception:
                        pass

                    # Firewall FAIL → best-effort attack-path refresh when asset known
                    if test_name == TEST_HOST_FIREWALL and asset:
                        try:
                            from app.services.attack_path_realtime import (
                                refresh_attack_paths_for_threat,
                            )

                            refresh_attack_paths_for_threat(
                                user_id,
                                agent_id=agent_id,
                                asset_id=asset,
                                reason="host_firewall_fail",
                            )
                        except Exception:
                            pass

                    # Sprint 4/5: POA&M-like open for any host FAIL (incl. firewall RT-11)
                    try:
                        from app.controls.poam import open_poam_for_host_fail

                        rem = open_poam_for_host_fail(
                            user_id,
                            agent_id=agent_id,
                            hostname=hostname,
                            test_name=test_name,
                            result=result,
                            control_id=primary[1] if primary else None,
                            framework_id=primary[0] if primary else None,
                        )
                        if rem and rem.get("id"):
                            out["remediation_id"] = rem.get("id")
                            out.setdefault("remediation_ids", []).append(rem.get("id"))
                            try:
                                from app.realtime_bus import publish

                                publish(
                                    type="remediation.recommended",
                                    event_type="remediation.recommended",
                                    remediation_id=rem.get("id"),
                                    test=test_name,
                                    agent_id=agent_id,
                                    asset_id=asset,
                                    user_id=user_id,
                                    control_id=primary[1] if primary else None,
                                    framework_id=primary[0] if primary else None,
                                    summary=result.get("summary") or "",
                                    auto_execute=False,
                                )
                                out["events"].append(
                                    {"type": "remediation.recommended", "test": test_name}
                                )
                            except Exception:
                                pass
                    except Exception:
                        # Legacy RT-11 firewall-only fallback
                        if test_name == TEST_HOST_FIREWALL:
                            rem = _ensure_host_firewall_remediation(
                                user_id, agent_id=agent_id, hostname=hostname, result=result
                            )
                            if rem:
                                out["remediation_id"] = rem.get("id")

                elif status == "pass" and prev == "fail":
                    # RT-11 verify: prior FAIL → PASS evidence + risk-reduction hint
                    try:
                        from app.realtime_bus import publish

                        publish(
                            type="risk",
                            severity="info",
                            title=f"Host control recovered: {test_name}",
                            summary=(
                                f"Previous FAIL cleared after re-check. {result.get('summary') or ''}"
                            ),
                            agent_id=agent_id,
                            asset_id=asset,
                            user_id=user_id,
                            test=test_name,
                            reason="host_control_pass_after_fail",
                            evidence_ids=evidence_ids,
                            risk_hint="reduction",
                        )
                        out["events"].append({"type": "risk", "hint": "reduction", "test": test_name})
                    except Exception:
                        pass
                    try:
                        from app.event_processor import _maybe_publish_org_risk

                        _maybe_publish_org_risk(
                            user_id, reason=f"host_control_pass:{test_name}"
                        )
                        out["events"].append({"type": "risk.changed", "test": test_name})
                    except Exception:
                        pass
                    try:
                        from app.controls.poam import close_poam_for_host_pass

                        close_poam_for_host_pass(
                            user_id, agent_id=agent_id, test_name=test_name
                        )
                    except Exception:
                        if test_name == TEST_HOST_FIREWALL:
                            _close_host_firewall_remediation(user_id, agent_id)

                # Close enable_firewall / enable_defender verification from observed host state
                if status in ("pass", "fail") and test_name in (
                    TEST_HOST_FIREWALL,
                    TEST_HOST_DEFENDER,
                ):
                    try:
                        from app.agents import verify_pending_host_remediation_commands

                        verified = verify_pending_host_remediation_commands(
                            agent_id,
                            test_name=test_name,
                            observed_pass=(status == "pass"),
                        )
                        if verified:
                            out.setdefault("command_verifications", []).extend(verified)
                            out["events"].append(
                                {
                                    "type": "command.verified"
                                    if status == "pass"
                                    else "command.verification_failed",
                                    "test": test_name,
                                    "count": len(verified),
                                }
                            )
                    except Exception:
                        pass
            except Exception:
                continue
    except Exception as exc:
        return {"ok": False, "error": str(exc)[:200], "results": out.get("results") or []}

    return out