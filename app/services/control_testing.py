"""Live Control Testing — a control's status computed directly from real
product data (assets, vulnerabilities, patch inventory), independent of the
pasted-evidence heuristic in app.gap_analysis.score_control_against_evidence.

This is deliberately additive and separate, not a replacement:
  - app.gap_analysis's keyword-matched scoring answers "does the evidence
    text a human pasted in describe this control?" -- a proxy for policy/
    procedure documentation.
  - This module answers a narrower, harder question for a small number of
    controls: "does SecuraIQ's own real telemetry show this control is
    actually operating?" -- e.g. is there a real asset inventory, are open
    critical/high vulnerabilities within SLA, is the patch-compliance rate
    healthy. Three tests today; more can be added the same way.

A control is only ever mapped to a live test here via an EXPLICIT
(framework_id, control_id) -> test-name table (_CONTROL_TEST_MAP below),
never fuzzy keyword matching -- a live test result is a specific factual
claim about a specific control, so the mapping itself must be as precise
as everything else in this product's evidence model. Adding a wrong
mapping would be exactly the kind of "AI invents a relationship" mistake
this product's whole evidence philosophy exists to prevent.

Every result records to the Evidence Store (app.services.evidence) with
source="derived" -- computed from real data, not a human attestation and
not a guess -- so it's independently queryable/auditable later.
"""

from __future__ import annotations

from typing import Any

from app.db import now

# Real product-capability tests this module can run today.
TEST_ASSET_INVENTORY = "asset_inventory"
TEST_VULNERABILITY_MANAGEMENT = "vulnerability_management"
TEST_PATCH_MANAGEMENT = "patch_management"

# Explicit (framework_id, control_id) -> [test names]. Curated by hand from
# each framework's own control title/keywords (see data/frameworks/*.json)
# -- never derived by fuzzy string matching. A control absent from this map
# simply has no live test yet; its status still comes from pasted evidence
# only, exactly as before this module existed.
_CONTROL_TEST_MAP: dict[tuple[str, str], list[str]] = {
    ("cis_controls", "CIS-1"): [TEST_ASSET_INVENTORY],
    ("iso27001", "A.5.9"): [TEST_ASSET_INVENTORY],
    ("nist_csf", "ID.AM-01"): [TEST_ASSET_INVENTORY],
    ("cis_controls", "CIS-7"): [TEST_VULNERABILITY_MANAGEMENT, TEST_PATCH_MANAGEMENT],
    ("iso27001", "A.8.8"): [TEST_VULNERABILITY_MANAGEMENT, TEST_PATCH_MANAGEMENT],
    ("nist_csf", "ID.RA-01"): [TEST_VULNERABILITY_MANAGEMENT],
    ("nist_csf", "PR.PS-02"): [TEST_PATCH_MANAGEMENT],
    ("nist_800_53", "RA-5"): [TEST_VULNERABILITY_MANAGEMENT],
    ("nist_800_53", "SI-2"): [TEST_PATCH_MANAGEMENT],
    ("nist_800_171", "3.11.2"): [TEST_VULNERABILITY_MANAGEMENT],
    ("nist_800_171", "3.14.1"): [TEST_PATCH_MANAGEMENT],
    ("cmmc_l2", "RA.L2-3.11.2"): [TEST_VULNERABILITY_MANAGEMENT],
    ("cmmc_l2", "SI.L2-3.14.1"): [TEST_PATCH_MANAGEMENT],
    ("pci_dss", "6.3"): [TEST_VULNERABILITY_MANAGEMENT],
    ("pci_dss", "11.3"): [TEST_VULNERABILITY_MANAGEMENT],
}

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


_TEST_FUNCS = {
    TEST_ASSET_INVENTORY: _test_asset_inventory,
    TEST_VULNERABILITY_MANAGEMENT: _test_vulnerability_management,
    TEST_PATCH_MANAGEMENT: _test_patch_management,
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
        if record_evidence:
            try:
                from app.services.evidence import record_evidence as _record

                _record(
                    user_id,
                    entity_type="control_test",
                    entity_id=f"{framework_id}:{control_id}",
                    source="derived",
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
        "failures": failures,
        "disclaimer": (
            "Live control tests are telemetry signals that help assess operating effectiveness — "
            "not a certification that you are compliant with any framework."
        ),
    }