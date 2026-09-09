"""Control catalog — load & normalize from existing framework JSON.

Reuses ``app.gap_analysis.list_frameworks`` / ``load_framework``. Never invents
control text; CMMC IDs are normalized to catalog form (e.g. ``AC.L2-3.1.1``).
"""

from __future__ import annotations

import re
from typing import Any

from app.controls.schema import Control, ControlTest, Framework, Verifiability
from app.gap_analysis import list_frameworks, load_framework

# CMMC practice id: DOMAIN.L{n}-{requirement}  e.g. SC.L2-3.13.1
_CMMC_ID_RE = re.compile(
    r"^([A-Za-z]{2})\.(L\d)-(\d+(?:\.\d+)*)$",
    re.IGNORECASE,
)


def normalize_cmmc_control_id(control_id: str) -> str:
    """Normalize CMMC practice ids to catalog casing (``AC.L2-3.1.1``).

    Non-CMMC-shaped ids are returned stripped but otherwise unchanged.
    """
    cid = (control_id or "").strip()
    if not cid:
        return cid
    m = _CMMC_ID_RE.match(cid)
    if not m:
        return cid
    domain, level, req = m.group(1), m.group(2), m.group(3)
    return f"{domain.upper()}.{level.upper()}-{req}"


def normalize_control_id(framework_id: str, control_id: str) -> str:
    """Framework-aware id normalize (CMMC casing; others strip only)."""
    fid = (framework_id or "").strip().lower()
    cid = (control_id or "").strip()
    if fid in ("cmmc_l2", "cmmc") or _CMMC_ID_RE.match(cid):
        return normalize_cmmc_control_id(cid)
    return cid


def _mapped_test_names(framework_id: str, control_id: str) -> list[str]:
    try:
        from app.services.control_testing import _CONTROL_TEST_MAP
    except Exception:
        return []
    fid = (framework_id or "").strip()
    cid = normalize_control_id(fid, control_id)
    # Try exact, then case-insensitive key scan for CMMC
    names = _CONTROL_TEST_MAP.get((fid, cid))
    if names is not None:
        return list(names)
    for (mf, mc), tests in _CONTROL_TEST_MAP.items():
        if mf == fid and normalize_control_id(fid, mc) == cid:
            return list(tests)
    return []


def _verifiability_for_tests(test_names: list[str]) -> Verifiability:
    """Classify verifiability from whether curated live tests exist.

    - no tests → human (pasted evidence / assessment)
    - only soft/proxy tests (asset_inventory) → partial
    - host / vuln / patch telemetry → machine
    - mix → partial
    """
    if not test_names:
        return "human"
    soft = {"asset_inventory"}
    hard = {
        "host_firewall",
        "host_defender",
        "host_ssh_root",
        "vulnerability_management",
        "patch_management",
    }
    names = set(test_names)
    if names <= soft:
        return "partial"
    if names <= hard:
        return "machine"
    if names & hard:
        return "partial"
    return "partial"


def _control_from_row(framework_id: str, row: dict[str, Any]) -> Control:
    cid = normalize_control_id(framework_id, str(row.get("id") or ""))
    test_names = _mapped_test_names(framework_id, cid)
    ver = _verifiability_for_tests(test_names)
    tests = [
        ControlTest(
            name=n,
            verifiability=ver,
            description=f"Live test `{n}` (explicit map in control_testing)",
        )
        for n in test_names
    ]
    return Control(
        id=cid,
        title=str(row.get("title") or cid),
        framework_id=framework_id,
        domain=str(row.get("domain") or ""),
        description=str(row.get("description") or ""),
        keywords=list(row.get("keywords") or []),
        objectives=[],
        tests=tests,
        verifiability=ver,
        raw=dict(row),
    )


def list_framework_controls(framework_id: str) -> list[Control]:
    """All controls in a framework catalog, normalized."""
    fw = load_framework(framework_id)
    fid = str(fw.get("id") or framework_id)
    return [_control_from_row(fid, c) for c in (fw.get("controls") or [])]


def get_control(framework_id: str, control_id: str) -> Control | None:
    """One control by id (CMMC ids matched case-insensitively / normalized)."""
    fw = load_framework(framework_id)
    fid = str(fw.get("id") or framework_id)
    want = normalize_control_id(fid, control_id)
    for row in fw.get("controls") or []:
        rid = normalize_control_id(fid, str(row.get("id") or ""))
        if rid == want or str(row.get("id") or "").strip().lower() == (control_id or "").strip().lower():
            return _control_from_row(fid, row)
    return None


def framework_meta(framework_id: str) -> Framework:
    fw = load_framework(framework_id)
    controls = fw.get("controls") or []
    return Framework(
        id=str(fw.get("id") or framework_id),
        name=str(fw.get("name") or framework_id),
        version=str(fw.get("version") or ""),
        description=str(fw.get("description") or ""),
        control_count=len(controls),
    )


def catalog_frameworks() -> list[dict[str, Any]]:
    """Thin pass-through of gap_analysis.list_frameworks()."""
    return list_frameworks()


def control_center_summary(user_id: str, framework_id: str = "cmmc_l2") -> dict[str, Any]:
    """Control Center rollup for one framework.

    Counts come from stored live test results when available; otherwise honest
    zeros (never invent pass/fail). Evidence coverage and open gaps are
    best-effort from existing assessment / remediations data.
    """
    fw = load_framework(framework_id)
    fid = str(fw.get("id") or framework_id)
    controls = fw.get("controls") or []
    total = len(controls)

    passing = failing = unknown = na = 0
    last_test: float | None = None

    try:
        from app.controls.results import aggregate_control_statuses, ensure_schema

        ensure_schema()
        agg = aggregate_control_statuses(user_id, fid)
        passing = int(agg.get("passing") or 0)
        failing = int(agg.get("failing") or 0)
        unknown = int(agg.get("unknown") or 0)
        na = int(agg.get("na") or 0)
        last_test = agg.get("last_test")
    except Exception:
        passing = failing = unknown = na = 0
        last_test = None

    evidence_coverage: float | None = None
    try:
        from app.gap_analysis import get_assessment, list_assessments
        from app.evidence_workflow import evidence_coverage_for_assessment

        latest = None
        for row in list_assessments(user_id):
            if row.get("framework_id") == fid:
                latest = row
                break
        if latest:
            coverage = evidence_coverage_for_assessment(user_id, latest["id"])
            evidence_coverage = coverage.get("coverage_percent")
    except Exception:
        evidence_coverage = None

    open_gaps = 0
    try:
        from app.gap_analysis import get_assessment, list_assessments

        for row in list_assessments(user_id):
            if row.get("framework_id") != fid:
                continue
            full = get_assessment(user_id, row["id"])
            if not full:
                break
            for r in full.get("results") or []:
                if (r.get("status") or "").lower() in ("missing", "partial"):
                    open_gaps += 1
            break
    except Exception:
        open_gaps = 0

    return {
        "framework_id": fid,
        "framework_name": fw.get("name") or fid,
        "controls_total": total,
        "passing": passing,
        "failing": failing,
        "unknown": unknown,
        "na": na,
        "evidence_coverage": evidence_coverage if evidence_coverage is not None else 0,
        "open_gaps": open_gaps,
        "last_test": last_test,
        "disclaimer": (
            "Live control tests are operating-effectiveness signals from SecuraIQ "
            "telemetry — not a CMMC certification, SPRS submission, or compliance "
            "attestation. Catalog text is sourced from framework JSON only."
        ),
    }


def verifiability_map(framework_id: str) -> dict[str, Any]:
    """machine | partial | human | unknown for each control in the catalog."""
    controls = list_framework_controls(framework_id)
    by_control = {
        c.id: {
            "control_id": c.id,
            "title": c.title,
            "verifiability": c.verifiability,
            "live_tests": [t.name for t in c.tests],
        }
        for c in controls
    }
    counts = {"machine": 0, "partial": 0, "human": 0, "unknown": 0}
    for row in by_control.values():
        v = row["verifiability"]
        if v in counts:
            counts[v] += 1
        else:
            counts["unknown"] += 1
    return {
        "framework_id": framework_id,
        "controls_total": len(controls),
        "counts": counts,
        "controls": by_control,
    }
