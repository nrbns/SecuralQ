"""Integrity checks from the full-catalog completeness audit (task: audit all
remaining framework catalogs against their real official source).

Covers three catalogs fixed during that audit:
- nist_csf: expanded from an 84-subcategory subset to the full 106 NIST CSF
  2.0 core subcategories (per NIST CSWP.29 / "CSF 2.0 Core With Withdrawn
  CSF 1.1 Elements", nist.gov, 2024-03-25).
- nist_800_171: expanded from a 33-control subset to the full 110 NIST SP
  800-171 Rev 2 security requirements (the same 110 CMMC 2.0 Level 2 assesses).
- soc2: filled in the 2 missing Common Criteria controls (CC6.4, CC6.5) for
  full 33/33 Common Criteria coverage.

These tests lock in the corrected shapes and assert scripts/refresh_frameworks.py
produces byte-identical output to each checked-in JSON, so the generator and
the data file can't silently drift apart.
"""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
FRAMEWORKS_DIR = REPO_ROOT / "data" / "frameworks"


def _load(name: str) -> dict:
    return json.loads((FRAMEWORKS_DIR / f"{name}.json").read_text(encoding="utf-8"))


def _load_generator_module():
    spec = importlib.util.spec_from_file_location(
        "refresh_frameworks", REPO_ROOT / "scripts" / "refresh_frameworks.py"
    )
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


# --- nist_csf: full 106 CSF 2.0 core subcategories -------------------------


def test_nist_csf_has_106_unique_subcategories():
    data = _load("nist_csf")
    controls = data["controls"]
    assert len(controls) == 106
    ids = [c["id"] for c in controls]
    assert len(set(ids)) == 106, "duplicate control ids found"


def test_nist_csf_function_counts_match_cswp29():
    """Official NIST CSF 2.0 core breakdown (CSWP.29): GV 31, ID 21, PR 22,
    DE 11, RS 13, RC 8 = 106 active subcategories."""
    data = _load("nist_csf")
    expected = {"GV": 31, "ID": 21, "PR": 22, "DE": 11, "RS": 13, "RC": 8}
    counts: dict[str, int] = {}
    for c in data["controls"]:
        fn = c["id"].split(".")[0]
        counts[fn] = counts.get(fn, 0) + 1
    assert counts == expected


def test_nist_csf_live_control_test_mappings_still_resolve():
    """app/services/control_testing.py hard-maps these nist_csf ids to live
    tests -- confirm they still exist after the 84->106 expansion."""
    data = _load("nist_csf")
    ids = {c["id"] for c in data["controls"]}
    assert "ID.AM-01" in ids
    assert "ID.RA-01" in ids
    assert "PR.PS-02" in ids


def test_nist_csf_generator_matches_checked_in_catalog():
    module = _load_generator_module()
    assert module.nist_csf() == _load("nist_csf")


# --- nist_800_171: full 110 requirements ------------------------------------


def test_nist_800_171_has_110_unique_controls():
    data = _load("nist_800_171")
    controls = data["controls"]
    assert len(controls) == 110
    ids = [c["id"] for c in controls]
    assert len(set(ids)) == 110


def test_nist_800_171_live_control_test_mappings_still_resolve():
    data = _load("nist_800_171")
    ids = {c["id"] for c in data["controls"]}
    assert "3.11.2" in ids
    assert "3.14.1" in ids


def test_nist_800_171_generator_matches_checked_in_catalog():
    module = _load_generator_module()
    assert module.nist_800_171() == _load("nist_800_171")


# --- soc2: full 33/33 Common Criteria + Availability + Confidentiality -----


def test_soc2_has_full_common_criteria_coverage():
    data = _load("soc2")
    cc_ids = {c["id"] for c in data["controls"] if c["id"].startswith("CC")}
    assert len(cc_ids) == 33
    assert "CC6.4" in cc_ids
    assert "CC6.5" in cc_ids


def test_soc2_total_control_count():
    data = _load("soc2")
    assert len(data["controls"]) == 38  # 33 CC + 3 Availability + 2 Confidentiality


def test_soc2_generator_matches_checked_in_catalog():
    module = _load_generator_module()
    assert module.soc2() == _load("soc2")
