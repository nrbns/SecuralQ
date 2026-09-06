"""Integrity checks for the cmmc_l2 framework catalog (data/frameworks/cmmc_l2.json).

This catalog covers all 110 NIST SP 800-171 Rev 2 / CMMC 2.0 Level 2 practices
(expanded from an earlier 24-practice priority subset). These tests lock in
the shape the rest of the app depends on -- 110 unique controls, official DoD
SPRS point weights that sum to 313, and exactly 17 controls flagged as also
required at CMMC Level 1 -- so a future edit can't silently drop practices or
corrupt the weights without a test failing. Also asserts scripts/refresh_frameworks.py
(the generator) produces byte-identical output to the checked-in JSON, so the
two can't drift apart.
"""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
CATALOG_PATH = REPO_ROOT / "data" / "frameworks" / "cmmc_l2.json"


def _load_catalog() -> dict:
    return json.loads(CATALOG_PATH.read_text(encoding="utf-8"))


def test_catalog_has_all_110_unique_controls():
    data = _load_catalog()
    controls = data["controls"]
    assert len(controls) == 110
    ids = [c["id"] for c in controls]
    assert len(set(ids)) == 110, "duplicate control ids found"


def test_catalog_family_counts_match_nist_800_171_rev2():
    """Official family sizes: AC 22, AT 3, AU 9, CM 9, IA 11, IR 3, MA 6, MP 9,
    PS 2, PE 6, RA 3, CA 4, SC 16, SI 7 = 110."""
    data = _load_catalog()
    expected = {
        "Access Control": 22,
        "Awareness and Training": 3,
        "Audit and Accountability": 9,
        "Configuration Management": 9,
        "Identification and Authentication": 11,
        "Incident Response": 3,
        "Maintenance": 6,
        "Media Protection": 9,
        "Personnel Security": 2,
        "Physical Protection": 6,
        "Risk Assessment": 3,
        "Security Assessment": 4,
        "System and Communications Protection": 16,
        "System and Information Integrity": 7,
    }
    counts: dict[str, int] = {}
    for c in data["controls"]:
        counts[c["domain"]] = counts.get(c["domain"], 0) + 1
    assert counts == expected


def test_catalog_sprs_weights_sum_to_313():
    data = _load_catalog()
    total = sum(c["sprs_weight"] for c in data["controls"])
    assert total == 313


def test_catalog_exactly_17_level1_controls():
    data = _load_catalog()
    l1 = [c["id"] for c in data["controls"] if c.get("cmmc_level1")]
    assert len(l1) == 17


def test_catalog_ssp_control_present_with_zero_weight():
    """3.12.4 (System Security Plan) has no SPRS point value -- it's a
    pass/fail gate, not a scored control (per DoD assessment methodology)."""
    data = _load_catalog()
    ssp = next(c for c in data["controls"] if c["id"] == "CA.L2-3.12.4")
    assert ssp["sprs_weight"] == 0
    assert "security plan" in ssp["title"].lower()


def test_catalog_has_official_resources():
    data = _load_catalog()
    urls = {r["url"] for r in data["resources"]}
    assert "https://dodcio.defense.gov/cmmc/About/" in urls
    assert "https://dodcio.defense.gov/CMMC/Resources-Documentation/" in urls


def test_live_control_test_mappings_still_resolve():
    """app/services/control_testing.py hard-maps specific cmmc_l2 control ids
    to live test names -- confirm those ids still exist after the expansion."""
    data = _load_catalog()
    ids = {c["id"] for c in data["controls"]}
    assert "RA.L2-3.11.2" in ids
    assert "SI.L2-3.14.1" in ids


def test_generator_script_matches_checked_in_catalog():
    """scripts/refresh_frameworks.py:cmmc_l2() must produce exactly the JSON
    checked in at data/frameworks/cmmc_l2.json -- otherwise a future
    `python scripts/refresh_frameworks.py` run would silently regress the
    catalog back to a stale version."""
    spec = importlib.util.spec_from_file_location(
        "refresh_frameworks", REPO_ROOT / "scripts" / "refresh_frameworks.py"
    )
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)

    generated = module.cmmc_l2()
    checked_in = _load_catalog()
    assert generated == checked_in
