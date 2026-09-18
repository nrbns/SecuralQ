"""DPDP Act 2023 + Rules 2025 catalog integrity + phased commencement."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent


def _load_builder(name: str):
    spec = importlib.util.spec_from_file_location(
        "refresh_frameworks", REPO_ROOT / "scripts" / "refresh_frameworks.py"
    )
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return getattr(module, name)


def test_dpdp_act_catalog_shape():
    data = json.loads((REPO_ROOT / "data/frameworks/dpdp_act_2023.json").read_text(encoding="utf-8"))
    assert data["id"] == "dpdp_act_2023"
    assert data["jurisdiction"] == "IN"
    assert data["family"] == "India DPDP"
    assert "not a determination" in (data["legal_disclaimer"] or "").lower() or "evidence-backed" in (
        data["legal_disclaimer"] or ""
    ).lower()
    ids = [c["id"] for c in data["controls"]]
    assert len(ids) == len(set(ids))
    assert "Act-8" in ids
    assert "Act-10" in ids
    sdf = next(c for c in data["controls"] if c["id"] == "Act-10")
    assert sdf.get("applicability", {}).get("significant_data_fiduciary") == "conditional"


def test_dpdp_rules_phased_commencement():
    data = json.loads((REPO_ROOT / "data/frameworks/dpdp_rules_2025.json").read_text(encoding="utf-8"))
    assert data["notified_on"] == "2025-11-13"
    phases = data["phased_commencement"]
    assert phases["phase_a"]["effective_from"] == "2025-11-13"
    assert phases["phase_b"]["effective_from"] == "2026-11-13"
    assert phases["phase_c"]["effective_from"] == "2027-05-13"
    by_id = {c["id"]: c for c in data["controls"]}
    assert by_id["Rule-1"]["effective_from"] == "2025-11-13"
    assert by_id["Rule-4"]["effective_from"] == "2026-11-13"
    assert by_id["Rule-3"]["effective_from"] == "2027-05-13"
    assert by_id["Rule-6"]["effective_from"] == "2027-05-13"


def test_dpdp_generators_match_checked_in():
    for name, path in (
        ("dpdp_act_2023", REPO_ROOT / "data/frameworks/dpdp_act_2023.json"),
        ("dpdp_rules_2025", REPO_ROOT / "data/frameworks/dpdp_rules_2025.json"),
    ):
        generated = _load_builder(name)()
        checked = json.loads(path.read_text(encoding="utf-8"))
        assert generated == checked


def test_commencement_filter_respects_as_of():
    from app.compliance.effective_dates import filter_controls_in_force, framework_commencement_summary
    from app.gap_analysis import load_framework

    fw = load_framework("dpdp_rules_2025")
    early = framework_commencement_summary(fw, as_of="2025-11-13")
    assert early["in_force"] >= 1
    assert early["not_yet_in_force"] > 0
    mid = filter_controls_in_force(fw, as_of="2026-11-13")
    mid_ids = {c["id"] for c in mid}
    assert "Rule-4" in mid_ids
    assert "Rule-6" not in mid_ids
    late = filter_controls_in_force(fw, as_of="2027-05-13")
    assert any(c["id"] == "Rule-6" for c in late)


def test_aliases_resolve_dpdp():
    from app.gap_analysis import load_framework

    assert load_framework("dpdp")["id"] == "dpdp_rules_2025"
    assert load_framework("dpdp_act")["id"] == "dpdp_act_2023"
