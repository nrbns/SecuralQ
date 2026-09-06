"""Integrity checks for data/frameworks/canonical_controls.json -- the
cross-framework control registry (task: 'connect security -> risk ->
compliance -> remediation -> verification' rather than 14 disconnected
checklists).

Every canonical control maps to real control IDs that were individually
verified (by reading each framework's actual control title/keywords) to
genuinely cover that concept -- never padded to inflate framework coverage.
These tests lock in that every referenced (framework_id, control_id) pair
actually exists in that framework's real catalog, so a future edit can't
silently introduce a typo'd or fabricated cross-reference.
"""

from __future__ import annotations

import json
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
FRAMEWORKS_DIR = REPO_ROOT / "data" / "frameworks"


def _load_registry() -> dict:
    return json.loads((FRAMEWORKS_DIR / "canonical_controls.json").read_text(encoding="utf-8"))


def _load_all_catalogs() -> dict[str, set[str]]:
    catalogs = {}
    for path in FRAMEWORKS_DIR.glob("*.json"):
        data = json.loads(path.read_text(encoding="utf-8"))
        if data["id"] == "canonical_controls":
            continue
        catalogs[data["id"]] = {c["id"] for c in data["controls"]}
    return catalogs


def test_registry_has_unique_canonical_ids():
    reg = _load_registry()
    ids = [c["id"] for c in reg["canonical_controls"]]
    assert len(ids) >= 20
    assert len(set(ids)) == len(ids), "duplicate canonical control ids"


def test_every_canonical_control_has_required_fields():
    reg = _load_registry()
    for c in reg["canonical_controls"]:
        assert c.get("name"), f"{c.get('id')} has no name"
        assert c.get("description"), f"{c.get('id')} has no description"
        assert c.get("category"), f"{c.get('id')} has no category"
        assert c.get("frameworks"), f"{c.get('id')} maps to no frameworks at all"


def test_every_mapped_control_id_actually_exists():
    """The core integrity guarantee: no canonical control may reference a
    (framework, control_id) pair that isn't real. This is what stops the
    registry from silently drifting into fabricated cross-framework claims."""
    reg = _load_registry()
    catalogs = _load_all_catalogs()

    bad_frameworks = []
    bad_controls = []
    for cc in reg["canonical_controls"]:
        for fw_id, ctrl_ids in cc["frameworks"].items():
            if fw_id not in catalogs:
                bad_frameworks.append((cc["id"], fw_id))
                continue
            for cid in ctrl_ids:
                if cid not in catalogs[fw_id]:
                    bad_controls.append((cc["id"], fw_id, cid))

    assert not bad_frameworks, f"canonical controls reference unknown frameworks: {bad_frameworks}"
    assert not bad_controls, f"canonical controls reference nonexistent control ids: {bad_controls}"


def test_every_framework_has_at_least_one_canonical_mapping():
    """All 14 real framework catalogs should be reachable through the
    registry -- if a framework has zero canonical mappings, the registry
    isn't actually cross-framework for it yet."""
    reg = _load_registry()
    catalogs = _load_all_catalogs()

    covered: set[str] = set()
    for cc in reg["canonical_controls"]:
        covered.update(cc["frameworks"].keys())

    missing = set(catalogs) - covered
    assert not missing, f"frameworks with zero canonical control coverage: {missing}"


def test_high_value_canonical_controls_present():
    """Sanity check on the fixture -- a few universally-expected canonical
    controls must exist by these exact ids (other code will reference them)."""
    reg = _load_registry()
    ids = {c["id"] for c in reg["canonical_controls"]}
    for expected in (
        "mfa",
        "encryption_at_rest",
        "encryption_in_transit",
        "vulnerability_management",
        "backup_recovery",
        "incident_response_plan",
        "access_control_least_privilege",
    ):
        assert expected in ids, f"expected canonical control {expected!r} missing"


def test_mfa_covers_at_least_ten_frameworks():
    """MFA is the flagship example in the product pitch ('implement once,
    satisfied across many frameworks') -- it should actually demonstrate
    that breadth, not just theoretically support it."""
    reg = _load_registry()
    mfa = next(c for c in reg["canonical_controls"] if c["id"] == "mfa")
    assert len(mfa["frameworks"]) >= 10
