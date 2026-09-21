"""CMMC assessment layer — objectives, Examine/Interview/Test, POA&M policy, SPRS prep.

Does **not** rebuild Evidence Spine. Reuses securaiq_evidence, vault, live SSP,
cmmc_scoping, affirmations, and gap_remediations.

Honesty:
  - Not a C3PAO assessment, SPRS submission, or certification claim.
  - Assessment objective titles seeded as Examine/Interview/Test scaffolds —
    not verbatim DoD Assessment Guide determination statements.
  - Program status notes come from the catalog ``status_note`` (versioned).
"""

from __future__ import annotations

from app.cmmc.cui_program import list_cui_programs, upsert_cui_program
from app.cmmc.methods import list_method_evidence, record_method_evidence
from app.cmmc.objectives import (
    get_control_assessment,
    list_objectives,
    seed_objectives_for_framework,
    set_objective_status,
)
from app.cmmc.poam_items import close_poam_item, list_poam_items, open_poam_item
from app.cmmc.poam_policy import poam_policy_for_control, poam_policy_for_framework
from app.cmmc.schema import ensure_cmmc_assessment_schema
from app.cmmc.sprs_prep import sprs_preparation_snapshot
from app.cmmc.versioning import framework_version_info

__all__ = [
    "ensure_cmmc_assessment_schema",
    "seed_objectives_for_framework",
    "list_objectives",
    "set_objective_status",
    "get_control_assessment",
    "record_method_evidence",
    "list_method_evidence",
    "poam_policy_for_framework",
    "poam_policy_for_control",
    "open_poam_item",
    "close_poam_item",
    "list_poam_items",
    "sprs_preparation_snapshot",
    "framework_version_info",
    "upsert_cui_program",
    "list_cui_programs",
]
