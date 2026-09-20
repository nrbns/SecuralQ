"""Evidence Spine — common language for documents, agents, controls, risk, tasks.

Architecture (do not rebuild SecuraIQ; unify what already exists):

  SERVER / AGENT / DOCUMENT
           ↓
     OBSERVATION | UPLOAD
           ↓
        EVIDENCE   (securaiq_evidence)
           ↓
   evidence_control_map  (many-to-many)
           ↓
     CONTROL RESULT
           ↓
   RISK / COMPLIANCE / TASK / SSE

Honesty: document evidence supports policy/governance claims; it does not
alone prove a live host control is PASS. Observed agent evidence is the
runtime signal. Both can map to the same control.
"""

from __future__ import annotations

from app.evidence_spine.evaluate import evaluate_control_from_evidence
from app.evidence_spine.ingest import (
    ingest_document_as_evidence,
    ingest_observation_as_evidence,
)
from app.evidence_spine.mapping import (
    ensure_evidence_spine_schema,
    link_evidence_to_control,
    list_controls_for_evidence,
    list_evidence_for_control,
    unlink_evidence_from_control,
)

__all__ = [
    "ensure_evidence_spine_schema",
    "ingest_observation_as_evidence",
    "ingest_document_as_evidence",
    "link_evidence_to_control",
    "unlink_evidence_from_control",
    "list_evidence_for_control",
    "list_controls_for_evidence",
    "evaluate_control_from_evidence",
]
