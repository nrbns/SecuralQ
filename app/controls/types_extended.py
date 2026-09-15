"""First-class Requirement / Check / Observation / ControlResult contracts.

Extends the curated Control catalog without inventing framework text.
Observations feed automatic evidence (Sprint 3).
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Literal

ControlResultStatus = Literal["pass", "fail", "partial", "unknown", "error", "na"]


@dataclass
class Requirement:
    """Framework requirement that maps to one or more controls."""

    id: str
    framework_id: str
    title: str
    description: str = ""
    control_ids: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class Check:
    """Executable check bound to a control (telemetry / agent / human)."""

    id: str
    control_id: str
    framework_id: str = ""
    name: str = ""
    data_source: str = "agent"  # agent | scan | integration | human
    description: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class Observation:
    """One telemetry observation feeding a check."""

    id: str
    check_id: str
    control_id: str
    result: ControlResultStatus
    observed_at: float
    organization_id: str = ""
    asset_id: str = ""
    agent_id: str = ""
    event_id: str = ""
    source: str = "observed"
    detail: dict[str, Any] = field(default_factory=dict)
    expires_at: float | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ControlResult:
    """PASS/FAIL (etc.) for a control after evaluation."""

    control_id: str
    framework_id: str
    result: ControlResultStatus
    check_id: str = ""
    observation_id: str = ""
    evidence_id: str = ""
    previous_evidence_id: str = ""
    content_hash: str = ""
    evaluated_at: float | None = None
    detail: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
