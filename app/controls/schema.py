"""Canonical types for the Control & Configuration Engine (Sprint 1).

These are structural contracts only — they do not invent control text.
Control titles/descriptions come from ``data/frameworks/*.json``.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any, Literal


Verifiability = Literal["machine", "partial", "human", "unknown"]


class VerifiabilityLevel(str, Enum):
    """How a control's operating effectiveness can be assessed today."""

    MACHINE = "machine"  # curated live test(s) exist and are telemetry-driven
    PARTIAL = "partial"  # live test exists but is inherently incomplete / soft
    HUMAN = "human"  # no live test — requires human evidence / assessment
    UNKNOWN = "unknown"  # cannot classify (e.g. framework load failure)


@dataclass
class Objective:
    """Optional assessment objective under a control (future sprints)."""

    id: str
    title: str = ""
    description: str = ""


@dataclass
class ControlTest:
    """Named live test bound to a control via explicit map only."""

    name: str
    verifiability: Verifiability = "unknown"
    description: str = ""


@dataclass
class TestResult:
    """Outcome of one live test run for a control."""

    test: str
    status: str  # pass | fail | partial | unknown | na
    summary: str = ""
    detail: dict[str, Any] = field(default_factory=dict)
    tested_at: float | None = None
    framework_id: str = ""
    control_id: str = ""
    why_failing: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class Control:
    """Normalized control from a framework catalog JSON row."""

    id: str
    title: str
    framework_id: str
    domain: str = ""
    description: str = ""
    keywords: list[str] = field(default_factory=list)
    objectives: list[Objective] = field(default_factory=list)
    tests: list[ControlTest] = field(default_factory=list)
    verifiability: Verifiability = "unknown"
    raw: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        return d


@dataclass
class Framework:
    """Framework catalog header + control count."""

    id: str
    name: str
    version: str = ""
    description: str = ""
    control_count: int = 0

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
