"""Configuration observe / drift foundations (Control & Configuration Engine Sprint 2).

Observes host settings from agent check-in telemetry, compares against seeded
baselines, and records light history — no auto-remediation of dangerous actions.
"""

from __future__ import annotations

from app.configuration.baselines import (
    BASELINE_CMMC_WINDOWS_WORKSTATION,
    get_baseline,
    list_baselines,
)
from app.configuration.drift import compare_to_baseline, list_drift_for_user
from app.configuration.observe import (
    ensure_observations_schema,
    extract_observed_config,
    list_observations,
    record_checkin_observations,
)

__all__ = [
    "BASELINE_CMMC_WINDOWS_WORKSTATION",
    "compare_to_baseline",
    "ensure_observations_schema",
    "extract_observed_config",
    "get_baseline",
    "list_baselines",
    "list_drift_for_user",
    "list_observations",
    "record_checkin_observations",
]
