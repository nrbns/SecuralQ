"""Canonical realtime event type registry — UI + workers share one vocabulary."""

from __future__ import annotations

from typing import Any

# Aggregates safe to stream to the browser at fleet scale
FLEET_AGGREGATE_EVENTS: tuple[str, ...] = (
    "fleet.health.changed",
    "fleet.risk.changed",
    "fleet.compliance.changed",
    "fleet.vulnerability.count.changed",
    "fleet.incident.count.changed",
)

# Per-agent / high-volume — process in backend; detail only when operator drills in
HIGH_VOLUME_EVENTS: tuple[str, ...] = (
    "agent.heartbeat",
    "agent.checkin",
    "telemetry",
    "software.inventory.updated",
)

PRIVACY_EVENTS: tuple[str, ...] = (
    "privacy.inventory.changed",
    "privacy.processor.changed",
    "privacy.request.changed",
    "privacy.retention.changed",
    "privacy.consent.changed",
)

CONTROL_PLANE_EVENTS: tuple[str, ...] = (
    "control.failed",
    "control.passed",
    "control.evaluating",
    "compliance.updated",
    "risk.changed",
    "remediation.created",
    "verification.pass",
    "verification.fail",
    "evidence.created",
)


def event_catalog() -> dict[str, Any]:
    return {
        "fleet_aggregates": list(FLEET_AGGREGATE_EVENTS),
        "high_volume": list(HIGH_VOLUME_EVENTS),
        "privacy": list(PRIVACY_EVENTS),
        "control_plane": list(CONTROL_PLANE_EVENTS),
        "ui_subscribe_hint": (
            "Subscribe the operator UI to fleet aggregates + control_plane. "
            "Do not fan every high_volume event to the browser."
        ),
    }


def is_fleet_aggregate(event_type: str) -> bool:
    return (event_type or "").strip() in FLEET_AGGREGATE_EVENTS


def is_high_volume(event_type: str) -> bool:
    et = (event_type or "").strip().lower()
    if et in HIGH_VOLUME_EVENTS:
        return True
    return et.startswith("agent.heartbeat") or et.endswith(".heartbeat")
