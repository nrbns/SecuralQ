"""REALTIME v1 — unified event contract (Task A).

Canonical envelope fields, event_type registry, and validation. Publish-path
normalization lives in ``app.realtime_events``; this module is the schema source
of truth.

Task B (Redis Streams durable queue) and Task C (event processor) live in
``app.realtime_bus`` / ``app.event_processor`` — this module is the schema
source of truth only.
"""

from __future__ import annotations

from typing import Any

# Contract version stamped on every normalized publish.
EVENT_VERSION = 1

# Envelope keys (plus dual-write aliases). Domain fields stay outside / in ``data``.
ENVELOPE_FIELDS: frozenset[str] = frozenset(
    {
        "event_id",
        "organization_id",
        "org_id",  # existing tenancy alias — dual-written with organization_id
        "agent_id",
        "asset_id",
        "event_type",
        "type",  # SSE / UI backward-compat alias for event_type
        "event_version",
        "sequence",
        "seq",  # legacy millis sequence — dual-written with sequence
        "generated_at",
        "received_at",
        "severity",
        "source",
        "environment",
        "data",
        "evidence_ids",
        # transport / legacy (not part of the public contract, preserved on wire)
        "ts",
        "user_id",
        "_pid",
        "also",
    }
)

SEVERITIES: frozenset[str] = frozenset(
    {"critical", "high", "medium", "low", "info", "unknown", ""}
)

# Known domain event types used by publish sites + dashboard REALTIME_LIVE_TYPES.
# Unknown types are allowed on the wire (advisory registry) so new producers
# are not blocked; strict validation can still flag them.
# Dotted aliases (e.g. ``threat.created``, ``scan.started``) map to existing
# flat semantics for advisory typing; dual-write still uses flat ``type`` for UI.
EVENT_TYPE_REGISTRY: frozenset[str] = frozenset(
    {
        "agent",
        "agent.connected",
        "agent.disconnected",
        "agent.health_changed",
        "agent_command",
        "agent_threat",
        "archive",
        "archive_delete",
        "asset",
        "attack_path",
        "campaign",
        "cloud",
        "combo",
        "compliance",
        "compliance.control_failed",
        "compliance.control_passed",
        "evidence",
        "evidence.created",
        "gap",
        "hardening",
        "hunt",
        "incident",
        "incident.created",
        "incident.updated",
        "intel",
        "intel_watch",
        "inventory",
        "job",
        "notification",
        "playbook",
        "remediation",
        "remediation.completed",
        "remediation.created",
        "risk",
        "risk.changed",
        "scan",
        "scan.completed",
        "scan.progress",
        "scan.started",
        "scan_clear",
        "siem",
        "software_inventory",
        "software.inventory.updated",
        "software.vulnerability.changed",
        "thehive",
        "threat",
        "threat.created",
        "threat.updated",
        "tool",
        "tool_progress",
        "verification",
        "verification.completed",
        "vuln",
        "vuln_batch",
        "xdr",
        "xdr_batch",
    }
)

# Fields that must be present after normalize / for a "good" contract event.
REQUIRED_AFTER_NORMALIZE: tuple[str, ...] = (
    "event_id",
    "event_type",
    "type",
    "event_version",
    "sequence",
    "generated_at",
    "received_at",
    "data",
    "evidence_ids",
)


def resolve_event_type(payload: dict[str, Any]) -> str:
    """Prefer ``event_type``, fall back to legacy ``type``."""
    et = payload.get("event_type")
    if et is None or str(et).strip() == "":
        et = payload.get("type")
    return str(et or "").strip()


def is_registered_event_type(event_type: str) -> bool:
    return event_type in EVENT_TYPE_REGISTRY


def validate_event(
    payload: dict[str, Any] | None,
    *,
    strict_registry: bool = False,
    require_normalized: bool = False,
) -> tuple[bool, list[str]]:
    """Validate an event dict against the REALTIME v1 contract.

    Returns ``(ok, errors)``. Does not mutate ``payload``.

    - Always requires a non-empty ``event_type`` or legacy ``type``.
    - ``severity``, when set, must be in ``SEVERITIES``.
    - ``evidence_ids``, when set, must be a list.
    - ``data``, when set, must be a dict.
    - ``strict_registry``: unknown event_type is an error.
    - ``require_normalized``: also require post-normalize envelope fields.
    """
    errors: list[str] = []
    if not isinstance(payload, dict):
        return False, ["payload must be a dict"]

    event_type = resolve_event_type(payload)
    if not event_type:
        errors.append("missing event_type (or type)")
    elif strict_registry and not is_registered_event_type(event_type):
        errors.append(f"unknown event_type: {event_type!r}")

    sev = payload.get("severity")
    if sev is not None and str(sev).strip().lower() not in SEVERITIES:
        errors.append(f"invalid severity: {sev!r}")

    if "evidence_ids" in payload and payload["evidence_ids"] is not None:
        if not isinstance(payload["evidence_ids"], list):
            errors.append("evidence_ids must be a list")

    if "data" in payload and payload["data"] is not None:
        if not isinstance(payload["data"], dict):
            errors.append("data must be a dict")

    if "event_version" in payload and payload["event_version"] is not None:
        try:
            ver = int(payload["event_version"])
            if ver < 1:
                errors.append("event_version must be >= 1")
        except (TypeError, ValueError):
            errors.append("event_version must be an int")

    if require_normalized:
        for key in REQUIRED_AFTER_NORMALIZE:
            if key not in payload or payload[key] is None or payload[key] == "":
                errors.append(f"missing required field after normalize: {key}")

    return (len(errors) == 0), errors


def domain_payload(payload: dict[str, Any]) -> dict[str, Any]:
    """Return non-envelope keys (the domain ``data`` bag)."""
    return {k: v for k, v in payload.items() if k not in ENVELOPE_FIELDS}
