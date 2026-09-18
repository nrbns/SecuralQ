"""Lifecycle audit trail for remediation / agent commands (Phase A).

Every RECOMMENDED → … → VERIFIED (and failure) transition should leave an
immutable audit row. Bus publishes already exist; this module centralizes
the durable audit write so UI/SSE and DB stay aligned.
"""

from __future__ import annotations

from typing import Any


def audit_lifecycle_transition(
    user_id: str,
    *,
    agent_id: str,
    command_id: str,
    lifecycle: str,
    status: str = "",
    verification_status: str = "",
    kind: str = "",
    extra: dict[str, Any] | None = None,
) -> None:
    """Best-effort audit write — never raises."""
    try:
        from app.db import audit

        payload: dict[str, Any] = {
            "agent_id": agent_id,
            "command_id": command_id,
            "lifecycle": lifecycle,
            "status": status,
            "verification_status": verification_status or None,
            "kind": kind or None,
            **(extra or {}),
        }
        audit(
            f"lifecycle.{(lifecycle or 'unknown').lower()}",
            user_id or "system",
            {k: v for k, v in payload.items() if v is not None},
        )
    except Exception:
        pass
