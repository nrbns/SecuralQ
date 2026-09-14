"""Engagement CRUD + structured scope for tool policy."""

from __future__ import annotations

from typing import Any

from app.workspace import (
    ENGAGEMENT_STATUSES,
    ENGAGEMENT_TRANSITIONS,
    create_engagement as _create,
    get_engagement as _get,
    list_engagements as _list,
    transition_engagement_status as _transition,
    update_engagement as _update,
)


def create_engagement(
    user_id: str,
    name: str,
    scope_notes: str = "",
    status: str = "active",
    scope_json: str | list | None = None,
    cmmc_enclave_architecture: str = "",
) -> dict[str, Any]:
    return _create(
        user_id, name, scope_notes, status, scope_json=scope_json,
        cmmc_enclave_architecture=cmmc_enclave_architecture,
    )


def list_engagements(user_id: str, status: str | None = None) -> list[dict[str, Any]]:
    return _list(user_id, status)


def get_engagement(user_id: str, engagement_id: str) -> dict[str, Any] | None:
    return _get(user_id, engagement_id)


def update_engagement(
    user_id: str,
    engagement_id: str,
    name: str | None = None,
    scope_notes: str | None = None,
    scope_json: str | list | None = None,
    cmmc_enclave_architecture: str | None = None,
) -> dict[str, Any] | None:
    return _update(
        user_id, engagement_id, name, scope_notes, scope_json=scope_json,
        cmmc_enclave_architecture=cmmc_enclave_architecture,
    )


def transition_engagement_status(user_id: str, engagement_id: str, new_status: str) -> dict[str, Any]:
    return _transition(user_id, engagement_id, new_status)


__all__ = [
    "ENGAGEMENT_STATUSES",
    "ENGAGEMENT_TRANSITIONS",
    "create_engagement",
    "get_engagement",
    "list_engagements",
    "transition_engagement_status",
    "update_engagement",
]
