"""Automatic evidence for control / check / remediation state changes (Sprint 3)."""

from __future__ import annotations

import hashlib
import json
from typing import Any

from app.db import new_id, now


def _content_hash(payload: dict[str, Any]) -> str:
    raw = json.dumps(payload, sort_keys=True, default=str)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def record_control_result_evidence(
    user_id: str,
    *,
    control_id: str,
    result: str,
    framework_id: str = "",
    check_id: str = "",
    observation_id: str = "",
    event_id: str = "",
    organization_id: str = "",
    asset_id: str = "",
    agent_id: str = "",
    previous_evidence_id: str = "",
    source: str = "observed",
    summary: str = "",
    detail: dict[str, Any] | None = None,
    expires_at: float | None = None,
) -> dict[str, Any] | None:
    """Record structured evidence for a control result; never raises."""
    try:
        from app.services.evidence import record_evidence

        st = (result or "unknown").strip().lower() or "unknown"
        obs_id = observation_id or new_id()
        summary_text = summary or f"Control {control_id} → {st.upper()}"
        body = {
            "event_id": event_id or "",
            "organization_id": organization_id or "",
            "asset_id": asset_id or "",
            "agent_id": agent_id or "",
            "control_id": control_id,
            "check_id": check_id or "",
            "observation_id": obs_id,
            "result": st,
            "timestamp": now(),
            "observed_at": now(),
            "expires_at": expires_at,
            "source": source,
            "previous_evidence_id": previous_evidence_id or "",
            "framework_id": framework_id or "",
            **(detail or {}),
        }
        body["hash"] = _content_hash(
            {
                "control_id": control_id,
                "check_id": check_id,
                "result": st,
                "agent_id": agent_id,
                "observation_id": obs_id,
            }
        )
        row = record_evidence(
            user_id,
            entity_type="control_result",
            entity_id=f"{framework_id}:{control_id}" if framework_id else control_id,
            source=source if source in {"declared", "derived", "inferred", "observed"} else "observed",
            summary=summary_text[:500],
            confidence=0.9 if st in {"pass", "fail"} else 0.6,
            detail=body,
            org_id=organization_id or None,
            expires_at=expires_at,
            created_by="control_evidence",
        )
        if isinstance(row, dict):
            row = dict(row)
            row["observation_id"] = obs_id
            row["content_hash"] = body["hash"]
        return row
    except Exception:
        return None


def record_remediation_verified_evidence(
    user_id: str,
    *,
    command_id: str,
    control_id: str = "",
    agent_id: str = "",
    result: str = "pass",
    previous_evidence_id: str = "",
    detail: dict[str, Any] | None = None,
) -> dict[str, Any] | None:
    """Evidence after remediation verification (control PASS path)."""
    return record_control_result_evidence(
        user_id,
        control_id=control_id or f"remediation:{command_id}",
        result=result,
        check_id="remediation_verify",
        agent_id=agent_id,
        previous_evidence_id=previous_evidence_id,
        summary=f"Remediation {command_id} verified → {(result or '').upper()}",
        detail={"command_id": command_id, **(detail or {})},
    )
