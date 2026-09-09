"""RT-09 — Threat → Attack Path → Risk → Incident (realtime foundations).

Best-effort refresh of attack paths when a critical agent threat or
processor-created incident fires. Uses the real ``compute_attack_paths``
API — never invents path graphs or CVEs. Failures are swallowed so the
event processor never breaks publishers.
"""

from __future__ import annotations

import logging
from typing import Any

_log = logging.getLogger("securaiq.attack_path_realtime")


def _resolve_asset_id(*, agent_id: str = "", asset_id: str = "") -> str:
    aid = str(asset_id or "").strip()
    if aid:
        return aid
    ag = str(agent_id or "").strip()
    if not ag:
        return ""
    try:
        from app.agents import get_agent

        row = get_agent(ag)
        if row:
            return str(row.get("asset_id") or "").strip()
    except Exception as exc:
        _log.debug("asset lookup skipped: %s", exc)
    return ""


def refresh_attack_paths_for_threat(
    user_id: str,
    *,
    agent_id: str = "",
    asset_id: str = "",
    reason: str = "",
    org_id: str | None = None,
    incident_id: str = "",
) -> dict[str, Any] | None:
    """Recalculate org attack paths and publish a thin realtime summary.

    Returns the compute result (or a status dict) for tests; returns None
    when user_id is missing or compute fails. Publishes with
    ``_from_processor=True`` so the event processor does not recurse.
    """
    uid = str(user_id or "").strip()
    if not uid:
        return None

    resolved_asset = _resolve_asset_id(agent_id=agent_id, asset_id=asset_id)
    org = str(org_id or "").strip() or None
    path_count: int | None = None
    status = "recalculated"
    detail: dict[str, Any] = {}

    try:
        from app.services.attack_graph import compute_attack_paths

        result = compute_attack_paths(
            uid,
            org_id=org,
            max_depth=4,
            limit=50,
        )
        if isinstance(result, dict):
            path_count = int(result.get("total_paths") or 0)
            detail = {
                "total_paths": path_count,
                "paths_returned": len(result.get("paths") or []),
                "generated_at": result.get("generated_at"),
            }
        else:
            status = "recalculated_empty"
    except Exception as exc:
        _log.debug("compute_attack_paths skipped: %s", exc)
        status = "compute_failed"
        detail = {"error": type(exc).__name__}

    try:
        from app.realtime_bus import publish

        payload: dict[str, Any] = {
            "type": "attack_path",
            "user_id": uid,
            "status": status,
            "reason": reason or "event_processor:rt09",
            "agent_id": str(agent_id or "").strip() or None,
            "asset_id": resolved_asset or None,
            "incident_id": str(incident_id or "").strip() or None,
            "org_id": org,
            "path_count": path_count,
            "summary": (
                f"Attack paths recalculated · {path_count} path(s)"
                if path_count is not None
                else f"Attack path refresh · {status}"
            ),
            "_from_processor": True,
        }
        if detail:
            payload["detail"] = detail
        publish(**payload)
        # Thin risk hint for dashboards that listen on type=risk.
        if path_count is not None:
            publish(
                type="risk",
                user_id=uid,
                reason="attack_path_refresh",
                path_count=path_count,
                asset_id=resolved_asset or None,
                agent_id=str(agent_id or "").strip() or None,
                _from_processor=True,
            )
    except Exception as exc:
        _log.debug("attack_path publish skipped: %s", exc)

    return {
        "status": status,
        "path_count": path_count,
        "asset_id": resolved_asset or None,
        "user_id": uid,
        **detail,
    }
