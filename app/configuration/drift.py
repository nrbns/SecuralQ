"""Baseline vs observed config drift + realtime publish helpers.

No auto-remediation. Drift is an operating-effectiveness signal only —
not a CMMC certification claim.
"""

from __future__ import annotations

from typing import Any

from app.configuration.baselines import default_baseline_id, get_baseline


def drifts_vs_baseline(
    observed: dict[str, Any],
    *,
    baseline_id: str | None = None,
    previous_values: dict[str, Any] | None = None,
    agent_id: str = "",
    asset_id: str = "",
) -> list[dict[str, Any]]:
    """Compare extracted observed entries to a baseline's expected values.

    ``observed`` maps setting key → ``{"value": ..., "raw": ...}``.
    """
    bid = (baseline_id or default_baseline_id()).strip()
    baseline = get_baseline(bid) or {}
    settings = baseline.get("settings") if isinstance(baseline.get("settings"), dict) else {}
    prev_map = previous_values if isinstance(previous_values, dict) else {}
    out: list[dict[str, Any]] = []

    for key, entry in (observed or {}).items():
        if not isinstance(entry, dict):
            continue
        spec = settings.get(key)
        if not isinstance(spec, dict):
            continue
        expected = spec.get("expected")
        current = entry.get("value")
        if expected is None or current is None:
            continue
        if current == expected:
            continue
        controls = list(spec.get("control_ids") or [])
        out.append(
            {
                "key": key,
                "expected": expected,
                "current": current,
                "previous": prev_map.get(key),
                "status": "fail",
                "history_changed": key in prev_map and prev_map.get(key) != current,
                "agent_id": agent_id,
                "asset_id": asset_id or "",
                "baseline_id": bid,
                "control_ids": controls,
                "summary": (
                    f"{key}: expected {expected!r}, observed {current!r}"
                    f" — {(spec.get('summary') or '').strip()}"
                ).strip(" —"),
                "severity": "high" if key.startswith("firewall") else "medium",
            }
        )
    return out


def compare_to_baseline(
    observed_flat: dict[str, Any],
    *,
    baseline_id: str | None = None,
) -> list[dict[str, Any]]:
    """Compare flat key→value map (or observe entries) to baseline."""
    normalized: dict[str, Any] = {}
    for k, v in (observed_flat or {}).items():
        if isinstance(v, dict) and "value" in v:
            normalized[k] = v
        else:
            normalized[k] = {"value": v, "raw": {}}
    return drifts_vs_baseline(normalized, baseline_id=baseline_id)


def list_drift_for_user(
    user_id: str,
    *,
    org_id: str | None = None,
    baseline_id: str | None = None,
    limit: int = 50,
) -> list[dict[str, Any]]:
    """Latest observation per (agent_id, key) that fails the baseline."""
    from app.configuration.observe import list_observations

    bid = (baseline_id or default_baseline_id()).strip()
    baseline = get_baseline(bid) or {}
    settings = baseline.get("settings") if isinstance(baseline.get("settings"), dict) else {}
    rows = list_observations(user_id, org_id=org_id, limit=max(limit * 4, 100))
    latest: dict[tuple[str, str], dict[str, Any]] = {}
    for row in rows:
        key = str(row.get("key") or "")
        aid = str(row.get("agent_id") or row.get("asset_id") or "")
        ck = (aid, key)
        if ck in latest:
            continue
        latest[ck] = row

    drifts: list[dict[str, Any]] = []
    for (_aid, key), row in latest.items():
        spec = settings.get(key)
        if not isinstance(spec, dict):
            continue
        expected = spec.get("expected")
        val_wrap = row.get("value") if isinstance(row.get("value"), dict) else {}
        current = val_wrap.get("value") if val_wrap else None
        if expected is None or current is None or current == expected:
            continue
        drifts.append(
            {
                "key": key,
                "expected": expected,
                "current": current,
                "previous": None,
                "status": "fail",
                "agent_id": row.get("agent_id") or "",
                "asset_id": row.get("asset_id") or "",
                "baseline_id": bid,
                "control_ids": list(spec.get("control_ids") or []),
                "summary": f"{key}: expected {expected!r}, observed {current!r}",
                "observed_at": row.get("observed_at"),
                "severity": "high" if key.startswith("firewall") else "medium",
            }
        )
        if len(drifts) >= limit:
            break
    return drifts


def publish_drift_events(
    user_id: str,
    drift_events: list[dict[str, Any]],
    *,
    agent_id: str = "",
    asset_id: str = "",
    org_id: str | None = None,
) -> list[dict[str, Any]]:
    """Publish configuration.drift_detected (+ flat compliance/configuration)."""
    published: list[dict[str, Any]] = []
    if not drift_events:
        return published
    try:
        from app.realtime_bus import publish
        from app.tenancy import primary_org_id

        oid = org_id or primary_org_id(user_id)
    except Exception:
        return published

    for d in drift_events:
        try:
            payload = {
                "type": "configuration",
                "event_type": "configuration.drift_detected",
                "user_id": user_id,
                "org_id": oid,
                "organization_id": oid,
                "agent_id": d.get("agent_id") or agent_id,
                "asset_id": d.get("asset_id") or asset_id,
                "severity": d.get("severity") or "medium",
                "source": "securaiq_configuration",
                "key": d.get("key"),
                "expected": d.get("expected"),
                "current": d.get("current"),
                "previous": d.get("previous"),
                "status": d.get("status") or "fail",
                "baseline_id": d.get("baseline_id"),
                "control_ids": d.get("control_ids") or [],
                "summary": d.get("summary") or "",
                "also_types": ["compliance"],
            }
            publish(**payload)
            # Dual flat compliance for existing LIVE_TYPES
            publish(
                type="compliance",
                event_type="configuration.drift_detected",
                user_id=user_id,
                org_id=oid,
                organization_id=oid,
                agent_id=payload["agent_id"],
                asset_id=payload["asset_id"],
                severity=payload["severity"],
                status="drift",
                key=d.get("key"),
                summary=d.get("summary") or "",
            )
            published.append(payload)
        except Exception:
            continue
    return published
