"""Compare observed host configuration against seeded baselines."""

from __future__ import annotations

from typing import Any

from app.configuration.baselines import default_baseline_id, get_baseline
from app.configuration.observe import extract_observed_config, list_observations


def _control_id_labels(control_ids: list[Any]) -> list[str]:
    out: list[str] = []
    for c in control_ids or []:
        if isinstance(c, dict):
            fid = c.get("framework_id") or ""
            cid = c.get("control_id") or ""
            if fid and cid:
                out.append(f"{fid}:{cid}")
            elif cid:
                out.append(str(cid))
        elif c:
            out.append(str(c))
    return out


def _as_observed_map(payload_or_observed: dict[str, Any] | None) -> tuple[dict[str, Any], str]:
    """Accept raw agent payload or extract_observed_config output."""
    raw = payload_or_observed if isinstance(payload_or_observed, dict) else {}
    # Already-normalized map: keys like firewall.enabled → {value, raw}
    if any(isinstance(v, dict) and "value" in v for v in raw.values()):
        return raw, str(raw.get("os") or "") if isinstance(raw.get("os"), str) else ""
    return extract_observed_config(raw), str(raw.get("os") or "")


def drifts_vs_baseline(
    observed: dict[str, Any],
    *,
    baseline_id: str | None = None,
    previous_values: dict[str, Any] | None = None,
    agent_id: str = "",
    asset_id: str = "",
    os_name: str = "",
) -> list[dict[str, Any]]:
    """Return drift events where observed value != baseline expected.

    ``observed`` is the map from ``extract_observed_config`` (key → {value, raw}).
    When ``previous_values`` is provided, each event includes previous/current.
    Status is ``fail`` when out of baseline (UI / tests); ``changed`` is reserved
    for history-only flips that still match the baseline.
    """
    bid = (baseline_id or default_baseline_id()).strip()
    baseline = get_baseline(bid)
    if not baseline:
        return []
    settings = baseline.get("settings") or {}
    prev_map = previous_values or {}
    os_l = (os_name or "").lower()
    events: list[dict[str, Any]] = []

    for key, spec in settings.items():
        if not isinstance(spec, dict):
            continue
        scope = (spec.get("os_scope") or "any").lower()
        if scope == "windows" and os_l and "win" not in os_l:
            continue
        if scope == "linux" and os_l and (
            "linux" not in os_l and "ubuntu" not in os_l and "debian" not in os_l
        ):
            if "win" in os_l or "darwin" in os_l or "mac" in os_l:
                continue

        entry = observed.get(key)
        if not isinstance(entry, dict) or "value" not in entry:
            continue
        current = entry.get("value")
        expected = spec.get("expected")
        if current == expected:
            continue
        ctrl = list(spec.get("control_ids") or [])
        events.append(
            {
                "key": key,
                "expected": expected,
                "current": current,
                "previous": prev_map.get(key),
                "status": "fail",
                "severity": "high" if key in {"defender.enabled", "ssh.permit_root_login"} else "medium",
                "history_changed": key in prev_map and prev_map.get(key) != current,
                "agent_id": agent_id,
                "asset_id": asset_id or "",
                "baseline_id": bid,
                "control_ids": _control_id_labels(ctrl),
                "control_refs": ctrl,
                "os_scope": scope,
                "summary": (
                    f"{key} drift vs baseline {bid}: expected={expected!r}, "
                    f"current={current!r}"
                    + (f", previous={prev_map.get(key)!r}" if key in prev_map else "")
                ),
            }
        )
    return events


def compare_to_baseline(
    payload_or_observed: dict[str, Any] | None,
    *,
    baseline_id: str | None = None,
    previous_values: dict[str, Any] | None = None,
    agent_id: str = "",
    asset_id: str = "",
) -> list[dict[str, Any]]:
    """Compare payload (or extract_observed_config map) to baseline; return fail list."""
    observed, os_guess = _as_observed_map(payload_or_observed)
    os_name = os_guess
    if isinstance(payload_or_observed, dict) and payload_or_observed.get("os"):
        os_name = str(payload_or_observed.get("os") or os_name)
    return drifts_vs_baseline(
        observed,
        baseline_id=baseline_id,
        previous_values=previous_values,
        agent_id=agent_id,
        asset_id=asset_id,
        os_name=os_name,
    )


def publish_drift_events(
    user_id: str,
    drift_events: list[dict[str, Any]],
    *,
    agent_id: str = "",
    asset_id: str = "",
    org_id: str | None = None,
) -> list[dict[str, Any]]:
    """Publish configuration.drift_detected plus flat compliance/configuration types.

    No auto-remediation. Never raises to callers.
    """
    published: list[dict[str, Any]] = []
    if not drift_events:
        return published
    try:
        from app.realtime_bus import publish
        from app.tenancy import primary_org_id

        oid = org_id or primary_org_id(user_id)
    except Exception:
        return published

    for ev in drift_events:
        key = ev.get("key") or ""
        summary = ev.get("summary") or f"Configuration drift: {key}"
        base_kwargs = dict(
            user_id=user_id,
            org_id=oid,
            agent_id=agent_id or ev.get("agent_id") or "",
            asset_id=asset_id or ev.get("asset_id") or "",
            key=key,
            expected=ev.get("expected"),
            current=ev.get("current"),
            previous=ev.get("previous"),
            baseline_id=ev.get("baseline_id") or "",
            control_ids=ev.get("control_ids") or [],
            summary=summary,
            reason="configuration_drift",
            source="securaiq_agent",
            _from_processor=True,
        )
        try:
            publish(
                event_type="configuration.drift_detected",
                severity=ev.get("severity") or "medium",
                title=f"Config drift: {key}",
                **base_kwargs,
            )
            published.append({"type": "configuration.drift_detected", "key": key})
        except Exception:
            pass
        for flat in ("compliance", "configuration"):
            try:
                publish(
                    type=flat,
                    severity=ev.get("severity") or "medium",
                    title=f"Config drift: {key}",
                    status=ev.get("status") or "fail",
                    **base_kwargs,
                )
                published.append({"type": flat, "key": key})
            except Exception:
                pass
    return published


def list_drift_for_user(
    user_id: str,
    *,
    baseline_id: str | None = None,
    org_id: str | None = None,
    limit: int = 50,
) -> list[dict[str, Any]]:
    """User-scoped list of current baseline failures (from agent last_payload).

    Shape matches Control Center UI: flat list with key/expected/current/agent_id.
    """
    bid = (baseline_id or default_baseline_id()).strip()
    drifts: list[dict[str, Any]] = []

    try:
        from app.agents import list_agents

        agents = list_agents(user_id, org_id=org_id, limit=200)
    except Exception:
        agents = []

    for agent in agents:
        payload = agent.get("last_payload") if isinstance(agent.get("last_payload"), dict) else {}
        aid = str(agent.get("id") or "")
        asset = str(agent.get("asset_id") or "")
        for d in compare_to_baseline(payload, baseline_id=bid, agent_id=aid, asset_id=asset):
            d["hostname"] = agent.get("hostname") or agent.get("name") or ""
            drifts.append(d)
            if len(drifts) >= limit:
                return drifts

    # Supplement with recent history flips that are still out of baseline.
    if len(drifts) < limit:
        try:
            obs = list_observations(user_id, org_id=org_id, limit=max(20, limit * 4))
            by_ak: dict[tuple[str, str], list[dict[str, Any]]] = {}
            for row in obs:
                ak = (str(row.get("agent_id") or ""), str(row.get("key") or ""))
                by_ak.setdefault(ak, []).append(row)
            seen = {(d.get("agent_id"), d.get("key")) for d in drifts}
            for (agent_id, key), rows in by_ak.items():
                if len(rows) < 2 or (agent_id, key) in seen:
                    continue
                newer = rows[0]
                older = rows[1]
                nv = newer.get("value")
                ov = older.get("value")
                nval = nv.get("value") if isinstance(nv, dict) else nv
                oval = ov.get("value") if isinstance(ov, dict) else ov
                if nval == oval:
                    continue
                # Only surface if current still fails baseline
                fake_obs = {key: {"value": nval, "raw": {}}}
                fails = drifts_vs_baseline(
                    fake_obs,
                    baseline_id=bid,
                    previous_values={key: oval},
                    agent_id=agent_id,
                    asset_id=str(newer.get("asset_id") or ""),
                )
                for d in fails:
                    d["previous"] = oval
                    d["history_changed"] = True
                    drifts.append(d)
                    if len(drifts) >= limit:
                        return drifts
        except Exception:
            pass

    return drifts[:limit]
