"""Extract and persist observed host configuration from agent check-in payloads."""

from __future__ import annotations

import json
from typing import Any

from app.db import get_conn, new_id, now, row_to_dict

_SCHEMA_READY = False


def ensure_observations_schema() -> None:
    """Light history table for config observe/drift (idempotent)."""
    global _SCHEMA_READY
    if _SCHEMA_READY:
        return
    c = get_conn()
    c.execute(
        """
        CREATE TABLE IF NOT EXISTS securaiq_config_observations (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL DEFAULT 'local',
            org_id TEXT,
            asset_id TEXT NOT NULL DEFAULT '',
            agent_id TEXT NOT NULL DEFAULT '',
            key TEXT NOT NULL,
            value_json TEXT NOT NULL DEFAULT 'null',
            observed_at REAL NOT NULL,
            baseline_id TEXT NOT NULL DEFAULT '',
            source TEXT NOT NULL DEFAULT 'securaiq_agent'
        )
        """
    )
    c.execute(
        "CREATE INDEX IF NOT EXISTS idx_cfg_obs_user_key "
        "ON securaiq_config_observations(user_id, key, observed_at DESC)"
    )
    c.execute(
        "CREATE INDEX IF NOT EXISTS idx_cfg_obs_agent_key "
        "ON securaiq_config_observations(agent_id, key, observed_at DESC)"
    )
    c.commit()
    _SCHEMA_READY = True


def _truthy_enabled(val: Any) -> bool | None:
    if val is None:
        return None
    if isinstance(val, bool):
        return val
    if isinstance(val, (int, float)):
        return bool(val)
    s = str(val).strip().lower()
    if s in {"1", "true", "yes", "on", "enabled"}:
        return True
    if s in {"0", "false", "no", "off", "disabled"}:
        return False
    return None


def _ssh_permit_root_login(settings: dict[str, Any]) -> bool | None:
    """True when PermitRootLogin is effectively yes; False when no/prohibit-password."""
    if not isinstance(settings, dict):
        return None
    value = None
    for k, v in settings.items():
        if str(k).lower() == "permitrootlogin":
            value = str(v).strip().lower()
            break
    if value is None:
        return None
    if value in {"yes", "true", "1"}:
        return True
    if value in {"no", "prohibit-password", "without-password", "forced-commands-only", "false", "0"}:
        return False
    return None


def _defender_enabled(def_st: dict[str, Any]) -> bool | None:
    rt = _truthy_enabled(def_st.get("realtime_protection_enabled"))
    av = _truthy_enabled(def_st.get("antivirus_enabled"))
    top = _truthy_enabled(def_st.get("enabled"))
    if top is not None:
        return top
    flags = [f for f in (rt, av) if f is not None]
    if not flags:
        return None
    return all(flags)


def extract_observed_config(payload: dict[str, Any] | None) -> dict[str, Any]:
    """Normalize agent last_payload / check-in fields into baseline setting keys.

    Only includes keys when telemetry was collected with a decidable value.
    """
    payload = payload if isinstance(payload, dict) else {}
    out: dict[str, Any] = {}

    fw = payload.get("firewall_status") if isinstance(payload.get("firewall_status"), dict) else {}
    if fw.get("collected"):
        enabled = _truthy_enabled(fw.get("enabled"))
        if enabled is not None:
            out["firewall.enabled"] = {
                "value": enabled,
                "raw": {
                    "enabled": fw.get("enabled"),
                    "backend": fw.get("backend"),
                    "reason": (fw.get("reason") or "")[:200],
                },
            }

    def_st = payload.get("defender_status") if isinstance(payload.get("defender_status"), dict) else {}
    if def_st.get("collected"):
        enabled = _defender_enabled(def_st)
        if enabled is not None:
            out["defender.enabled"] = {
                "value": enabled,
                "raw": {
                    "enabled": enabled,
                    "antivirus_enabled": def_st.get("antivirus_enabled"),
                    "realtime_protection_enabled": def_st.get("realtime_protection_enabled"),
                    "reason": (def_st.get("reason") or "")[:200],
                },
            }

    ssh = payload.get("ssh_config") if isinstance(payload.get("ssh_config"), dict) else {}
    if ssh.get("collected"):
        settings = ssh.get("settings") if isinstance(ssh.get("settings"), dict) else {}
        permit = _ssh_permit_root_login(settings)
        if permit is not None:
            out["ssh.permit_root_login"] = {
                "value": permit,
                "raw": {
                    "PermitRootLogin": next(
                        (
                            str(v).strip().lower()
                            for k, v in settings.items()
                            if str(k).lower() == "permitrootlogin"
                        ),
                        None,
                    ),
                    "path": ssh.get("path"),
                    "reason": (ssh.get("reason") or "")[:200],
                },
            }

    return out


def _serialize_value(entry: dict[str, Any]) -> str:
    return json.dumps({"value": entry.get("value"), "raw": entry.get("raw") or {}}, sort_keys=True)


def _parse_value_json(raw: str | None) -> Any:
    try:
        return json.loads(raw or "null")
    except Exception:
        return None


def latest_observation(
    user_id: str,
    *,
    key: str,
    agent_id: str = "",
    asset_id: str = "",
) -> dict[str, Any] | None:
    ensure_observations_schema()
    c = get_conn()
    if agent_id:
        row = c.execute(
            """
            SELECT * FROM securaiq_config_observations
            WHERE user_id = ? AND agent_id = ? AND key = ?
            ORDER BY observed_at DESC LIMIT 1
            """,
            (user_id, agent_id, key),
        ).fetchone()
    elif asset_id:
        row = c.execute(
            """
            SELECT * FROM securaiq_config_observations
            WHERE user_id = ? AND asset_id = ? AND key = ?
            ORDER BY observed_at DESC LIMIT 1
            """,
            (user_id, asset_id, key),
        ).fetchone()
    else:
        row = c.execute(
            """
            SELECT * FROM securaiq_config_observations
            WHERE user_id = ? AND key = ?
            ORDER BY observed_at DESC LIMIT 1
            """,
            (user_id, key),
        ).fetchone()
    if not row:
        return None
    d = row_to_dict(row)
    d["value"] = _parse_value_json(d.pop("value_json", None))
    return d


def list_observations(
    user_id: str,
    *,
    org_id: str | None = None,
    key: str | None = None,
    agent_id: str | None = None,
    limit: int = 100,
) -> list[dict[str, Any]]:
    ensure_observations_schema()
    lim = max(1, min(int(limit or 100), 500))
    try:
        from app.tenancy import tenant_visibility_sql

        where, args = tenant_visibility_sql(user_id, org_id=org_id)
    except Exception:
        where, args = "user_id = ?", [user_id]
    if key:
        where += " AND key = ?"
        args.append(key)
    if agent_id:
        where += " AND agent_id = ?"
        args.append(agent_id)
    rows = get_conn().execute(
        f"""
        SELECT * FROM securaiq_config_observations
        WHERE {where}
        ORDER BY observed_at DESC
        LIMIT ?
        """,
        (*args, lim),
    ).fetchall()
    out: list[dict[str, Any]] = []
    for r in rows:
        d = row_to_dict(r)
        d["value"] = _parse_value_json(d.pop("value_json", None))
        out.append(d)
    return out


def record_observation(
    user_id: str,
    *,
    key: str,
    value_entry: dict[str, Any],
    agent_id: str = "",
    asset_id: str = "",
    org_id: str | None = None,
    baseline_id: str = "",
    observed_at: float | None = None,
) -> dict[str, Any]:
    """Insert one observation row; returns row + previous value if any."""
    ensure_observations_schema()
    from app.tenancy import primary_org_id

    oid = org_id or primary_org_id(user_id)
    prev = latest_observation(user_id, key=key, agent_id=agent_id, asset_id=asset_id)
    prev_val = None
    if prev and isinstance(prev.get("value"), dict):
        prev_val = prev["value"].get("value")
    elif prev is not None:
        prev_val = prev.get("value")

    ts = float(observed_at if observed_at is not None else now())
    oid_row = new_id()
    value_json = _serialize_value(value_entry)
    c = get_conn()
    c.execute(
        """
        INSERT INTO securaiq_config_observations
        (id, user_id, org_id, asset_id, agent_id, key, value_json, observed_at, baseline_id, source)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            oid_row,
            user_id,
            oid,
            asset_id or "",
            agent_id or "",
            key,
            value_json,
            ts,
            baseline_id or "",
            "securaiq_agent",
        ),
    )
    c.commit()
    current_val = value_entry.get("value")
    changed = prev is not None and prev_val != current_val
    return {
        "id": oid_row,
        "user_id": user_id,
        "org_id": oid,
        "asset_id": asset_id or "",
        "agent_id": agent_id or "",
        "key": key,
        "value": {"value": current_val, "raw": value_entry.get("raw") or {}},
        "observed_at": ts,
        "baseline_id": baseline_id or "",
        "previous_value": prev_val,
        "changed": changed,
        "had_previous": prev is not None,
    }


def record_checkin_observations(
    user_id: str,
    agent_id: str,
    payload: dict[str, Any],
    *,
    asset_id: str = "",
    org_id: str | None = None,
    baseline_id: str | None = None,
    publish_drift: bool = True,
) -> dict[str, Any]:
    """Record observations from a check-in; publish drift when a key value changes.

    Does not auto-remediate. Callers should still run host control evaluation.
    """
    from app.configuration.baselines import default_baseline_id
    from app.configuration.drift import drifts_vs_baseline, publish_drift_events

    bid = (baseline_id or default_baseline_id()).strip()
    observed = extract_observed_config(payload)
    recorded: list[dict[str, Any]] = []
    drift_events: list[dict[str, Any]] = []

    for key, entry in observed.items():
        row = record_observation(
            user_id,
            key=key,
            value_entry=entry,
            agent_id=agent_id,
            asset_id=asset_id,
            org_id=org_id,
            baseline_id=bid,
        )
        recorded.append(row)
        if row.get("changed") and publish_drift:
            # History drift (previous observation → current), plus baseline compare.
            baseline_drifts = drifts_vs_baseline(
                {key: entry},
                baseline_id=bid,
                previous_values={key: row.get("previous_value")},
                agent_id=agent_id,
                asset_id=asset_id,
            )
            for d in baseline_drifts:
                d["history_changed"] = True
                d["previous"] = row.get("previous_value")
                d["current"] = entry.get("value")
            # Always emit a history-change event even if baseline still matches
            # (e.g. firewall off→on both may be "in" or "out" of baseline depending
            # on expected — still useful as configuration.drift_detected).
            if not baseline_drifts:
                drift_events.append(
                    {
                        "key": key,
                        "expected": None,
                        "current": entry.get("value"),
                        "previous": row.get("previous_value"),
                        "status": "changed",
                        "history_changed": True,
                        "agent_id": agent_id,
                        "asset_id": asset_id or "",
                        "baseline_id": bid,
                        "control_ids": [],
                        "summary": f"{key} changed ({row.get('previous_value')!r} → {entry.get('value')!r})",
                    }
                )
            else:
                drift_events.extend(baseline_drifts)

    published = []
    if publish_drift and drift_events:
        published = publish_drift_events(
            user_id,
            drift_events,
            agent_id=agent_id,
            asset_id=asset_id,
            org_id=org_id,
        )

    return {
        "ok": True,
        "observed_keys": list(observed.keys()),
        "recorded": recorded,
        "drift_events": drift_events,
        "published": published,
        "baseline_id": bid,
    }
