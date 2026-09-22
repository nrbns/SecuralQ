"""Refresh policy engine — freshness-driven intervals, not one global hammer.

Uses Evidence Spine freshness policies. Explicitly excludes deep scanners
(Nmap/Nuclei/ZAP) from the posture cycle.
"""

from __future__ import annotations

import os
from typing import Any

from app.evidence_spine.freshness import DEFAULT_FRESHNESS, list_freshness_policies

# Allowed global cadence options (seconds)
ALLOWED_INTERVALS = {
    5 * 60,
    15 * 60,
    30 * 60,
    60 * 60,
    4 * 3600,
    12 * 3600,
    24 * 3600,
}

DEEP_SCAN_KINDS = frozenset(
    {
        "nmap",
        "nuclei",
        "zap",
        "dast",
        "network_discovery",
        "full_vuln_scan",
        "cloud_deep_assessment",
    }
)

LAYER_A_REALTIME = (
    "agent_telemetry",
    "firewall",
    "defender",
    "fim",
    "security_logs",
    "processes",
    "critical_configuration",
    "threat_events",
)

LAYER_B_POSTURE = (
    "asset_health",
    "control_evaluation",
    "evidence_freshness",
    "vulnerability_state",
    "risk",
    "compliance",
    "task_state",
    "notifications",
)

LAYER_C_DEEP = tuple(sorted(DEEP_SCAN_KINDS))


def default_interval_sec() -> int:
    raw = (os.environ.get("SECURAIQ_POSTURE_REFRESH_SEC") or "").strip()
    if raw.isdigit():
        return max(60, int(raw))
    return 30 * 60


def default_jitter_sec() -> int:
    raw = (os.environ.get("SECURAIQ_POSTURE_JITTER_SEC") or "").strip()
    if raw.isdigit():
        return max(0, int(raw))
    return 60


def get_org_interval(user_id: str) -> dict[str, Any]:
    from app.db import get_conn
    from app.posture.schema import ensure_posture_schema

    ensure_posture_schema()
    row = get_conn().execute(
        "SELECT * FROM posture_org_settings WHERE user_id = ?", (user_id,)
    ).fetchone()
    if not row:
        return {
            "interval_sec": default_interval_sec(),
            "jitter_sec": default_jitter_sec(),
            "enabled": True,
            "deep_scan_excluded": True,
            "source": "global_default",
        }
    return {
        "interval_sec": int(row["interval_sec"] or default_interval_sec()),
        "jitter_sec": int(row["jitter_sec"] or default_jitter_sec()),
        "enabled": bool(row["enabled"]),
        "deep_scan_excluded": bool(row["deep_scan_excluded"]),
        "source": "org_settings",
    }


def set_org_interval(
    user_id: str,
    *,
    interval_sec: int,
    jitter_sec: int | None = None,
    enabled: bool = True,
    org_id: str | None = None,
) -> dict[str, Any]:
    from app.db import get_conn, now
    from app.posture.schema import ensure_posture_schema
    from app.tenancy import primary_org_id

    ensure_posture_schema()
    iv = int(interval_sec)
    if iv not in ALLOWED_INTERVALS and iv < 60:
        raise ValueError(f"interval_sec must be one of {sorted(ALLOWED_INTERVALS)} or >= 60 custom")
    jit = default_jitter_sec() if jitter_sec is None else max(0, int(jitter_sec))
    oid = org_id or primary_org_id(user_id)
    t = now()
    get_conn().execute(
        """
        INSERT INTO posture_org_settings
        (user_id, org_id, interval_sec, jitter_sec, enabled, deep_scan_excluded, meta_json, updated_at)
        VALUES (?, ?, ?, ?, ?, 1, '{}', ?)
        ON CONFLICT(user_id) DO UPDATE SET
            interval_sec = excluded.interval_sec,
            jitter_sec = excluded.jitter_sec,
            enabled = excluded.enabled,
            org_id = COALESCE(excluded.org_id, org_id),
            updated_at = excluded.updated_at
        """,
        (user_id, oid, iv, jit, 1 if enabled else 0, t),
    )
    get_conn().commit()
    return get_org_interval(user_id)


def list_refresh_policies() -> list[dict[str, Any]]:
    """Policies for Layer B posture — derived from Evidence Spine freshness."""
    out = []
    for p in list_freshness_policies():
        out.append(
            {
                "id": p["id"],
                "label": p["label"],
                "layer": "B_posture",
                "freshness_sec": p["stale_after_sec"],
                "collection_interval_sec": p["collection_interval_sec"],
                "scan_type": "agent_or_inventory",
                "priority": _priority_for(p["id"], p["stale_after_sec"]),
                "includes_deep_scan": False,
            }
        )
    for kind in LAYER_C_DEEP:
        out.append(
            {
                "id": kind,
                "label": kind.replace("_", " ").title(),
                "layer": "C_deep_scan",
                "freshness_sec": None,
                "collection_interval_sec": None,
                "scan_type": kind,
                "priority": "P5",
                "includes_deep_scan": True,
                "note": "Scheduled independently — never part of 30-min posture cycle",
            }
        )
    return out


def get_refresh_policy(policy_id: str) -> dict[str, Any] | None:
    for p in list_refresh_policies():
        if p["id"] == policy_id:
            return p
    return None


def shortest_required_interval_sec() -> int:
    """Shortest control freshness among Layer B — informs how often reconciliation must run."""
    vals = [int(m["stale_after_sec"]) for m in DEFAULT_FRESHNESS.values()]
    return min(vals) if vals else default_interval_sec()


def _priority_for(policy_id: str, stale_after: int) -> str:
    if policy_id in {"host_firewall", "host_defender", "host_ssh_root"}:
        return "P1"
    if stale_after <= 15 * 60:
        return "P1"
    if stale_after <= 6 * 3600:
        return "P3"
    if stale_after <= 24 * 3600:
        return "P2"
    return "P4"


def architecture_layers() -> dict[str, Any]:
    return {
        "A_realtime": {
            "latency": "seconds/minutes",
            "sources": list(LAYER_A_REALTIME),
            "note": "Event-driven via agents/SSE — not waiting for posture cycle",
        },
        "B_posture_refresh": {
            "default_interval_sec": default_interval_sec(),
            "stages": list(LAYER_B_POSTURE),
            "note": "Platform reconciliation — never full Nmap/Nuclei/ZAP",
        },
        "C_deep_scans": {
            "kinds": list(LAYER_C_DEEP),
            "note": "Independently scheduled and rate-limited",
        },
    }
