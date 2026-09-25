"""Measured-ops ladder — last real numbers only. Never invent rungs.

Reads gitignored jsonl under data/ops/ (or SECURAIQ_OPS_LOG_DIR).
SQLite RTO/RPO and in-process restart reclaim can be published from this host.
HTTP 5k, Sentinel multi-AZ, Postgres restore, and macOS M1/M2 stay ops.
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

_ROOT = Path(__file__).resolve().parents[1]

HA_DR_LOG = "ha_dr_measurements.jsonl"
RESTART_LOG = "restart_reclaim_measurements.jsonl"


def ops_log_dir() -> Path:
    override = (os.environ.get("SECURAIQ_OPS_LOG_DIR") or "").strip()
    if override:
        return Path(override)
    return _ROOT / "data" / "ops"


def append_measurement(log_name: str, row: dict[str, Any]) -> Path:
    log = ops_log_dir() / log_name
    log.parent.mkdir(parents=True, exist_ok=True)
    payload = {"ts_utc": datetime.now(timezone.utc).isoformat(), **row}
    with log.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(payload, default=str) + "\n")
    return log


def latest_measurement(log_name: str, *, require_ok: bool = True) -> dict[str, Any] | None:
    log = ops_log_dir() / log_name
    if not log.is_file():
        return None
    latest: dict[str, Any] | None = None
    try:
        for line in log.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            row = json.loads(line)
            if require_ok and not row.get("ok"):
                continue
            latest = row
    except Exception:
        return latest
    return latest


def sqlite_dr_published() -> bool:
    row = latest_measurement(HA_DR_LOG)
    if not row:
        return False
    return row.get("rto_ms") is not None and row.get("rpo_ms") is not None


def sqlite_dr_status() -> dict[str, Any]:
    row = latest_measurement(HA_DR_LOG)
    published = bool(row and row.get("rto_ms") is not None and row.get("rpo_ms") is not None)
    return {
        "id": "sqlite_ha_dr",
        "status": "lab" if published else "ops",
        "published": published,
        "rto_ms": row.get("rto_ms") if row else None,
        "rpo_ms": row.get("rpo_ms") if row else None,
        "backup_ms": row.get("backup_ms") if row else None,
        "restore_ms": row.get("restore_ms") if row else None,
        "verify_ms": row.get("verify_ms") if row else None,
        "src_bytes": row.get("src_bytes") if row else None,
        "ts_utc": row.get("ts_utc") if row else None,
        "ops_blocked": [] if published else ["rto_rpo_unpublished"],
        "leftover": ["postgres_restore", "cluster_kill_rto"],
        "hint": "python scripts/backup_restore_drill.py --record",
        "disclaimer": (
            "RTO is file-copy + verify of a closed SQLite lab DB. "
            "Not control-plane restore after killing API/Redis/Postgres."
        ),
    }


def restart_reclaim_published() -> bool:
    row = latest_measurement(RESTART_LOG)
    return bool(row and row.get("reclaim_ms") is not None)


def restart_reclaim_status() -> dict[str, Any]:
    row = latest_measurement(RESTART_LOG)
    published = bool(row and row.get("reclaim_ms") is not None)
    return {
        "id": "restart_reclaim",
        "status": "lab" if published else "ops",
        "published": published,
        "reclaim_ms": row.get("reclaim_ms") if row else None,
        "reclaimed": row.get("reclaimed") if row else None,
        "ts_utc": row.get("ts_utc") if row else None,
        "leftover": ["kill_at_5k"],
        "hint": "python scripts/restart_reclaim_drill.py --record",
        "disclaimer": (
            "In-process running→pending flip. Process-kill @5k HTTP remains ops."
        ),
    }


def measured_ops_board() -> dict[str, Any]:
    from app.phase1_ops_remaining import capacity_http_status, sentinel_ha_status

    sqlite = sqlite_dr_status()
    restart = restart_reclaim_status()
    capacity = capacity_http_status()
    sentinel = sentinel_ha_status()
    try:
        from app.metrics import stage_latency_snapshot

        stages = stage_latency_snapshot()
    except Exception:
        stages = {
            "disclaimer": "Process-local stage meters unavailable.",
        }
    return {
        "ok": True,
        "sqlite_dr": sqlite,
        "restart_reclaim": restart,
        "http_capacity": {
            "http_top_measured": capacity.get("http_top_measured"),
            "http_1000_measured": capacity.get("http_1000_measured"),
            "status": capacity.get("status"),
            "disclaimer": capacity.get("disclaimer"),
        },
        "sentinel": {
            "live_inject_measured": sentinel.get("live_inject_measured"),
            "docker_present": sentinel.get("docker_present"),
            "status": sentinel.get("status"),
            "disclaimer": sentinel.get("disclaimer"),
        },
        "stage_latency": stages,
        "still_ops": [
            "ev_notarize",
            "cloud_object_lock",
            "live_idp",
            "c3pao",
            "http_5k_100k",
            "macos_m1_m2_live",
            "postgres_restore",
            "sentinel_multi_az",
            "kill_at_5k",
        ],
        "disclaimer": (
            "Only numbers present in data/ops jsonl are shown. "
            "Unmeasured rungs stay null — never invented."
        ),
    }
