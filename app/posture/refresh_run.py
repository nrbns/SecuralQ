"""PostureRefreshRun persistence and stage tracking."""

from __future__ import annotations

import json
from typing import Any

from app.db import get_conn, new_id, now, row_to_dict
from app.posture.schema import ensure_posture_schema

VALID_STATUS = frozenset(
    {"scheduled", "queued", "running", "partial", "completed", "failed", "cancelled"}
)
VALID_TRIGGERS = frozenset({"scheduled", "manual", "event", "api"})


def create_refresh_run(
    user_id: str,
    *,
    trigger: str = "scheduled",
    refresh_type: str = "posture",
    org_id: str | None = None,
    scope: dict[str, Any] | None = None,
    idempotency_key: str = "",
) -> dict[str, Any]:
    ensure_posture_schema()
    from app.tenancy import primary_org_id

    tr = (trigger or "scheduled").lower()
    if tr not in VALID_TRIGGERS:
        raise ValueError(f"trigger must be one of {sorted(VALID_TRIGGERS)}")
    oid = org_id or primary_org_id(user_id)
    key = (idempotency_key or "").strip()
    if key:
        existing = get_conn().execute(
            """
            SELECT * FROM posture_refresh_runs
            WHERE idempotency_key = ? AND status IN ('queued', 'running')
            LIMIT 1
            """,
            (key,),
        ).fetchone()
        if existing:
            return _hydrate(row_to_dict(existing))

    rid = new_id()
    t = now()
    get_conn().execute(
        """
        INSERT INTO posture_refresh_runs
        (id, user_id, org_id, trigger, status, refresh_type, scope_json,
         idempotency_key, created_at, updated_at)
        VALUES (?, ?, ?, ?, 'queued', ?, ?, ?, ?, ?)
        """,
        (
            rid,
            user_id,
            oid,
            tr,
            refresh_type[:40],
            json.dumps(scope or {})[:4000],
            key,
            t,
            t,
        ),
    )
    get_conn().commit()
    return get_refresh_run(user_id, rid) or {"id": rid, "status": "queued"}


def update_refresh_run(run_id: str, **fields: Any) -> dict[str, Any] | None:
    ensure_posture_schema()
    row = get_conn().execute(
        "SELECT * FROM posture_refresh_runs WHERE id = ?", (run_id,)
    ).fetchone()
    if not row:
        return None
    allowed = {
        "status",
        "started_at",
        "completed_at",
        "duration_ms",
        "assets_checked",
        "controls_checked",
        "vulnerabilities_checked",
        "compliance_checked",
        "evidence_checked",
        "risk_recalculated",
        "findings_created",
        "stale_assets",
        "errors_json",
        "stages_json",
        "metrics_json",
        "previous_snapshot_id",
        "snapshot_id",
        "evidence_id",
        "content_hash",
    }
    sets = ["updated_at = ?"]
    args: list[Any] = [now()]
    for k, v in fields.items():
        if k not in allowed:
            continue
        if k.endswith("_json") and not isinstance(v, str):
            v = json.dumps(v)[:16000]
        sets.append(f"{k} = ?")
        args.append(v)
    args.append(run_id)
    get_conn().execute(
        f"UPDATE posture_refresh_runs SET {', '.join(sets)} WHERE id = ?", args
    )
    get_conn().commit()
    d = row_to_dict(
        get_conn().execute("SELECT * FROM posture_refresh_runs WHERE id = ?", (run_id,)).fetchone()
    )
    return _hydrate(d)


def get_refresh_run(user_id: str, run_id: str) -> dict[str, Any] | None:
    ensure_posture_schema()
    row = get_conn().execute(
        "SELECT * FROM posture_refresh_runs WHERE id = ? AND user_id = ?",
        (run_id, user_id),
    ).fetchone()
    return _hydrate(row_to_dict(row)) if row else None


def list_refresh_runs(
    user_id: str, *, limit: int = 20, status: str = ""
) -> list[dict[str, Any]]:
    ensure_posture_schema()
    from app.tenancy import tenant_visibility_sql

    where, args = tenant_visibility_sql(user_id)
    q = f"SELECT * FROM posture_refresh_runs WHERE {where}"
    if status:
        q += " AND status = ?"
        args.append(status)
    q += " ORDER BY created_at DESC LIMIT ?"
    args.append(max(1, min(limit, 100)))
    return [_hydrate(row_to_dict(r)) for r in get_conn().execute(q, args).fetchall()]


def latest_refresh_run(user_id: str) -> dict[str, Any] | None:
    rows = list_refresh_runs(user_id, limit=1)
    return rows[0] if rows else None


def _hydrate(d: dict[str, Any]) -> dict[str, Any]:
    for key, alias in (
        ("errors_json", "errors"),
        ("stages_json", "stages"),
        ("metrics_json", "metrics"),
        ("scope_json", "scope"),
    ):
        try:
            raw = d.get(key) or ("[]" if alias != "metrics" and alias != "scope" else "{}")
            d[alias] = json.loads(raw)
        except Exception:
            d[alias] = [] if alias in {"errors", "stages"} else {}
    return d
