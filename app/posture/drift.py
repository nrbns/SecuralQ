"""Posture drift + security baseline snapshots."""

from __future__ import annotations

import json
from typing import Any

from app.db import get_conn, new_id, now, row_to_dict
from app.posture.schema import ensure_posture_schema


def create_baseline(
    user_id: str,
    *,
    name: str = "Baseline",
    org_id: str | None = None,
) -> dict[str, Any]:
    """Capture current posture snapshot as known-good baseline."""
    ensure_posture_schema()
    from app.tenancy import primary_org_id

    oid = org_id or primary_org_id(user_id)
    snap = get_conn().execute(
        """
        SELECT * FROM posture_snapshots WHERE user_id = ?
        ORDER BY created_at DESC LIMIT 1
        """,
        (user_id,),
    ).fetchone()
    if not snap:
        raise ValueError("No posture snapshot yet — run a posture refresh first")
    snap_d = dict(snap)
    version = 1
    prev = get_conn().execute(
        "SELECT MAX(version) AS v FROM posture_baselines WHERE user_id = ?",
        (user_id,),
    ).fetchone()
    if prev and prev["v"]:
        version = int(prev["v"]) + 1
    bid = new_id()
    t = now()
    payload = {
        "snapshot_id": snap_d.get("id"),
        "risk_score": snap_d.get("risk_score"),
        "evidence_fresh_percent": snap_d.get("evidence_fresh_percent"),
        "asset_health": json.loads(snap_d.get("asset_health_json") or "{}"),
        "posture_scores": json.loads(snap_d.get("posture_scores_json") or "{}"),
    }
    get_conn().execute(
        """
        INSERT INTO posture_baselines
        (id, user_id, org_id, name, version, snapshot_id, payload_json, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            bid,
            user_id,
            oid,
            (name or "Baseline")[:200],
            version,
            snap_d.get("id") or "",
            json.dumps(payload)[:12000],
            t,
            t,
        ),
    )
    get_conn().commit()
    return get_baseline(user_id, bid) or {"id": bid, "version": version}


def get_baseline(user_id: str, baseline_id: str) -> dict[str, Any] | None:
    ensure_posture_schema()
    row = get_conn().execute(
        "SELECT * FROM posture_baselines WHERE id = ? AND user_id = ?",
        (baseline_id, user_id),
    ).fetchone()
    if not row:
        return None
    d = row_to_dict(row)
    try:
        d["payload"] = json.loads(d.get("payload_json") or "{}")
    except Exception:
        d["payload"] = {}
    return d


def latest_baseline(user_id: str) -> dict[str, Any] | None:
    ensure_posture_schema()
    row = get_conn().execute(
        """
        SELECT * FROM posture_baselines WHERE user_id = ?
        ORDER BY version DESC LIMIT 1
        """,
        (user_id,),
    ).fetchone()
    if not row:
        return None
    return get_baseline(user_id, row["id"])


def detect_drift(user_id: str) -> dict[str, Any]:
    """Compare latest baseline vs current snapshot."""
    ensure_posture_schema()
    base = latest_baseline(user_id)
    if not base:
        return {"ok": True, "available": False, "reason": "no_baseline"}
    snap = get_conn().execute(
        """
        SELECT * FROM posture_snapshots WHERE user_id = ?
        ORDER BY created_at DESC LIMIT 1
        """,
        (user_id,),
    ).fetchone()
    if not snap:
        return {"ok": True, "available": False, "reason": "no_current_snapshot"}
    cur = dict(snap)
    try:
        cur_assets = json.loads(cur.get("asset_health_json") or "{}")
        cur_scores = json.loads(cur.get("posture_scores_json") or "{}")
    except Exception:
        cur_assets, cur_scores = {}, {}
    payload = base.get("payload") or {}
    base_assets = payload.get("asset_health") or {}
    base_scores = payload.get("posture_scores") or {}

    drifts: list[dict[str, Any]] = []
    # Asset health drift
    for key in ("stale", "offline", "degraded"):
        b = int(base_assets.get(key) or 0)
        c = int(cur_assets.get(key) or 0)
        if c > b:
            drifts.append(
                {
                    "kind": "security_drift" if key != "stale" else "endpoint_drift",
                    "field": f"assets.{key}",
                    "baseline": b,
                    "current": c,
                    "delta": c - b,
                    "severity": "high" if key == "offline" else "medium",
                }
            )
    # Evidence / compliance score drift
    for lens in ("evidence", "compliance", "overall", "endpoint"):
        b = base_scores.get(lens)
        c = cur_scores.get(lens)
        if b is None or c is None:
            continue
        try:
            delta = float(c) - float(b)
        except (TypeError, ValueError):
            continue
        if delta <= -5:
            drifts.append(
                {
                    "kind": "compliance_drift" if lens in {"evidence", "compliance"} else "posture_drift",
                    "field": f"score.{lens}",
                    "baseline": b,
                    "current": c,
                    "delta": round(delta, 1),
                    "severity": "high" if delta <= -15 else "medium",
                }
            )
    # Risk score increase
    br = payload.get("risk_score")
    cr = cur.get("risk_score")
    if br is not None and cr is not None:
        try:
            rd = float(cr) - float(br)
            if rd >= 5:
                drifts.append(
                    {
                        "kind": "risk_drift",
                        "field": "risk_score",
                        "baseline": br,
                        "current": cr,
                        "delta": round(rd, 1),
                        "severity": "high" if rd >= 15 else "medium",
                    }
                )
        except (TypeError, ValueError):
            pass

    return {
        "ok": True,
        "available": True,
        "baseline": {"id": base.get("id"), "version": base.get("version"), "name": base.get("name")},
        "current_snapshot_id": cur.get("id"),
        "drift_count": len(drifts),
        "drifts": drifts,
        "disclaimer": "Drift is relative to the org baseline snapshot — not an external audit finding.",
    }
