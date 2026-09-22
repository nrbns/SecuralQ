"""Posture dashboard views — score lenses, attention, health, history."""

from __future__ import annotations

import json
from typing import Any

from app.db import get_conn, now
from app.posture.refresh_policy import architecture_layers, default_interval_sec, get_org_interval
from app.posture.refresh_run import latest_refresh_run, list_refresh_runs
from app.posture.schema import ensure_posture_schema


def compute_posture_scores(
    user_id: str,
    *,
    asset_r: dict[str, Any] | None = None,
    ev_r: dict[str, Any] | None = None,
    vuln_r: dict[str, Any] | None = None,
    risk_r: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Multi-lens posture scores (0–100 heuristics). Not a certification score."""
    asset_r = asset_r or {}
    ev_r = ev_r or {}
    vuln_r = vuln_r or {}
    risk_r = risk_r or {}

    total_a = max(int(asset_r.get("total") or 0), 1)
    healthy = int(asset_r.get("healthy") or 0)
    endpoint = round(100.0 * healthy / total_a, 1)

    checked = max(int(ev_r.get("checked") or 0), 1)
    evidence = round(100.0 * int(ev_r.get("fresh") or 0) / checked, 1)

    open_v = int(vuln_r.get("open") or 0)
    crit = int(vuln_r.get("critical") or 0)
    # exposure: fewer open/critical → higher
    exposure = max(0.0, min(100.0, 100.0 - open_v * 0.5 - crit * 5.0))

    risk_score = risk_r.get("score")
    try:
        technical = max(0.0, min(100.0, 100.0 - float(risk_score or 0)))
    except (TypeError, ValueError):
        technical = 50.0

    # Compliance / identity / cloud — best-effort from available data
    compliance = evidence  # until richer live SSP rollup injected
    identity = evidence
    cloud = 50.0
    try:
        from app.services.live_ssp import live_ssp_snapshot

        ssp = live_ssp_snapshot(user_id, "cmmc_l2")
        counts = ssp.get("counts") or {}
        impl = int(counts.get("implemented") or 0)
        total = max(int(ssp.get("controls_total") or 1), 1)
        compliance = round(100.0 * impl / total, 1)
    except Exception:
        pass

    overall = round(
        (
            technical * 0.2
            + compliance * 0.2
            + exposure * 0.15
            + identity * 0.1
            + endpoint * 0.15
            + cloud * 0.05
            + evidence * 0.15
        ),
        1,
    )
    return {
        "overall": overall,
        "technical": round(technical, 1),
        "compliance": round(compliance, 1),
        "exposure": round(exposure, 1),
        "identity": round(identity, 1),
        "endpoint": endpoint,
        "cloud": cloud,
        "evidence": evidence,
        "disclaimer": "Heuristic multi-lens posture — not a certification or SPRS score.",
    }


def what_needs_attention(
    user_id: str,
    *,
    asset_r: dict[str, Any] | None = None,
    vuln_r: dict[str, Any] | None = None,
    ev_r: dict[str, Any] | None = None,
    risk_r: dict[str, Any] | None = None,
    limit: int = 10,
) -> list[dict[str, Any]]:
    """Prioritized WHAT → WHY → IMPACT actions (not a dump of every finding)."""
    items: list[dict[str, Any]] = []
    vuln_r = vuln_r or {}
    asset_r = asset_r or {}
    ev_r = ev_r or {}

    if int(vuln_r.get("critical") or 0) > 0:
        items.append(
            {
                "priority": 1,
                "title": f"{vuln_r['critical']} critical open vulnerabilities",
                "why": "Internet/business exposure risk",
                "impact": "HIGH",
                "lens": "exposure",
                "action": "Prioritize patching / compensating controls",
            }
        )
    if int(asset_r.get("critical_stale") or 0) > 0:
        items.append(
            {
                "priority": 2,
                "title": f"{asset_r['critical_stale']} critical/high assets stale",
                "why": "High-value systems without fresh telemetry",
                "impact": "HIGH",
                "lens": "endpoint",
                "action": "Restore agent check-in on critical assets",
            }
        )
    if int(asset_r.get("stale") or 0) > 0:
        items.append(
            {
                "priority": 3,
                "title": f"{asset_r['stale']} stale endpoints",
                "why": "Telemetry older than expected",
                "impact": "HIGH",
                "lens": "endpoint",
                "action": "Investigate agent check-in / network reachability",
            }
        )
    if int(asset_r.get("unreachable") or 0) > 0:
        items.append(
            {
                "priority": 4,
                "title": f"{asset_r['unreachable']} unreachable assets",
                "why": "Cannot verify control state",
                "impact": "HIGH",
                "lens": "endpoint",
                "action": "Check network path / agent registration",
            }
        )
    if int(ev_r.get("expired") or 0) > 0:
        items.append(
            {
                "priority": 5,
                "title": f"{ev_r['expired']} expired evidence items",
                "why": "Compliance claims may no longer be current",
                "impact": "HIGH",
                "lens": "evidence",
                "action": "Recollect Examine/Interview/Test evidence",
            }
        )
    if int(ev_r.get("stale") or 0) > 0:
        items.append(
            {
                "priority": 6,
                "title": f"{ev_r['stale']} stale evidence items",
                "why": "Freshness policy threshold exceeded",
                "impact": "MEDIUM",
                "lens": "evidence",
                "action": "Refresh policies / host controls",
            }
        )
    if int(asset_r.get("offline") or 0) > 0:
        items.append(
            {
                "priority": 7,
                "title": f"{asset_r['offline']} offline assets",
                "why": "Cannot verify control state",
                "impact": "MEDIUM",
                "lens": "endpoint",
                "action": "Restore connectivity or decommission",
            }
        )
    return sorted(items, key=lambda x: x["priority"])[:limit]


def posture_dashboard(user_id: str) -> dict[str, Any]:
    ensure_posture_schema()
    latest = latest_refresh_run(user_id)
    settings = get_org_interval(user_id)
    interval = int(settings.get("interval_sec") or default_interval_sec())
    last_ts = (latest or {}).get("completed_at") or (latest or {}).get("started_at")
    next_ts = (float(last_ts) + interval) if last_ts else now() + interval

    snap = None
    row = get_conn().execute(
        """
        SELECT * FROM posture_snapshots WHERE user_id = ?
        ORDER BY created_at DESC LIMIT 1
        """,
        (user_id,),
    ).fetchone()
    if row:
        snap = dict(row)
        for k in ("asset_health_json", "posture_scores_json", "attention_json", "counts_json"):
            alias = k.replace("_json", "")
            try:
                snap[alias] = json.loads(snap.get(k) or ("[]" if "attention" in k else "{}"))
            except Exception:
                snap[alias] = [] if "attention" in k else {}

    status = "unknown"
    if latest:
        st = latest.get("status")
        if st == "completed":
            status = "healthy"
        elif st == "partial":
            status = "degraded"
        elif st == "failed":
            status = "unhealthy"
        elif st == "running":
            status = "refreshing"

    scores = (snap or {}).get("posture_scores") or {}
    assets = (snap or {}).get("asset_health") or {}

    return {
        "ok": True,
        "engine": "SecuraIQ Continuous Posture Engine",
        "status": status,
        "last_refresh": latest,
        "next_refresh_at": next_ts,
        "interval_sec": interval,
        "settings": settings,
        "assets": assets,
        "scores": scores,
        "attention": (snap or {}).get("attention") or [],
        "snapshot": {
            "id": (snap or {}).get("id"),
            "risk_score": (snap or {}).get("risk_score"),
            "evidence_fresh_percent": (snap or {}).get("evidence_fresh_percent"),
            "created_at": (snap or {}).get("created_at"),
        },
        "layers": architecture_layers(),
        "disclaimer": (
            "Posture refresh reconciles assets/controls/evidence/vulns/risk/compliance. "
            "It does not run deep scanners (Nmap/Nuclei/ZAP)."
        ),
    }


def posture_history(user_id: str, *, limit: int = 48) -> dict[str, Any]:
    ensure_posture_schema()
    rows = get_conn().execute(
        """
        SELECT id, risk_score, risk_band, evidence_fresh_percent, created_at, content_hash
        FROM posture_snapshots WHERE user_id = ?
        ORDER BY created_at DESC LIMIT ?
        """,
        (user_id, max(1, min(limit, 200))),
    ).fetchall()
    points = [dict(r) for r in reversed(list(rows))]
    return {"ok": True, "points": points, "count": len(points)}


def posture_health() -> dict[str, Any]:
    """Mission Control style posture engine health."""
    ensure_posture_schema()
    from app.jobs import JOB_HANDLERS

    running = get_conn().execute(
        """
        SELECT COUNT(*) AS n FROM posture_refresh_runs
        WHERE status = 'running' AND started_at > ?
        """,
        (now() - 3600,),
    ).fetchone()
    failed = get_conn().execute(
        """
        SELECT COUNT(*) AS n FROM posture_refresh_runs
        WHERE status = 'failed' AND created_at > ?
        """,
        (now() - 86400,),
    ).fetchone()
    last = get_conn().execute(
        """
        SELECT completed_at, status, duration_ms FROM posture_refresh_runs
        WHERE completed_at IS NOT NULL
        ORDER BY completed_at DESC LIMIT 1
        """
    ).fetchone()
    last_ago = None
    if last and last["completed_at"]:
        last_ago = round(now() - float(last["completed_at"]), 1)

    metrics = {}
    try:
        from app.posture.metrics import refresh_metrics

        metrics = refresh_metrics(since_sec=86400)
    except Exception:
        metrics = {}

    return {
        "ok": True,
        "scheduler": "healthy" if "posture_refresh" in JOB_HANDLERS else "unregistered",
        "handler_registered": "posture_refresh" in JOB_HANDLERS,
        "running_last_hour": int(running["n"] or 0) if running else 0,
        "failed_last_24h": int(failed["n"] or 0) if failed else 0,
        "last_cycle_sec_ago": last_ago,
        "last_status": (dict(last).get("status") if last else None),
        "last_duration_ms": (dict(last).get("duration_ms") if last else None),
        "default_interval_sec": default_interval_sec(),
        "metrics_24h": metrics.get("by_status") if isinstance(metrics, dict) else {},
        "note": "In-process job worker — not multi-AZ HA proof.",
    }


def what_changed_since(user_id: str) -> dict[str, Any]:
    ensure_posture_schema()
    rows = get_conn().execute(
        """
        SELECT * FROM posture_snapshots WHERE user_id = ?
        ORDER BY created_at DESC LIMIT 2
        """,
        (user_id,),
    ).fetchall()
    if len(rows) < 2:
        return {"ok": True, "available": False, "reason": "need_two_snapshots"}
    cur, prev = dict(rows[0]), dict(rows[1])
    for snap in (cur, prev):
        try:
            snap["asset_health"] = json.loads(snap.get("asset_health_json") or "{}")
        except Exception:
            snap["asset_health"] = {}
    from app.posture.orchestrator import _diff_snapshots

    return {"ok": True, **_diff_snapshots(prev, cur)}
