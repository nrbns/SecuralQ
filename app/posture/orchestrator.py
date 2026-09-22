"""Posture refresh orchestrator — Layer B reconciliation only.

Never enqueues Nmap/Nuclei/ZAP. Calls existing Evidence Spine / risk /
compliance / exception / vault ticks and builds a snapshot.
"""

from __future__ import annotations

import hashlib
import json
import time
from typing import Any

from app.db import get_conn, new_id, now
from app.posture.refresh_lock import acquire_refresh_lock, release_refresh_lock
from app.posture.refresh_run import create_refresh_run, update_refresh_run
from app.posture.schema import ensure_posture_schema


def run_posture_refresh(
    user_id: str,
    *,
    trigger: str = "scheduled",
    org_id: str | None = None,
    force: bool = False,
) -> dict[str, Any]:
    """Execute one posture refresh cycle for a tenant."""
    ensure_posture_schema()
    from app.tenancy import primary_org_id

    oid = org_id or primary_org_id(user_id)
    lock_key = f"posture:{oid or user_id}:posture"
    idem = "" if force else f"{lock_key}:{int(now() // 60)}"  # per-minute bucket

    run = create_refresh_run(
        user_id,
        trigger=trigger,
        org_id=oid,
        idempotency_key=idem,
        scope={"layers": ["B_posture"], "excludes": ["nmap", "nuclei", "zap", "dast"]},
    )
    # If create returned an already-running sibling
    if run.get("status") in {"running", "queued"} and run.get("id") and not force:
        if run.get("started_at") and run.get("status") == "running":
            return {**run, "deduped": True}

    rid = run["id"]
    if not acquire_refresh_lock(lock_key, run_id=rid, user_id=user_id, org_id=oid, ttl_sec=1800):
        update_refresh_run(rid, status="cancelled", completed_at=now())
        return {
            "ok": False,
            "status": "cancelled",
            "reason": "refresh_already_running",
            "run_id": rid,
            "lock_key": lock_key,
        }

    t0 = time.perf_counter()
    started = now()
    stages: list[dict[str, Any]] = []
    errors: list[str] = []
    counts = {
        "assets_checked": 0,
        "controls_checked": 0,
        "vulnerabilities_checked": 0,
        "compliance_checked": 0,
        "evidence_checked": 0,
        "risk_recalculated": 0,
        "findings_created": 0,
        "stale_assets": 0,
    }

    update_refresh_run(rid, status="running", started_at=started)
    _publish(user_id, oid, "posture.refresh.started", run_id=rid, trigger=trigger)

    def _stage(name: str, fn) -> Any:
        st = {"name": name, "status": "running", "started_at": now()}
        try:
            result = fn()
            st["status"] = "ok"
            st["result"] = _summarize(result)
            stages.append(st)
            return result
        except Exception as exc:
            st["status"] = "error"
            st["error"] = str(exc)[:300]
            stages.append(st)
            errors.append(f"{name}: {exc}")
            return None

    # --- stages (existing components only) ---
    asset_r = _stage("asset_health", lambda: _refresh_assets(user_id))
    if isinstance(asset_r, dict):
        counts["assets_checked"] = int(asset_r.get("total") or 0)
        counts["stale_assets"] = int(asset_r.get("stale") or 0)

    ctrl_r = _stage("controls", lambda: _refresh_controls(user_id))
    if isinstance(ctrl_r, dict):
        counts["controls_checked"] = int(ctrl_r.get("checked") or ctrl_r.get("stale") or 0)

    ev_r = _stage("evidence_freshness", lambda: _refresh_evidence(user_id))
    if isinstance(ev_r, dict):
        counts["evidence_checked"] = int(ev_r.get("checked") or 0)

    vuln_r = _stage("vulnerabilities", lambda: _refresh_vulns(user_id))
    if isinstance(vuln_r, dict):
        counts["vulnerabilities_checked"] = int(vuln_r.get("open") or 0)

    comp_r = _stage("compliance", lambda: _refresh_compliance(user_id))
    if isinstance(comp_r, dict):
        counts["compliance_checked"] = int(comp_r.get("checked") or 0)

    risk_r = _stage("risk", lambda: _refresh_risk(user_id))
    if isinstance(risk_r, dict) and risk_r.get("score") is not None:
        counts["risk_recalculated"] = 1

    _stage("exceptions", lambda: _refresh_exceptions(user_id))
    _stage("vault_expiry", lambda: _refresh_vault(user_id))
    _stage("notifications", lambda: _refresh_notifications())

    # Snapshot + delta vs previous
    prev = _latest_snapshot(user_id)
    snap = _stage(
        "snapshot",
        lambda: _write_snapshot(
            user_id,
            org_id=oid,
            run_id=rid,
            asset_r=asset_r or {},
            ctrl_r=ctrl_r or {},
            ev_r=ev_r or {},
            vuln_r=vuln_r or {},
            risk_r=risk_r or {},
            comp_r=comp_r or {},
        ),
    )
    changed = _stage(
        "what_changed",
        lambda: _diff_snapshots(prev, snap if isinstance(snap, dict) else None),
    )

    # Audit evidence for the refresh itself
    evidence_id = ""
    try:
        from app.services.evidence import record_evidence

        ev = record_evidence(
            user_id,
            entity_type="posture_refresh",
            entity_id=rid,
            source="observed",
            summary=f"Posture refresh {trigger} — {len(stages)} stages",
            detail={
                "run_id": rid,
                "trigger": trigger,
                "counts": counts,
                "errors": errors,
                "changed": changed,
            },
            created_by="posture_engine",
            org_id=oid,
        )
        evidence_id = str(ev.get("id") or "")
    except Exception as exc:
        errors.append(f"refresh_evidence: {exc}")

    duration_ms = int((time.perf_counter() - t0) * 1000)
    status = "completed"
    if errors and any(s.get("status") == "ok" for s in stages):
        status = "partial"
    elif errors and not any(s.get("status") == "ok" for s in stages):
        status = "failed"
    if counts["stale_assets"] and status == "completed":
        # completed with stale assets → partial honesty
        if counts["assets_checked"] and (
            counts["stale_assets"] / max(counts["assets_checked"], 1) >= 0.02
        ):
            status = "partial"

    content = json.dumps({"counts": counts, "stages": stages, "changed": changed}, sort_keys=True, default=str)
    chash = hashlib.sha256(content.encode("utf-8")).hexdigest()

    out = update_refresh_run(
        rid,
        status=status,
        completed_at=now(),
        duration_ms=duration_ms,
        errors_json=errors,
        stages_json=stages,
        metrics_json={"changed": changed, "layers": "B_posture"},
        previous_snapshot_id=(prev or {}).get("id") or "",
        snapshot_id=(snap or {}).get("id") if isinstance(snap, dict) else "",
        evidence_id=evidence_id,
        content_hash=chash,
        **counts,
    )
    release_refresh_lock(lock_key, run_id=rid)
    _publish(
        user_id,
        oid,
        "posture.refresh.completed",
        run_id=rid,
        status=status,
        duration_ms=duration_ms,
        stale_assets=counts["stale_assets"],
    )
    return {
        "ok": status in {"completed", "partial"},
        "run": out,
        "status": status,
        "duration_ms": duration_ms,
        "counts": counts,
        "errors": errors,
        "changed": changed,
        "disclaimer": (
            "Posture refresh is platform reconciliation (assets/controls/evidence/"
            "vulns/risk/compliance). It does not run Nmap, Nuclei, ZAP, or other "
            "deep scanners — those remain independently scheduled."
        ),
    }


def run_posture_refresh_all_users(*, limit_users: int = 50) -> dict[str, Any]:
    """Scheduled fan-out across tenants (best-effort)."""
    ensure_posture_schema()
    try:
        uids = [
            r["id"]
            for r in get_conn()
            .execute("SELECT id FROM users LIMIT ?", (limit_users,))
            .fetchall()
        ]
    except Exception:
        uids = []
    if not uids:
        uids = ["local"]
    results = []
    for uid in uids:
        try:
            results.append(run_posture_refresh(uid, trigger="scheduled"))
        except Exception as exc:
            results.append({"ok": False, "user_id": uid, "error": str(exc)})
    return {
        "ok": True,
        "users": len(uids),
        "runs": len(results),
        "partial": sum(1 for r in results if r.get("status") == "partial"),
        "failed": sum(1 for r in results if not r.get("ok")),
    }


# --- stage helpers ---


def _refresh_assets(user_id: str) -> dict[str, Any]:
    # Be resilient to schema variants across labs
    try:
        cols = {r[1] for r in get_conn().execute("PRAGMA table_info(assets)").fetchall()}
    except Exception:
        cols = set()
    select = ["id"]
    for c in ("hostname", "name", "last_seen", "updated_at", "created_at", "status", "agent_id"):
        if c in cols:
            select.append(c)
    if not select:
        return {"total": 0, "healthy": 0, "stale": 0, "offline": 0, "degraded": 0, "unknown": 0}
    rows = get_conn().execute(
        f"SELECT {', '.join(select)} FROM assets WHERE user_id = ?",
        (user_id,),
    ).fetchall()
    t = now()
    healthy = stale = offline = degraded = unknown = 0
    for r in rows:
        d = dict(r)
        last = float(d.get("last_seen") or d.get("updated_at") or d.get("created_at") or 0)
        st = (d.get("status") or "").lower()
        age = t - last if last else 1e9
        if st in {"offline", "unreachable"} or age > 24 * 3600:
            offline += 1
        elif age > 2 * 3600:
            stale += 1
        elif st in {"degraded", "warning"}:
            degraded += 1
        elif last:
            healthy += 1
        else:
            unknown += 1
    return {
        "total": len(rows),
        "healthy": healthy,
        "stale": stale,
        "offline": offline,
        "degraded": degraded,
        "unknown": unknown,
    }


def _refresh_controls(user_id: str) -> dict[str, Any]:
    from app.evidence_spine.control_state import run_stale_tick

    return run_stale_tick(user_id)


def _refresh_evidence(user_id: str) -> dict[str, Any]:
    from app.services.evidence import freshness_status

    rows = get_conn().execute(
        "SELECT * FROM securaiq_evidence WHERE user_id = ? ORDER BY last_seen DESC LIMIT 2000",
        (user_id,),
    ).fetchall()
    fresh = stale = expired = 0
    for r in rows:
        d = dict(r)
        fs = freshness_status(d)
        if fs == "fresh":
            fresh += 1
        elif fs == "stale":
            stale += 1
        elif fs == "expired":
            expired += 1
    return {"checked": len(rows), "fresh": fresh, "stale": stale, "expired": expired}


def _refresh_vulns(user_id: str) -> dict[str, Any]:
    try:
        from app.enterprise import list_vulnerabilities

        open_v = list_vulnerabilities(user_id, status="open")
        crit = sum(1 for v in open_v if (v.get("severity") or "").lower() == "critical")
        high = sum(1 for v in open_v if (v.get("severity") or "").lower() == "high")
        return {"open": len(open_v), "critical": crit, "high": high}
    except Exception:
        n = get_conn().execute(
            "SELECT COUNT(*) AS n FROM vulnerabilities WHERE user_id = ? AND status = 'open'",
            (user_id,),
        ).fetchone()
        return {"open": int(n["n"] or 0) if n else 0}


def _refresh_compliance(user_id: str) -> dict[str, Any]:
    try:
        from app.compliance_ops.automation import run_compliance_ops_tick

        out = run_compliance_ops_tick(user_id)
        return {"checked": 1, "tick": out}
    except Exception as exc:
        return {"checked": 0, "error": str(exc)}


def _refresh_risk(user_id: str) -> dict[str, Any]:
    from app.event_processor import _maybe_publish_org_risk
    from app.services.risk_priority import compute_org_risk_score

    result = compute_org_risk_score(user_id)
    _maybe_publish_org_risk(user_id, reason="posture_refresh")
    return result if isinstance(result, dict) else {}


def _refresh_exceptions(user_id: str) -> dict[str, Any]:
    from app.services.exceptions import run_exception_expiry_tick

    # tick is multi-user; still useful as reconciliation
    return run_exception_expiry_tick(limit_users=5)


def _refresh_vault(user_id: str) -> dict[str, Any]:
    try:
        from app.evidence_spine.vault import run_vault_expiry_tick

        return run_vault_expiry_tick(limit=100)
    except Exception as exc:
        return {"ok": False, "error": str(exc)}


def _refresh_notifications() -> dict[str, Any]:
    try:
        from app.notification_worker import process_outbox

        return process_outbox(limit=20)
    except Exception as exc:
        return {"ok": False, "error": str(exc)}


def _latest_snapshot(user_id: str) -> dict[str, Any] | None:
    row = get_conn().execute(
        """
        SELECT * FROM posture_snapshots WHERE user_id = ?
        ORDER BY created_at DESC LIMIT 1
        """,
        (user_id,),
    ).fetchone()
    if not row:
        return None
    d = dict(row)
    for k in ("asset_health_json", "posture_scores_json", "counts_json", "attention_json"):
        alias = k.replace("_json", "")
        try:
            d[alias] = json.loads(d.get(k) or ("[]" if "attention" in k else "{}"))
        except Exception:
            d[alias] = [] if "attention" in k else {}
    return d


def _write_snapshot(
    user_id: str,
    *,
    org_id: str | None,
    run_id: str,
    asset_r: dict[str, Any],
    ctrl_r: dict[str, Any],
    ev_r: dict[str, Any],
    vuln_r: dict[str, Any],
    risk_r: dict[str, Any],
    comp_r: dict[str, Any],
) -> dict[str, Any]:
    from app.posture.views import compute_posture_scores, what_needs_attention

    scores = compute_posture_scores(
        user_id, asset_r=asset_r, ev_r=ev_r, vuln_r=vuln_r, risk_r=risk_r
    )
    attention = what_needs_attention(
        user_id, asset_r=asset_r, vuln_r=vuln_r, ev_r=ev_r, risk_r=risk_r
    )
    checked = max(int(ev_r.get("checked") or 0), 1)
    fresh_pct = round(100.0 * int(ev_r.get("fresh") or 0) / checked, 1)
    sid = new_id()
    t = now()
    payload = {
        "assets": asset_r,
        "controls": ctrl_r,
        "evidence": ev_r,
        "vulns": vuln_r,
        "compliance": comp_r,
        "risk": {"score": risk_r.get("score"), "band": risk_r.get("band")},
    }
    chash = hashlib.sha256(
        json.dumps(payload, sort_keys=True, default=str).encode("utf-8")
    ).hexdigest()
    get_conn().execute(
        """
        INSERT INTO posture_snapshots
        (id, user_id, org_id, run_id, risk_score, risk_band, compliance_percent,
         evidence_fresh_percent, asset_health_json, posture_scores_json, counts_json,
         attention_json, content_hash, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            sid,
            user_id,
            org_id,
            run_id,
            risk_r.get("score"),
            str(risk_r.get("band") or ""),
            None,
            fresh_pct,
            json.dumps(asset_r)[:4000],
            json.dumps(scores)[:4000],
            json.dumps(payload)[:8000],
            json.dumps(attention)[:8000],
            chash,
            t,
        ),
    )
    get_conn().commit()
    return {
        "id": sid,
        "risk_score": risk_r.get("score"),
        "risk_band": risk_r.get("band"),
        "evidence_fresh_percent": fresh_pct,
        "asset_health": asset_r,
        "posture_scores": scores,
        "attention": attention,
        "content_hash": chash,
        "created_at": t,
    }


def _diff_snapshots(
    prev: dict[str, Any] | None, cur: dict[str, Any] | None
) -> dict[str, Any]:
    if not cur:
        return {"available": False}
    if not prev:
        return {"available": True, "first_snapshot": True, "current": cur.get("id")}
    pa = prev.get("asset_health") or {}
    ca = cur.get("asset_health") or {}
    try:
        prev_counts = prev.get("counts") or json.loads(prev.get("counts_json") or "{}")
    except Exception:
        prev_counts = {}
    try:
        cur_counts = cur.get("counts") if "vulns" in (cur.get("counts") or {}) else None
    except Exception:
        cur_counts = None
    # Prefer nested from write
    pv = (prev_counts.get("vulns") if isinstance(prev_counts, dict) else None) or {}
    # cur write stores in counts_json via payload — for return object use asset_health directly
    risk_prev = prev.get("risk_score")
    risk_cur = cur.get("risk_score")
    return {
        "available": True,
        "previous_snapshot_id": prev.get("id"),
        "current_snapshot_id": cur.get("id"),
        "assets": {
            "total_delta": int(ca.get("total") or 0) - int(pa.get("total") or 0),
            "stale_delta": int(ca.get("stale") or 0) - int(pa.get("stale") or 0),
            "healthy_delta": int(ca.get("healthy") or 0) - int(pa.get("healthy") or 0),
        },
        "risk": {
            "from": risk_prev,
            "to": risk_cur,
            "delta": (float(risk_cur) - float(risk_prev))
            if risk_prev is not None and risk_cur is not None
            else None,
        },
        "evidence_fresh_percent": {
            "from": prev.get("evidence_fresh_percent"),
            "to": cur.get("evidence_fresh_percent"),
        },
    }


def _summarize(result: Any) -> Any:
    if result is None:
        return None
    if isinstance(result, dict):
        # keep small
        keys = list(result.keys())[:12]
        return {k: result[k] for k in keys if not isinstance(result[k], (list, dict)) or k in {"asset_health", "attention"}}
    return str(result)[:200]


def _publish(user_id: str, org_id: str | None, event_type: str, **extra: Any) -> None:
    try:
        from app.realtime_bus import publish

        publish(
            type="posture",
            event_type=event_type,
            user_id=user_id,
            org_id=org_id,
            **extra,
        )
    except Exception:
        pass
