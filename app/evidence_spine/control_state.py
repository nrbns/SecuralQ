"""Control runtime state machine.

States: unknown → evaluating → pass|fail|partial → stale → (recollect) → …

Tracks CURRENT / PREVIOUS / CHANGED_AT / SOURCE / VERSION for realtime UI.
"""

from __future__ import annotations

import json
from typing import Any

from app.db import get_conn, new_id, now, row_to_dict
from app.evidence_spine.dependencies import evaluate_dependencies
from app.evidence_spine.evaluate import evaluate_control_from_evidence
from app.evidence_spine.freshness import apply_freshness_to_result
from app.evidence_spine.schema import ensure_evidence_spine_schema

VALID_STATES = {
    "unknown",
    "evaluating",
    "pass",
    "fail",
    "partial",
    "stale",
    "error",
}


def ensure_control_state_schema() -> None:
    ensure_evidence_spine_schema()
    c = get_conn()
    c.executescript(
        """
        CREATE TABLE IF NOT EXISTS control_runtime_state (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            org_id TEXT,
            framework_id TEXT NOT NULL DEFAULT '',
            control_id TEXT NOT NULL,
            state TEXT NOT NULL DEFAULT 'unknown',
            previous_state TEXT NOT NULL DEFAULT '',
            changed_at REAL NOT NULL,
            last_observed_at REAL,
            evidence_ids_json TEXT NOT NULL DEFAULT '[]',
            source TEXT NOT NULL DEFAULT '',
            event_id TEXT NOT NULL DEFAULT '',
            version INTEGER NOT NULL DEFAULT 1,
            detail_json TEXT NOT NULL DEFAULT '{}',
            UNIQUE(user_id, framework_id, control_id)
        );
        CREATE INDEX IF NOT EXISTS idx_crs_user_state
            ON control_runtime_state(user_id, state, changed_at DESC);
        """
    )
    c.commit()


def _publish(event_type: str, user_id: str, **extra: Any) -> None:
    try:
        from app.realtime_events import publish_aliased
        from app.tenancy import primary_org_id

        oid = primary_org_id(user_id)
        publish_aliased(
            "control",
            aliases=[event_type, "control.updated"] if event_type != "control.updated" else [event_type],
            user_id=user_id,
            org_id=oid,
            organization_id=oid,
            **extra,
        )
    except Exception:
        pass


def get_control_state(
    user_id: str,
    *,
    control_id: str,
    framework_id: str = "",
) -> dict[str, Any] | None:
    ensure_control_state_schema()
    row = get_conn().execute(
        """
        SELECT * FROM control_runtime_state
        WHERE user_id = ? AND framework_id = ? AND control_id = ?
        """,
        (user_id, framework_id or "", control_id),
    ).fetchone()
    if not row:
        return None
    d = row_to_dict(row)
    try:
        d["evidence_ids"] = json.loads(d.get("evidence_ids_json") or "[]")
    except Exception:
        d["evidence_ids"] = []
    try:
        d["detail"] = json.loads(d.get("detail_json") or "{}")
    except Exception:
        d["detail"] = {}
    return d


def list_control_states(
    user_id: str,
    *,
    state: str = "",
    limit: int = 200,
    org_id: str | None = None,
) -> list[dict[str, Any]]:
    ensure_control_state_schema()
    from app.tenancy import tenant_visibility_sql

    where, args = tenant_visibility_sql(user_id, org_id=org_id)
    q = f"SELECT * FROM control_runtime_state WHERE {where}"
    if state:
        q += " AND state = ?"
        args.append(state)
    q += " ORDER BY changed_at DESC LIMIT ?"
    args.append(max(1, min(limit, 500)))
    out = []
    for row in get_conn().execute(q, args).fetchall():
        d = row_to_dict(row)
        try:
            d["evidence_ids"] = json.loads(d.get("evidence_ids_json") or "[]")
        except Exception:
            d["evidence_ids"] = []
        try:
            d["detail"] = json.loads(d.get("detail_json") or "{}")
        except Exception:
            d["detail"] = {}
        out.append(d)
    return out


def transition_control_state(
    user_id: str,
    *,
    control_id: str,
    new_state: str,
    framework_id: str = "",
    source: str = "",
    evidence_ids: list[str] | None = None,
    last_observed_at: float | None = None,
    detail: dict[str, Any] | None = None,
    event_id: str = "",
) -> dict[str, Any]:
    """Idempotent transition; records previous_state + bumps version on change."""
    ensure_control_state_schema()
    st = (new_state or "unknown").strip().lower()
    if st not in VALID_STATES:
        raise ValueError(f"invalid state: {new_state}")
    from app.tenancy import primary_org_id

    fid = framework_id or ""
    cid = (control_id or "").strip()
    if not cid:
        raise ValueError("control_id required")
    existing = get_control_state(user_id, control_id=cid, framework_id=fid)
    t = now()
    eid = event_id or new_id()
    if existing and existing.get("state") == st:
        # Refresh observation time / evidence without version bump
        get_conn().execute(
            """
            UPDATE control_runtime_state
            SET last_observed_at = COALESCE(?, last_observed_at),
                evidence_ids_json = ?,
                detail_json = ?,
                source = CASE WHEN ? != '' THEN ? ELSE source END
            WHERE id = ?
            """,
            (
                last_observed_at,
                json.dumps(evidence_ids or existing.get("evidence_ids") or [])[:4000],
                json.dumps(detail or existing.get("detail") or {})[:4000],
                source,
                source,
                existing["id"],
            ),
        )
        get_conn().commit()
        return get_control_state(user_id, control_id=cid, framework_id=fid) or existing

    prev = (existing or {}).get("state") or ""
    ver = int((existing or {}).get("version") or 0) + 1
    if existing:
        get_conn().execute(
            """
            UPDATE control_runtime_state SET
                state = ?, previous_state = ?, changed_at = ?,
                last_observed_at = ?, evidence_ids_json = ?, source = ?,
                event_id = ?, version = ?, detail_json = ?
            WHERE id = ?
            """,
            (
                st,
                prev,
                t,
                last_observed_at if last_observed_at is not None else existing.get("last_observed_at"),
                json.dumps(evidence_ids or [])[:4000],
                (source or "")[:80],
                eid,
                ver,
                json.dumps(detail or {})[:4000],
                existing["id"],
            ),
        )
        get_conn().commit()
        out = get_control_state(user_id, control_id=cid, framework_id=fid)
    else:
        rid = new_id()
        get_conn().execute(
            """
            INSERT INTO control_runtime_state
            (id, user_id, org_id, framework_id, control_id, state, previous_state,
             changed_at, last_observed_at, evidence_ids_json, source, event_id,
             version, detail_json)
            VALUES (?, ?, ?, ?, ?, ?, '', ?, ?, ?, ?, ?, 1, ?)
            """,
            (
                rid,
                user_id,
                primary_org_id(user_id),
                fid,
                cid,
                st,
                t,
                last_observed_at,
                json.dumps(evidence_ids or [])[:4000],
                (source or "")[:80],
                eid,
                json.dumps(detail or {})[:4000],
            ),
        )
        get_conn().commit()
        out = get_control_state(user_id, control_id=cid, framework_id=fid)

    event_map = {
        "pass": "control.passed",
        "fail": "control.failed",
        "stale": "control.stale",
        "evaluating": "control.evaluating",
        "error": "control.error",
        "partial": "control.updated",
        "unknown": "control.unknown",
    }
    _publish(
        event_map.get(st, "control.updated"),
        user_id,
        control_id=cid,
        framework_id=fid,
        state=st,
        previous_state=prev,
        version=ver if existing else 1,
        event_id=eid,
        changed_at=t,
    )
    return out or {"ok": True, "state": st}


def reconcile_control(
    user_id: str,
    *,
    control_id: str,
    framework_id: str = "",
    test_name: str = "",
) -> dict[str, Any]:
    """Evaluate evidence + dependencies + freshness → transition state."""
    eval_res = evaluate_control_from_evidence(
        user_id, control_id=control_id, framework_id=framework_id
    )
    deps = evaluate_dependencies(
        user_id, control_id=control_id, framework_id=framework_id
    )
    result = str(eval_res.get("result") or "unknown")
    # Dependency pack incomplete → cannot be pass
    if deps.get("required") and not deps.get("complete") and result == "pass":
        result = "partial"
        eval_res = dict(eval_res)
        eval_res["note"] = (
            f"{eval_res.get('note')} Dependency pack incomplete: {deps.get('note')}"
        )

    # Live-test freshness overlay when test_name provided
    if test_name and result in {"pass", "fail"}:
        existing = get_control_state(user_id, control_id=control_id, framework_id=framework_id)
        last = (existing or {}).get("last_observed_at")
        fr = apply_freshness_to_result(
            result=result,
            last_observed=float(last) if last else None,
            control_or_test=test_name or control_id,
        )
        if fr.get("stale"):
            result = "stale"

    state = transition_control_state(
        user_id,
        control_id=control_id,
        new_state=result if result in VALID_STATES else "unknown",
        framework_id=framework_id,
        source="reconcile",
        evidence_ids=list(eval_res.get("evidence_ids") or []),
        last_observed_at=now() if result in {"pass", "fail", "partial"} else None,
        detail={"evaluate": eval_res, "dependencies": deps},
    )
    return {
        "ok": True,
        "state": state,
        "evaluate": eval_res,
        "dependencies": deps,
    }


def run_stale_tick(user_id: str) -> dict[str, Any]:
    """Scan runtime states + mapped evidence; transition aged PASS/FAIL → STALE."""
    ensure_control_state_schema()
    actions: list[dict[str, Any]] = []
    rows = list_control_states(user_id, limit=400)
    for row in rows:
        st = row.get("state")
        if st not in {"pass", "fail", "partial"}:
            continue
        last = row.get("last_observed_at") or row.get("changed_at")
        test_hint = (row.get("detail") or {}).get("test_name") or row.get("control_id")
        fr = apply_freshness_to_result(
            result=st,
            last_observed=float(last) if last else None,
            control_or_test=str(test_hint),
        )
        if not fr.get("stale"):
            continue
        out = transition_control_state(
            user_id,
            control_id=str(row["control_id"]),
            new_state="stale",
            framework_id=str(row.get("framework_id") or ""),
            source="stale_tick",
            evidence_ids=list(row.get("evidence_ids") or []),
            detail={"freshness": fr, "reason": "evidence aged past policy"},
        )
        actions.append(
            {
                "control_id": row["control_id"],
                "framework_id": row.get("framework_id"),
                "from": st,
                "to": "stale",
                "version": (out or {}).get("version"),
            }
        )
        # Open a Compliance Ops recollection task for host live tests only
        cid = str(row.get("control_id") or "")
        if cid.startswith("host_"):
            try:
                from app.compliance_ops.bridge import upsert_task_from_control_result

                upsert_task_from_control_result(
                    user_id,
                    test_name=cid,
                    status="fail",
                    summary=f"Control went STALE — recollect evidence ({fr.get('note')})",
                )
            except Exception:
                pass
    # Also reconcile controls that have dependency packs but no runtime row yet
    try:
        from app.evidence_spine.dependencies import list_requirements

        seen = set()
        for req in list_requirements(user_id):
            key = (req.get("framework_id") or "", req.get("control_id") or "")
            if not key[1] or key in seen:
                continue
            seen.add(key)
            if any(
                r.get("control_id") == key[1] and (r.get("framework_id") or "") == key[0]
                for r in rows
            ):
                continue
            reconcile_control(
                user_id, control_id=key[1], framework_id=key[0]
            )
    except Exception:
        pass
    return {"ok": True, "user_id": user_id, "stale_transitions": len(actions), "actions": actions}


def run_stale_tick_all_users(*, limit_users: int = 50) -> dict[str, Any]:
    ensure_control_state_schema()
    # Users with runtime state or evidence mappings
    uids = [
        r["user_id"]
        for r in get_conn()
        .execute(
            """
            SELECT DISTINCT user_id FROM control_runtime_state
            UNION
            SELECT DISTINCT user_id FROM evidence_control_map
            LIMIT ?
            """,
            (limit_users,),
        )
        .fetchall()
    ]
    results = []
    for uid in uids:
        try:
            results.append(run_stale_tick(uid))
        except Exception as exc:
            results.append({"ok": False, "user_id": uid, "error": str(exc)[:200]})
    return {"ok": True, "users": len(results), "results": results}
