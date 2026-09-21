"""Multi-source Observation reconciliation → canonical subject state.

When Agent, Cloud, and Scanner disagree on the same check for the same
subject, SecuraIQ must not silently pick a winner. It must:

  Source → Observation → Confidence → Freshness
       → Conflict detection → Resolution → Canonical state

Honesty: auto-resolution uses severity + freshness rules only.
Human resolve is first-class when sources conflict.
"""

from __future__ import annotations

import json
from typing import Any

from app.db import get_conn, new_id, now, row_to_dict
from app.evidence_spine.freshness import apply_freshness_to_result
from app.evidence_spine.schema import ensure_evidence_spine_schema

# Prefer more severe when advising on conflicting fresh signals
_SEVERITY = {
    "fail": 40,
    "open": 40,
    "exposed": 40,
    "conflict": 35,
    "partial": 20,
    "stale": 15,
    "unknown": 10,
    "pass": 5,
    "on": 5,
    "off": 40,  # firewall OFF is fail-class for security checks
}


def ensure_reconciliation_schema() -> None:
    ensure_evidence_spine_schema()
    c = get_conn()
    c.executescript(
        """
        CREATE TABLE IF NOT EXISTS observation_canonical_state (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            org_id TEXT,
            subject_key TEXT NOT NULL,
            check_id TEXT NOT NULL,
            asset_id TEXT NOT NULL DEFAULT '',
            hostname TEXT NOT NULL DEFAULT '',
            canonical_result TEXT NOT NULL DEFAULT 'unknown',
            conflict_status TEXT NOT NULL DEFAULT 'insufficient',
            resolution TEXT NOT NULL DEFAULT '',
            resolved_by TEXT NOT NULL DEFAULT '',
            sources_json TEXT NOT NULL DEFAULT '[]',
            evidence_ids_json TEXT NOT NULL DEFAULT '[]',
            note TEXT NOT NULL DEFAULT '',
            version INTEGER NOT NULL DEFAULT 1,
            previous_result TEXT NOT NULL DEFAULT '',
            changed_at REAL NOT NULL,
            created_at REAL NOT NULL,
            UNIQUE(user_id, subject_key, check_id)
        );
        CREATE INDEX IF NOT EXISTS idx_ocs_user_conflict
            ON observation_canonical_state(user_id, conflict_status, changed_at DESC);
        CREATE INDEX IF NOT EXISTS idx_ocs_check
            ON observation_canonical_state(user_id, check_id);
        """
    )
    c.commit()


def subject_key(
    *,
    asset_id: str = "",
    hostname: str = "",
    agent_id: str = "",
    source_ref: str = "",
    ip: str = "",
) -> str:
    """Stable subject identity for reconciliation (not a full CMDB merge)."""
    aid = (asset_id or "").strip()
    if aid:
        return f"asset:{aid}"
    host = (hostname or "").strip().lower().rstrip(".")
    ip_s = (ip or "").strip()
    try:
        from app.asset_names import host_correlation_key

        if ip_s:
            key = host_correlation_key(ip_s)
            if key:
                return f"host:{key}"
        if host:
            key = host_correlation_key(host)
            if key:
                return f"host:{key}"
    except Exception:
        pass
    if host:
        return f"host:{host}"
    if ip_s:
        return f"ip:{ip_s}"
    ag = (agent_id or "").strip()
    if ag:
        return f"agent:{ag}"
    ref = (source_ref or "").strip()
    if ref:
        return f"ref:{ref}"
    return "subject:unknown"


def _publish(event_type: str, user_id: str, **extra: Any) -> None:
    try:
        from app.realtime_events import publish_aliased

        aliases = [event_type]
        if event_type != "observation.reconciled":
            aliases.append("observation.reconciled")
        publish_aliased(
            "observation",
            aliases=aliases,
            user_id=user_id,
            **extra,
        )
    except Exception:
        pass


def _normalize_result(raw: str) -> str:
    r = (raw or "unknown").strip().lower()
    if r in {"on", "enabled", "true", "ok", "healthy"}:
        return "pass"
    if r in {"off", "disabled", "false", "open", "exposed", "critical"}:
        return "fail"
    if r in {"pass", "fail", "partial", "stale", "unknown", "conflict"}:
        return r
    return r or "unknown"


def _parse_detail(row: dict[str, Any]) -> dict[str, Any]:
    d = row.get("detail")
    if isinstance(d, dict):
        return d
    try:
        return json.loads(row.get("detail_json") or "{}")
    except Exception:
        return {}


def list_observations_for_check(
    user_id: str,
    *,
    check_id: str,
    subject: str = "",
    since_sec: float = 7 * 86400,
    limit: int = 100,
) -> list[dict[str, Any]]:
    """Recent observations for a check, optionally filtered by subject_key."""
    ensure_reconciliation_schema()
    cid = (check_id or "").strip()
    if not cid:
        return []
    cutoff = now() - max(60.0, float(since_sec))
    rows = get_conn().execute(
        """
        SELECT * FROM evidence_observations
        WHERE user_id = ? AND check_id = ? AND observed_at >= ?
        ORDER BY observed_at DESC
        LIMIT ?
        """,
        (user_id, cid, cutoff, max(1, min(limit, 500))),
    ).fetchall()
    out: list[dict[str, Any]] = []
    for row in rows:
        d = row_to_dict(row)
        detail = _parse_detail(d)
        d["detail"] = detail
        sk = subject_key(
            asset_id=str(detail.get("asset_id") or ""),
            hostname=str(detail.get("hostname") or ""),
            agent_id=str(detail.get("agent_id") or ""),
            source_ref=str(d.get("source_ref") or ""),
            ip=str(detail.get("ip") or ""),
        )
        d["subject_key"] = sk
        if subject and sk != subject:
            continue
        out.append(d)
    return out


def _latest_per_source(observations: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Keep the freshest observation per data_source (+ source_ref)."""
    best: dict[str, dict[str, Any]] = {}
    for obs in observations:
        src = (obs.get("data_source") or "unknown").strip().lower() or "unknown"
        ref = (obs.get("source_ref") or "").strip()
        key = f"{src}:{ref}" if ref else src
        prev = best.get(key)
        if not prev or float(obs.get("observed_at") or 0) > float(prev.get("observed_at") or 0):
            best[key] = obs
    return list(best.values())


def detect_conflict(
    observations: list[dict[str, Any]],
    *,
    check_id: str,
    now_ts: float | None = None,
) -> dict[str, Any]:
    """Compare multi-source observations → agreed | conflict | insufficient."""
    t = now_ts if now_ts is not None else now()
    latest = _latest_per_source(observations)
    sources_out: list[dict[str, Any]] = []
    fresh_results: list[str] = []
    for obs in latest:
        result = _normalize_result(str(obs.get("result") or ""))
        fr = apply_freshness_to_result(
            result=result,
            last_observed=float(obs.get("observed_at") or 0) or None,
            control_or_test=check_id,
            now_ts=t,
        )
        effective = _normalize_result(str(fr.get("effective_result") or result))
        if fr.get("stale"):
            effective = "stale"
        entry = {
            "data_source": obs.get("data_source"),
            "source_ref": obs.get("source_ref"),
            "result": result,
            "effective_result": effective,
            "observed_at": obs.get("observed_at"),
            "evidence_id": obs.get("evidence_id"),
            "stale": bool(fr.get("stale")),
            "freshness_note": fr.get("note"),
            "summary": (obs.get("summary") or "")[:200],
        }
        sources_out.append(entry)
        if not fr.get("stale") and effective not in {"stale", "unknown", ""}:
            fresh_results.append(effective)

    if len(sources_out) == 0:
        return {
            "conflict_status": "insufficient",
            "canonical_result": "unknown",
            "sources": [],
            "note": "No observations for this subject/check.",
        }
    if len(fresh_results) == 0:
        return {
            "conflict_status": "insufficient",
            "canonical_result": "stale"
            if any(s.get("stale") for s in sources_out)
            else "unknown",
            "sources": sources_out,
            "note": "Only stale/unknown observations — recollect required.",
        }
    unique = sorted(set(fresh_results))
    if len(unique) == 1:
        return {
            "conflict_status": "agreed",
            "canonical_result": unique[0],
            "sources": sources_out,
            "note": f"All fresh sources agree: {unique[0]}.",
        }
    # Conflict — do not invent agreement. Prefer fail-class as advisory only.
    advisory = max(unique, key=lambda r: _SEVERITY.get(r, 0))
    return {
        "conflict_status": "conflict",
        "canonical_result": "conflict",
        "advisory_result": advisory,
        "sources": sources_out,
        "note": (
            f"Sources disagree ({', '.join(unique)}). "
            f"Advisory severity leans {advisory}; human resolution required."
        ),
    }


def get_canonical_state(
    user_id: str,
    *,
    subject_key_val: str,
    check_id: str,
) -> dict[str, Any] | None:
    ensure_reconciliation_schema()
    row = get_conn().execute(
        """
        SELECT * FROM observation_canonical_state
        WHERE user_id = ? AND subject_key = ? AND check_id = ?
        """,
        (user_id, subject_key_val, check_id),
    ).fetchone()
    if not row:
        return None
    return _hydrate(row_to_dict(row))


def list_canonical_states(
    user_id: str,
    *,
    conflict_status: str = "",
    check_id: str = "",
    limit: int = 100,
    org_id: str | None = None,
) -> list[dict[str, Any]]:
    ensure_reconciliation_schema()
    from app.tenancy import tenant_visibility_sql

    where, args = tenant_visibility_sql(user_id, org_id=org_id)
    q = f"SELECT * FROM observation_canonical_state WHERE {where}"
    if conflict_status:
        q += " AND conflict_status = ?"
        args.append(conflict_status)
    if check_id:
        q += " AND check_id = ?"
        args.append(check_id)
    q += " ORDER BY changed_at DESC LIMIT ?"
    args.append(max(1, min(limit, 500)))
    return [_hydrate(row_to_dict(r)) for r in get_conn().execute(q, args).fetchall()]


def _hydrate(d: dict[str, Any]) -> dict[str, Any]:
    try:
        d["sources"] = json.loads(d.get("sources_json") or "[]")
    except Exception:
        d["sources"] = []
    try:
        d["evidence_ids"] = json.loads(d.get("evidence_ids_json") or "[]")
    except Exception:
        d["evidence_ids"] = []
    return d


def _persist_canonical(
    user_id: str,
    *,
    subject_key_val: str,
    check_id: str,
    detection: dict[str, Any],
    asset_id: str = "",
    hostname: str = "",
    resolution: str = "auto",
    resolved_by: str = "system",
    force_result: str | None = None,
) -> dict[str, Any]:
    ensure_reconciliation_schema()
    from app.tenancy import primary_org_id

    existing = get_canonical_state(
        user_id, subject_key_val=subject_key_val, check_id=check_id
    )
    t = now()
    status = str(detection.get("conflict_status") or "insufficient")
    result = force_result or str(detection.get("canonical_result") or "unknown")
    if force_result:
        status = "agreed"
        resolution = "human"
    sources = detection.get("sources") or []
    eids = [s.get("evidence_id") for s in sources if s.get("evidence_id")]
    note = str(detection.get("note") or "")[:500]

    if (
        existing
        and existing.get("canonical_result") == result
        and existing.get("conflict_status") == status
    ):
        get_conn().execute(
            """
            UPDATE observation_canonical_state
            SET sources_json = ?, evidence_ids_json = ?, note = ?,
                asset_id = CASE WHEN ? != '' THEN ? ELSE asset_id END,
                hostname = CASE WHEN ? != '' THEN ? ELSE hostname END
            WHERE id = ?
            """,
            (
                json.dumps(sources)[:8000],
                json.dumps(eids)[:4000],
                note,
                asset_id,
                asset_id,
                hostname,
                hostname,
                existing["id"],
            ),
        )
        get_conn().commit()
        return (
            get_canonical_state(
                user_id, subject_key_val=subject_key_val, check_id=check_id
            )
            or existing
        )

    prev = (existing or {}).get("canonical_result") or ""
    ver = int((existing or {}).get("version") or 0) + 1
    if existing:
        get_conn().execute(
            """
            UPDATE observation_canonical_state SET
                canonical_result = ?, conflict_status = ?, resolution = ?,
                resolved_by = ?, sources_json = ?, evidence_ids_json = ?,
                note = ?, version = ?, previous_result = ?, changed_at = ?,
                asset_id = CASE WHEN ? != '' THEN ? ELSE asset_id END,
                hostname = CASE WHEN ? != '' THEN ? ELSE hostname END
            WHERE id = ?
            """,
            (
                result,
                status,
                resolution,
                resolved_by,
                json.dumps(sources)[:8000],
                json.dumps(eids)[:4000],
                note,
                ver,
                prev,
                t,
                asset_id,
                asset_id,
                hostname,
                hostname,
                existing["id"],
            ),
        )
        get_conn().commit()
        out = get_canonical_state(
            user_id, subject_key_val=subject_key_val, check_id=check_id
        )
    else:
        rid = new_id()
        get_conn().execute(
            """
            INSERT INTO observation_canonical_state
            (id, user_id, org_id, subject_key, check_id, asset_id, hostname,
             canonical_result, conflict_status, resolution, resolved_by,
             sources_json, evidence_ids_json, note, version, previous_result,
             changed_at, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, '', ?, ?)
            """,
            (
                rid,
                user_id,
                primary_org_id(user_id),
                subject_key_val,
                check_id,
                asset_id or "",
                hostname or "",
                result,
                status,
                resolution,
                resolved_by,
                json.dumps(sources)[:8000],
                json.dumps(eids)[:4000],
                note,
                t,
                t,
            ),
        )
        get_conn().commit()
        out = get_canonical_state(
            user_id, subject_key_val=subject_key_val, check_id=check_id
        )

    evt = (
        "observation.conflict"
        if status == "conflict"
        else "observation.reconciled"
    )
    _publish(
        evt,
        user_id,
        subject_key=subject_key_val,
        check_id=check_id,
        conflict_status=status,
        canonical_result=result,
        version=ver if existing else 1,
        previous_result=prev,
    )

    # Surface conflict onto control runtime for host_* checks
    if status == "conflict" and check_id.startswith("host_"):
        try:
            from app.evidence_spine.control_state import transition_control_state

            transition_control_state(
                user_id,
                control_id=check_id,
                new_state="partial",
                source="observation_conflict",
                evidence_ids=[e for e in eids if e],
                detail={
                    "conflict": True,
                    "subject_key": subject_key_val,
                    "sources": sources,
                    "note": note,
                },
            )
        except Exception:
            pass

    return out or {"ok": True, "canonical_result": result, "conflict_status": status}


def reconcile_observations(
    user_id: str,
    *,
    check_id: str,
    asset_id: str = "",
    hostname: str = "",
    agent_id: str = "",
    source_ref: str = "",
    ip: str = "",
    since_sec: float = 7 * 86400,
) -> dict[str, Any]:
    """Gather multi-source observations → detect conflict → persist canonical."""
    sk = subject_key(
        asset_id=asset_id,
        hostname=hostname,
        agent_id=agent_id,
        source_ref=source_ref,
        ip=ip,
    )
    cid = (check_id or "").strip()
    if not cid:
        raise ValueError("check_id required")
    observations = list_observations_for_check(
        user_id, check_id=cid, subject=sk, since_sec=since_sec
    )
    if not observations and sk == "subject:unknown":
        observations = list_observations_for_check(
            user_id, check_id=cid, since_sec=since_sec
        )
    detection = detect_conflict(observations, check_id=cid)
    state = _persist_canonical(
        user_id,
        subject_key_val=sk,
        check_id=cid,
        detection=detection,
        asset_id=asset_id,
        hostname=hostname,
        resolution="auto"
        if detection.get("conflict_status") != "conflict"
        else "pending",
        resolved_by="system",
    )
    return {
        "ok": True,
        "subject_key": sk,
        "check_id": cid,
        "detection": detection,
        "state": state,
    }


def resolve_conflict(
    user_id: str,
    *,
    subject_key_val: str,
    check_id: str,
    result: str,
    resolved_by: str = "",
    note: str = "",
) -> dict[str, Any]:
    """Human resolution of a multi-source conflict."""
    existing = get_canonical_state(
        user_id, subject_key_val=subject_key_val, check_id=check_id
    )
    if not existing:
        raise ValueError("canonical state not found — run reconcile first")
    nr = _normalize_result(result)
    detection = {
        "conflict_status": "agreed",
        "canonical_result": nr,
        "sources": existing.get("sources") or [],
        "note": note or f"Human resolved conflict → {nr}",
    }
    state = _persist_canonical(
        user_id,
        subject_key_val=subject_key_val,
        check_id=check_id,
        detection=detection,
        asset_id=str(existing.get("asset_id") or ""),
        hostname=str(existing.get("hostname") or ""),
        resolution="human",
        resolved_by=(resolved_by or "human")[:120],
        force_result=nr,
    )
    return {"ok": True, "state": state}


def reconcile_from_observation_payload(
    user_id: str,
    *,
    check_id: str,
    asset_id: str = "",
    hostname: str = "",
    agent_id: str = "",
    source_ref: str = "",
    ip: str = "",
) -> dict[str, Any] | None:
    """Best-effort hook after ingest — never raises to callers."""
    try:
        if not (check_id or "").strip():
            return None
        return reconcile_observations(
            user_id,
            check_id=check_id,
            asset_id=asset_id,
            hostname=hostname,
            agent_id=agent_id,
            source_ref=source_ref,
            ip=ip,
        )
    except Exception:
        return None
