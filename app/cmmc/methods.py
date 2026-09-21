"""Examine / Interview / Test evidence — first-class CMMC assessment methods."""

from __future__ import annotations

import json
from typing import Any

from app.cmmc.schema import ensure_cmmc_assessment_schema
from app.db import get_conn, new_id, now, row_to_dict

VALID_METHODS = frozenset({"examine", "interview", "test"})
VALID_RESULTS = frozenset({"pass", "fail", "partial", "unknown", "na"})


def record_method_evidence(
    user_id: str,
    *,
    framework_id: str,
    control_id: str,
    method: str,
    title: str,
    detail: dict[str, Any] | None = None,
    objective_id: str = "",
    result: str = "unknown",
    reviewer: str = "",
    org_id: str | None = None,
    link_to_spine: bool = True,
) -> dict[str, Any]:
    """Record Examine/Interview/Test and optionally create Evidence Spine row."""
    ensure_cmmc_assessment_schema()
    m = (method or "").strip().lower()
    if m not in VALID_METHODS:
        raise ValueError(f"method must be one of {sorted(VALID_METHODS)}")
    res = (result or "unknown").strip().lower()
    if res not in VALID_RESULTS:
        raise ValueError(f"result must be one of {sorted(VALID_RESULTS)}")
    from app.tenancy import primary_org_id

    oid = org_id or primary_org_id(user_id)
    t = now()
    rid = new_id()
    detail_d = dict(detail or {})
    detail_d.setdefault("method", m)
    detail_d.setdefault("framework_id", framework_id)
    detail_d.setdefault("control_id", control_id)

    evidence_id = ""
    if link_to_spine:
        try:
            from app.services.evidence import record_evidence
            from app.evidence_spine.mapping import link_evidence_to_control

            source = "declared" if m in {"examine", "interview"} else "observed"
            ev = record_evidence(
                user_id,
                entity_type=f"cmmc_{m}",
                entity_id=f"{control_id}:{rid[:8]}",
                source=source,
                summary=(title or f"{m} evidence for {control_id}")[:500],
                detail=detail_d,
                org_id=oid,
                created_by=reviewer or user_id,
                verified=(m == "examine" and res == "pass"),
            )
            evidence_id = str(ev.get("id") or "")
            if evidence_id:
                try:
                    link_evidence_to_control(
                        user_id,
                        evidence_id,
                        control_id=control_id,
                        framework_id=framework_id,
                        role="documents" if m == "examine" else "supports",
                    )
                except Exception:
                    pass
        except Exception:
            evidence_id = ""

    get_conn().execute(
        """
        INSERT INTO cmmc_method_evidence
        (id, user_id, org_id, framework_id, control_id, objective_id, method, title,
         detail_json, evidence_id, result, collected_at, reviewer, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            rid,
            user_id,
            oid,
            framework_id,
            control_id,
            objective_id or "",
            m,
            (title or "")[:300],
            json.dumps(detail_d)[:8000],
            evidence_id,
            res,
            t,
            (reviewer or "")[:200],
            t,
        ),
    )
    get_conn().commit()

    # Continuous chain: evidence → risk hint
    try:
        from app.event_processor import _maybe_publish_org_risk

        _maybe_publish_org_risk(user_id, reason=f"cmmc_{m}_evidence")
    except Exception:
        pass
    try:
        from app.realtime_bus import publish

        publish(
            type="cmmc",
            event_type="cmmc.method_evidence.created",
            user_id=user_id,
            org_id=oid,
            control_id=control_id,
            method=m,
            evidence_id=evidence_id,
            result=res,
        )
    except Exception:
        pass

    row = get_conn().execute("SELECT * FROM cmmc_method_evidence WHERE id = ?", (rid,)).fetchone()
    return _hydrate(row_to_dict(row)) if row else {"id": rid, "evidence_id": evidence_id}


def list_method_evidence(
    user_id: str,
    *,
    framework_id: str = "",
    control_id: str = "",
    method: str = "",
    limit: int = 100,
) -> list[dict[str, Any]]:
    ensure_cmmc_assessment_schema()
    from app.tenancy import tenant_visibility_sql

    where, args = tenant_visibility_sql(user_id)
    q = f"SELECT * FROM cmmc_method_evidence WHERE {where}"
    if framework_id:
        q += " AND framework_id = ?"
        args.append(framework_id)
    if control_id:
        q += " AND control_id = ?"
        args.append(control_id)
    if method:
        q += " AND method = ?"
        args.append(method)
    q += " ORDER BY collected_at DESC LIMIT ?"
    args.append(max(1, min(limit, 500)))
    return [_hydrate(row_to_dict(r)) for r in get_conn().execute(q, args).fetchall()]


def _hydrate(d: dict[str, Any]) -> dict[str, Any]:
    try:
        d["detail"] = json.loads(d.get("detail_json") or "{}")
    except Exception:
        d["detail"] = {}
    return d
