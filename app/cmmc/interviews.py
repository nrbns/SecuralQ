"""CMMC Interview workflow — Question → Person → Role → Response → Reviewer → Evidence.

Builds on method=interview evidence + human_attestations. Not a standalone HR system.
"""

from __future__ import annotations

from typing import Any

from app.cmmc.methods import record_method_evidence
from app.cmmc.schema import ensure_cmmc_assessment_schema
from app.db import get_conn, new_id, now, row_to_dict

VALID_INTERVIEW_STATUS = frozenset(
    {"assigned", "submitted", "approved", "rejected", "attested"}
)


def create_interview(
    user_id: str,
    *,
    framework_id: str,
    control_id: str,
    question: str,
    person: str,
    role: str = "",
    objective_id: str = "",
    assignee: str = "",
    org_id: str | None = None,
) -> dict[str, Any]:
    ensure_cmmc_assessment_schema()
    from app.tenancy import primary_org_id

    if not (question or "").strip():
        raise ValueError("question is required")
    if not (person or "").strip():
        raise ValueError("person is required")
    oid = org_id or primary_org_id(user_id)
    rid = new_id()
    t = now()
    get_conn().execute(
        """
        INSERT INTO cmmc_interviews
        (id, user_id, org_id, framework_id, control_id, objective_id, question,
         person, role, response, status, assignee, reviewer, evidence_id,
         method_evidence_id, notes, assigned_at, submitted_at, reviewed_at, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, '', 'assigned', ?, '', '', '', '', ?, NULL, NULL, ?, ?)
        """,
        (
            rid,
            user_id,
            oid,
            framework_id,
            control_id,
            objective_id or "",
            question[:2000],
            person[:200],
            (role or "")[:200],
            (assignee or person)[:200],
            t,
            t,
            t,
        ),
    )
    get_conn().commit()
    try:
        from app.realtime_bus import publish

        publish(
            type="cmmc",
            event_type="cmmc.interview.assigned",
            user_id=user_id,
            org_id=oid,
            interview_id=rid,
            control_id=control_id,
        )
    except Exception:
        pass
    return get_interview(user_id, rid) or {"id": rid}


def submit_interview_response(
    user_id: str,
    interview_id: str,
    *,
    response: str,
    notes: str = "",
) -> dict[str, Any]:
    ensure_cmmc_assessment_schema()
    row = get_conn().execute(
        "SELECT * FROM cmmc_interviews WHERE id = ? AND user_id = ?",
        (interview_id, user_id),
    ).fetchone()
    if not row:
        raise ValueError("interview not found")
    if not (response or "").strip():
        raise ValueError("response is required")
    t = now()
    get_conn().execute(
        """
        UPDATE cmmc_interviews SET
            response = ?, notes = ?, status = 'submitted',
            submitted_at = ?, updated_at = ?
        WHERE id = ?
        """,
        (response[:8000], (notes or "")[:2000], t, t, interview_id),
    )
    get_conn().commit()
    return get_interview(user_id, interview_id) or {"id": interview_id}


def review_interview(
    user_id: str,
    interview_id: str,
    *,
    decision: str,
    reviewer: str,
    notes: str = "",
    link_method_evidence: bool = True,
) -> dict[str, Any]:
    """Approve/reject interview; on approve, create Interview method evidence + attestation."""
    ensure_cmmc_assessment_schema()
    dec = (decision or "").strip().lower()
    if dec not in {"approved", "rejected", "attested"}:
        raise ValueError("decision must be approved, rejected, or attested")
    row = get_conn().execute(
        "SELECT * FROM cmmc_interviews WHERE id = ? AND user_id = ?",
        (interview_id, user_id),
    ).fetchone()
    if not row:
        raise ValueError("interview not found")
    d = row_to_dict(row)
    if d.get("status") not in {"submitted", "assigned", "rejected"}:
        raise ValueError(f"cannot review interview in status={d.get('status')}")
    t = now()
    evidence_id = ""
    method_id = ""
    status = "approved" if dec in {"approved", "attested"} else "rejected"

    if status == "approved" and link_method_evidence:
        meth = record_method_evidence(
            user_id,
            framework_id=d["framework_id"],
            control_id=d["control_id"],
            method="interview",
            title=f"Interview: {d.get('person')} — {d.get('question', '')[:80]}",
            detail={
                "interview_id": interview_id,
                "question": d.get("question"),
                "person": d.get("person"),
                "role": d.get("role"),
                "response": d.get("response"),
                "reviewer": reviewer,
            },
            objective_id=d.get("objective_id") or "",
            result="pass",
            reviewer=reviewer,
            org_id=d.get("org_id"),
        )
        evidence_id = str(meth.get("evidence_id") or "")
        method_id = str(meth.get("id") or "")

    get_conn().execute(
        """
        UPDATE cmmc_interviews SET
            status = ?, reviewer = ?, notes = CASE WHEN ? != '' THEN ? ELSE notes END,
            evidence_id = COALESCE(NULLIF(?, ''), evidence_id),
            method_evidence_id = COALESCE(NULLIF(?, ''), method_evidence_id),
            reviewed_at = ?, updated_at = ?
        WHERE id = ?
        """,
        (
            status if dec != "attested" else "attested",
            (reviewer or "")[:200],
            notes,
            notes[:2000],
            evidence_id,
            method_id,
            t,
            t,
            interview_id,
        ),
    )
    get_conn().commit()

    try:
        from app.services.human_attestation import record_attestation

        record_attestation(
            user_id,
            subject_type="control",
            subject_id=interview_id,
            decision="attested" if dec == "attested" else ("approved" if status == "approved" else "rejected"),
            title=f"CMMC interview {d.get('control_id')}",
            submitted_by=d.get("person") or "",
            reviewed_by=reviewer,
            comment=notes or d.get("response") or "",
            evidence_ids=[evidence_id] if evidence_id else [],
            framework_id=d["framework_id"],
            control_id=d["control_id"],
            meta={"interview_id": interview_id, "question": d.get("question")},
            org_id=d.get("org_id"),
        )
    except Exception:
        pass

    try:
        from app.realtime_bus import publish

        publish(
            type="cmmc",
            event_type="cmmc.interview.reviewed",
            user_id=user_id,
            org_id=d.get("org_id"),
            interview_id=interview_id,
            decision=dec,
            control_id=d.get("control_id"),
        )
    except Exception:
        pass

    return get_interview(user_id, interview_id) or {"id": interview_id}


def get_interview(user_id: str, interview_id: str) -> dict[str, Any] | None:
    ensure_cmmc_assessment_schema()
    row = get_conn().execute(
        "SELECT * FROM cmmc_interviews WHERE id = ? AND user_id = ?",
        (interview_id, user_id),
    ).fetchone()
    return row_to_dict(row) if row else None


def list_interviews(
    user_id: str,
    *,
    framework_id: str = "",
    control_id: str = "",
    status: str = "",
    limit: int = 100,
) -> list[dict[str, Any]]:
    ensure_cmmc_assessment_schema()
    from app.tenancy import tenant_visibility_sql

    where, args = tenant_visibility_sql(user_id)
    q = f"SELECT * FROM cmmc_interviews WHERE {where}"
    if framework_id:
        q += " AND framework_id = ?"
        args.append(framework_id)
    if control_id:
        q += " AND control_id = ?"
        args.append(control_id)
    if status:
        q += " AND status = ?"
        args.append(status)
    q += " ORDER BY updated_at DESC LIMIT ?"
    args.append(max(1, min(limit, 500)))
    return [row_to_dict(r) for r in get_conn().execute(q, args).fetchall()]
