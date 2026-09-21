"""Human attestation — Who / What / When / Evidence / Decision / Comment.

Not a checkbox. Every accept/reject/management review records a durable
attestation that can enter the audit pack.

Honesty: this records organizational decisions. It is not an external
certification or legal determination of compliance.
"""

from __future__ import annotations

import json
from typing import Any

from app.db import get_conn, new_id, now, row_to_dict

VALID_DECISIONS = {"approved", "rejected", "attested", "acknowledged"}
VALID_SUBJECTS = {
    "vault",
    "exception",
    "task",
    "framework",
    "remediation",
    "control",
    "evidence",
    "document",
}


def ensure_schema() -> None:
    c = get_conn()
    c.executescript(
        """
        CREATE TABLE IF NOT EXISTS human_attestations (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            org_id TEXT,
            subject_type TEXT NOT NULL,
            subject_id TEXT NOT NULL DEFAULT '',
            title TEXT NOT NULL DEFAULT '',
            submitted_by TEXT NOT NULL DEFAULT '',
            reviewed_by TEXT NOT NULL DEFAULT '',
            decision TEXT NOT NULL,
            comment TEXT NOT NULL DEFAULT '',
            evidence_ids_json TEXT NOT NULL DEFAULT '[]',
            framework_id TEXT NOT NULL DEFAULT '',
            control_id TEXT NOT NULL DEFAULT '',
            meta_json TEXT NOT NULL DEFAULT '{}',
            attested_at REAL NOT NULL,
            created_at REAL NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_hattest_user_time
            ON human_attestations(user_id, attested_at DESC);
        CREATE INDEX IF NOT EXISTS idx_hattest_subject
            ON human_attestations(user_id, subject_type, subject_id);
        """
    )
    c.commit()


def record_attestation(
    user_id: str,
    *,
    subject_type: str,
    decision: str,
    title: str = "",
    subject_id: str = "",
    submitted_by: str = "",
    reviewed_by: str = "",
    comment: str = "",
    evidence_ids: list[str] | None = None,
    framework_id: str = "",
    control_id: str = "",
    meta: dict[str, Any] | None = None,
    org_id: str | None = None,
) -> dict[str, Any]:
    """Record Who/What/When/Evidence/Decision/Comment for an audit trail."""
    ensure_schema()
    from app.tenancy import primary_org_id

    st = (subject_type or "").strip().lower()
    if st not in VALID_SUBJECTS:
        raise ValueError(f"subject_type must be one of {sorted(VALID_SUBJECTS)}")
    dec = (decision or "").strip().lower()
    if dec not in VALID_DECISIONS:
        raise ValueError(f"decision must be one of {sorted(VALID_DECISIONS)}")
    reviewer = (reviewed_by or user_id or "").strip()
    if not reviewer:
        raise ValueError("reviewed_by is required — attestation needs a named person")
    rid = new_id()
    t = now()
    oid = org_id or primary_org_id(user_id)
    eids = [str(x) for x in (evidence_ids or []) if x][:50]
    get_conn().execute(
        """
        INSERT INTO human_attestations
        (id, user_id, org_id, subject_type, subject_id, title, submitted_by,
         reviewed_by, decision, comment, evidence_ids_json, framework_id,
         control_id, meta_json, attested_at, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            rid,
            user_id,
            oid,
            st,
            (subject_id or "")[:120],
            (title or f"{st} {dec}")[:300],
            (submitted_by or "")[:120],
            reviewer[:120],
            dec,
            (comment or "")[:2000],
            json.dumps(eids)[:4000],
            (framework_id or "")[:80],
            (control_id or "")[:80],
            json.dumps(meta or {})[:4000],
            t,
            t,
        ),
    )
    get_conn().commit()
    # Evidence spine claim — human decision is declared evidence
    try:
        from app.services.evidence import record_evidence

        record_evidence(
            user_id,
            entity_type="human_attestation",
            entity_id=rid,
            source="declared",
            summary=(title or f"{st}:{dec}")[:500],
            confidence=0.85,
            detail={
                "attestation_id": rid,
                "subject_type": st,
                "subject_id": subject_id,
                "decision": dec,
                "reviewed_by": reviewer,
                "comment": (comment or "")[:500],
                "evidence_ids": eids,
                "framework_id": framework_id,
                "control_id": control_id,
            },
            verified=True,
            created_by=f"attestation:{reviewer}",
        )
    except Exception:
        pass
    try:
        from app.realtime_events import publish_aliased

        publish_aliased(
            "attestation",
            aliases=["attestation.recorded", "evidence.created"],
            attestation_id=rid,
            subject_type=st,
            decision=dec,
            user_id=user_id,
        )
    except Exception:
        pass
    return get_attestation(user_id, rid) or {"id": rid, "ok": True}


def get_attestation(user_id: str, attestation_id: str) -> dict[str, Any] | None:
    ensure_schema()
    from app.tenancy import row_visible_to_user, tenant_visibility_sql

    where, args = tenant_visibility_sql(user_id)
    row = get_conn().execute(
        f"SELECT * FROM human_attestations WHERE id = ? AND {where}",
        (attestation_id, *args),
    ).fetchone()
    if not row:
        return None
    d = row_to_dict(row)
    if not row_visible_to_user(user_id, d):
        return None
    return _hydrate(d)


def list_attestations(
    user_id: str,
    *,
    subject_type: str = "",
    subject_id: str = "",
    decision: str = "",
    limit: int = 100,
    org_id: str | None = None,
) -> list[dict[str, Any]]:
    ensure_schema()
    from app.tenancy import tenant_visibility_sql

    where, args = tenant_visibility_sql(user_id, org_id=org_id)
    q = f"SELECT * FROM human_attestations WHERE {where}"
    if subject_type:
        q += " AND subject_type = ?"
        args.append(subject_type)
    if subject_id:
        q += " AND subject_id = ?"
        args.append(subject_id)
    if decision:
        q += " AND decision = ?"
        args.append(decision)
    q += " ORDER BY attested_at DESC LIMIT ?"
    args.append(max(1, min(limit, 500)))
    return [_hydrate(row_to_dict(r)) for r in get_conn().execute(q, args).fetchall()]


def _hydrate(d: dict[str, Any]) -> dict[str, Any]:
    try:
        d["evidence_ids"] = json.loads(d.get("evidence_ids_json") or "[]")
    except Exception:
        d["evidence_ids"] = []
    try:
        d["meta"] = json.loads(d.get("meta_json") or "{}")
    except Exception:
        d["meta"] = {}
    d["honesty"] = (
        "Human attestation records an organizational decision with named "
        "reviewer and timestamp — not an external certification."
    )
    return d
