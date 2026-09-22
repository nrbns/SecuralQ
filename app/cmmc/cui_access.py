"""CUI-aware access helpers — enforce classification on evidence API, not UI hiding.

Honesty: local ACL based on CUI program membership / roles. Not a substitute
for enterprise ABAC/SSO identity providers.
"""

from __future__ import annotations

import json
from typing import Any

from app.cmmc.schema import ensure_cmmc_assessment_schema
from app.db import get_conn, now, row_to_dict

# Roles that may read CUI-classified evidence when assigned to a program
CUI_READER_ROLES = frozenset(
    {"cmmc_team", "security_admin", "authorized_auditor", "admin", "owner"}
)


def classify_evidence(
    user_id: str,
    evidence_id: str,
    *,
    classification: str,
    cui_program_id: str = "",
    allowed_roles: list[str] | None = None,
    org_id: str | None = None,
) -> dict[str, Any]:
    """Stamp evidence with CUI classification + allowed roles."""
    ensure_cmmc_assessment_schema()
    from app.db import new_id
    from app.tenancy import primary_org_id

    cls = (classification or "internal").strip().lower()
    if cls not in {"public", "internal", "cui", "fci", "restricted"}:
        raise ValueError("classification must be public|internal|cui|fci|restricted")
    oid = org_id or primary_org_id(user_id)
    roles = allowed_roles or list(CUI_READER_ROLES)
    t = now()
    existing = get_conn().execute(
        "SELECT id FROM cmmc_evidence_classification WHERE evidence_id = ? AND user_id = ?",
        (evidence_id, user_id),
    ).fetchone()
    if existing:
        get_conn().execute(
            """
            UPDATE cmmc_evidence_classification SET
                classification = ?, cui_program_id = ?, allowed_roles_json = ?,
                updated_at = ?, org_id = COALESCE(?, org_id)
            WHERE id = ?
            """,
            (
                cls,
                cui_program_id or "",
                json.dumps(roles)[:2000],
                t,
                oid,
                existing["id"],
            ),
        )
        get_conn().commit()
        return get_evidence_classification(user_id, evidence_id) or {"id": existing["id"]}
    rid = new_id()
    get_conn().execute(
        """
        INSERT INTO cmmc_evidence_classification
        (id, user_id, org_id, evidence_id, classification, cui_program_id,
         allowed_roles_json, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            rid,
            user_id,
            oid,
            evidence_id,
            cls,
            cui_program_id or "",
            json.dumps(roles)[:2000],
            t,
            t,
        ),
    )
    get_conn().commit()
    return get_evidence_classification(user_id, evidence_id) or {"id": rid}


def get_evidence_classification(user_id: str, evidence_id: str) -> dict[str, Any] | None:
    ensure_cmmc_assessment_schema()
    row = get_conn().execute(
        "SELECT * FROM cmmc_evidence_classification WHERE evidence_id = ? AND user_id = ?",
        (evidence_id, user_id),
    ).fetchone()
    if not row:
        return None
    d = row_to_dict(row)
    try:
        d["allowed_roles"] = json.loads(d.get("allowed_roles_json") or "[]")
    except Exception:
        d["allowed_roles"] = []
    return d


def user_may_access_evidence(
    user_id: str,
    evidence_id: str,
    *,
    user_roles: list[str] | None = None,
) -> dict[str, Any]:
    """API-enforced check. Unclassified evidence → allow (tenant scoping still applies)."""
    cls = get_evidence_classification(user_id, evidence_id)
    if not cls:
        return {"allowed": True, "reason": "unclassified", "classification": None}
    classification = (cls.get("classification") or "internal").lower()
    if classification in {"public", "internal"}:
        return {"allowed": True, "reason": "non_cui", "classification": classification}

    roles = {r.strip().lower() for r in (user_roles or []) if r}
    # Owner of the evidence row always allowed
    try:
        from app.services.evidence import get_evidence

        ev = get_evidence(user_id, evidence_id)
        if ev and ev.get("user_id") == user_id:
            return {"allowed": True, "reason": "owner", "classification": classification}
    except Exception:
        pass

    allowed = {r.strip().lower() for r in (cls.get("allowed_roles") or [])}
    if roles & allowed or roles & CUI_READER_ROLES:
        return {"allowed": True, "reason": "role_match", "classification": classification}
    # If no explicit roles on request, deny CUI (fail closed for API gate)
    if not roles:
        return {
            "allowed": False,
            "reason": "cui_requires_role",
            "classification": classification,
            "required_roles": sorted(allowed or CUI_READER_ROLES),
        }
    return {
        "allowed": False,
        "reason": "role_denied",
        "classification": classification,
        "required_roles": sorted(allowed or CUI_READER_ROLES),
    }


def require_cui_access(
    user_id: str,
    evidence_id: str,
    *,
    user_roles: list[str] | None = None,
) -> None:
    """Raise PermissionError if CUI evidence access denied."""
    result = user_may_access_evidence(user_id, evidence_id, user_roles=user_roles)
    if not result.get("allowed"):
        raise PermissionError(
            f"CUI evidence access denied ({result.get('reason')}); "
            f"required_roles={result.get('required_roles')}"
        )
