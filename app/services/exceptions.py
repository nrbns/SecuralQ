"""Compliance Exceptions -- a risk-accepted deviation from a control, tracked
as a real, bounded, auditable record instead of a silent gap.

The one rule every function here enforces: **no exception is ever open-ended.**
"Exception forever" is exactly the failure mode this module exists to prevent
-- a control marked "missing" quietly becomes "well, we accepted that risk"
with no owner, no review date, and no automatic expiry, and five years later
nobody remembers why. So:

  - `expiry` is REQUIRED on every exception -- the DB column is NOT NULL with
    no default, and create/update both reject a missing or past-the-cap
    expiry before anything is written.
  - An exception cannot be requested for longer than `MAX_EXCEPTION_DAYS`
    (default 365) in one grant. A team that needs longer must explicitly
    renew it, which re-runs the same validation and leaves an audit trail
    of each renewal rather than one open-ended record.
  - Expiry is never "soft" -- nothing here silently extends it. A row past
    its `expiry` is always reported as expired (`expired: True` in every
    read), regardless of its stored `status`, so an approved-but-lapsed
    exception can't be mistaken for current coverage.

Status vocabulary (the *approval* lifecycle, independent of expiry):
  pending_approval -- default on creation; not yet a valid risk acceptance
  approved          -- a named approver signed off (see approve_exception)
  rejected          -- an approver declined it
  revoked           -- an approved exception ended early, before its expiry

An exception only counts as real, current coverage for a control when
status == "approved" AND not expired -- callers (e.g. the Compliance
Center) must check both.
"""

from __future__ import annotations

from typing import Any

from app.db import get_conn, new_id, now

VALID_RISK_LEVELS = {"low", "medium", "high", "critical"}
VALID_STATUSES = {"pending_approval", "approved", "rejected", "revoked"}
MAX_EXCEPTION_DAYS = 365
_UPDATABLE_FIELDS = {
    "title",
    "reason",
    "risk_accepted",
    "risk_level",
    "owner",
    "compensating_controls",
    "framework_id",
    "control_id",
    "expiry",
    "review_date",
}


def ensure_schema() -> None:
    c = get_conn()
    c.execute(
        """
        CREATE TABLE IF NOT EXISTS securaiq_exceptions (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL DEFAULT 'local',
            org_id TEXT,
            title TEXT NOT NULL,
            framework_id TEXT NOT NULL DEFAULT '',
            control_id TEXT NOT NULL DEFAULT '',
            reason TEXT NOT NULL,
            risk_accepted TEXT NOT NULL,
            risk_level TEXT NOT NULL DEFAULT 'medium',
            owner TEXT NOT NULL,
            compensating_controls TEXT NOT NULL DEFAULT '',
            status TEXT NOT NULL DEFAULT 'pending_approval',
            approved_by TEXT NOT NULL DEFAULT '',
            approved_at REAL,
            rejected_reason TEXT NOT NULL DEFAULT '',
            revoked_by TEXT NOT NULL DEFAULT '',
            revoked_at REAL,
            expiry REAL NOT NULL,
            review_date REAL,
            created_by TEXT NOT NULL DEFAULT 'system',
            created_at REAL NOT NULL,
            updated_at REAL NOT NULL
        )
        """
    )
    c.execute("CREATE INDEX IF NOT EXISTS idx_exceptions_user ON securaiq_exceptions(user_id)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_exceptions_control ON securaiq_exceptions(framework_id, control_id)")
    c.commit()


def _validate_expiry(expiry: float | None) -> float:
    if expiry is None:
        raise ValueError("An exception must have an expiry date -- open-ended exceptions are not allowed.")
    expiry = float(expiry)
    ts = now()
    if expiry <= ts:
        raise ValueError("Exception expiry must be in the future.")
    if expiry > ts + MAX_EXCEPTION_DAYS * 86400:
        raise ValueError(
            f"Exceptions cannot be granted for more than {MAX_EXCEPTION_DAYS} days at a time. "
            "Request a renewal closer to expiry instead of a longer initial grant."
        )
    return expiry


def create_exception(
    user_id: str,
    *,
    title: str,
    reason: str,
    risk_accepted: str,
    owner: str,
    expiry: float,
    risk_level: str = "medium",
    framework_id: str = "",
    control_id: str = "",
    compensating_controls: str = "",
    review_date: float | None = None,
    org_id: str | None = None,
    created_by: str = "system",
) -> dict[str, Any]:
    title = (title or "").strip()
    reason = (reason or "").strip()
    risk_accepted = (risk_accepted or "").strip()
    owner = (owner or "").strip()
    if not title:
        raise ValueError("title is required")
    if not reason:
        raise ValueError("reason is required")
    if not risk_accepted:
        raise ValueError("risk_accepted is required -- describe the residual risk being accepted")
    if not owner:
        raise ValueError("owner is required -- an exception with no accountable owner is not a real exception")
    risk_level = (risk_level or "medium").lower()
    if risk_level not in VALID_RISK_LEVELS:
        raise ValueError(f"risk_level must be one of {sorted(VALID_RISK_LEVELS)}")
    expiry_ts = _validate_expiry(expiry)

    ensure_schema()
    eid = new_id()
    ts = now()
    c = get_conn()
    c.execute(
        """
        INSERT INTO securaiq_exceptions
        (id, user_id, org_id, title, framework_id, control_id, reason, risk_accepted, risk_level,
         owner, compensating_controls, status, expiry, review_date, created_by, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending_approval', ?, ?, ?, ?, ?)
        """,
        (
            eid, user_id, org_id, title[:300], framework_id.strip(), control_id.strip(), reason[:4000],
            risk_accepted[:4000], risk_level, owner[:200], (compensating_controls or "").strip()[:4000],
            expiry_ts, review_date, created_by, ts, ts,
        ),
    )
    c.commit()
    try:
        from app.db import audit

        audit("exception_create", user_id, {"exception_id": eid, "title": title, "control_id": control_id})
    except Exception:
        pass
    try:
        from app.services.evidence import record_evidence

        record_evidence(
            user_id,
            entity_type="compliance_exception",
            entity_id=eid,
            source="declared",
            summary=f"Exception requested: {title}",
            detail={"framework_id": framework_id, "control_id": control_id, "risk_level": risk_level},
            created_by=created_by,
        )
    except Exception:
        pass
    return get_exception(user_id, eid)


def _row_to_dict(row: Any) -> dict[str, Any]:
    d = dict(row)
    ts = now()
    d["expired"] = bool(d.get("expiry") and float(d["expiry"]) <= ts)
    d["days_until_expiry"] = round((float(d["expiry"]) - ts) / 86400, 1) if d.get("expiry") else None
    d["is_active_coverage"] = d.get("status") == "approved" and not d["expired"]
    return d


def get_exception(user_id: str, exception_id: str) -> dict[str, Any] | None:
    ensure_schema()
    row = get_conn().execute(
        "SELECT * FROM securaiq_exceptions WHERE id = ? AND user_id = ?", (exception_id, user_id)
    ).fetchone()
    return _row_to_dict(row) if row else None


def list_exceptions(
    user_id: str, *, org_id: str | None = None, status: str | None = None, limit: int = 200
) -> list[dict[str, Any]]:
    ensure_schema()
    from app.tenancy import tenant_visibility_sql

    where, args = tenant_visibility_sql(user_id, org_id=org_id)
    q = f"SELECT * FROM securaiq_exceptions WHERE {where}"
    if status:
        if status not in VALID_STATUSES:
            raise ValueError(f"status must be one of {sorted(VALID_STATUSES)}")
        q += " AND status = ?"
        args.append(status)
    q += " ORDER BY expiry ASC LIMIT ?"
    args.append(max(1, min(limit, 1000)))
    rows = get_conn().execute(q, args).fetchall()
    return [_row_to_dict(r) for r in rows]


def update_exception(user_id: str, exception_id: str, fields: dict[str, Any]) -> dict[str, Any] | None:
    ensure_schema()
    c = get_conn()
    existing = c.execute(
        "SELECT * FROM securaiq_exceptions WHERE id = ? AND user_id = ?", (exception_id, user_id)
    ).fetchone()
    if not existing:
        return None
    updates: dict[str, Any] = {}
    for k, v in fields.items():
        if k not in _UPDATABLE_FIELDS or v is None:
            continue
        if k == "expiry":
            updates[k] = _validate_expiry(v)
        elif k == "risk_level":
            v = str(v).lower()
            if v not in VALID_RISK_LEVELS:
                raise ValueError(f"risk_level must be one of {sorted(VALID_RISK_LEVELS)}")
            updates[k] = v
        elif k in ("title", "reason", "risk_accepted", "owner", "compensating_controls", "framework_id", "control_id"):
            updates[k] = str(v).strip()[:4000]
        else:
            updates[k] = v
    if not updates:
        return get_exception(user_id, exception_id)
    updates["updated_at"] = now()
    set_clause = ", ".join(f"{k} = ?" for k in updates)
    c.execute(
        f"UPDATE securaiq_exceptions SET {set_clause} WHERE id = ? AND user_id = ?",
        (*updates.values(), exception_id, user_id),
    )
    c.commit()
    return get_exception(user_id, exception_id)


def approve_exception(user_id: str, exception_id: str, *, approved_by: str) -> dict[str, Any] | None:
    """An explicit human sign-off -- the only way status becomes 'approved'.
    Re-validates expiry hasn't lapsed between request and approval."""
    ensure_schema()
    existing = get_exception(user_id, exception_id)
    if not existing:
        return None
    if existing["expired"]:
        raise ValueError("Cannot approve an exception whose expiry has already passed -- create a new request.")
    c = get_conn()
    ts = now()
    c.execute(
        "UPDATE securaiq_exceptions SET status = 'approved', approved_by = ?, approved_at = ?, updated_at = ? "
        "WHERE id = ? AND user_id = ?",
        (approved_by[:200], ts, ts, exception_id, user_id),
    )
    c.commit()
    try:
        from app.db import audit

        audit("exception_approve", user_id, {"exception_id": exception_id, "approved_by": approved_by})
    except Exception:
        pass
    try:
        from app.services.evidence import record_evidence

        record_evidence(
            user_id,
            entity_type="compliance_exception",
            entity_id=exception_id,
            source="declared",
            summary=f"Exception approved by {approved_by}",
            confidence=1.0,
            verified=True,
            created_by=approved_by,
        )
    except Exception:
        pass
    return get_exception(user_id, exception_id)


def reject_exception(user_id: str, exception_id: str, *, rejected_by: str, reason: str = "") -> dict[str, Any] | None:
    ensure_schema()
    c = get_conn()
    existing = c.execute(
        "SELECT id FROM securaiq_exceptions WHERE id = ? AND user_id = ?", (exception_id, user_id)
    ).fetchone()
    if not existing:
        return None
    ts = now()
    c.execute(
        "UPDATE securaiq_exceptions SET status = 'rejected', rejected_reason = ?, updated_at = ? "
        "WHERE id = ? AND user_id = ?",
        ((reason or "").strip()[:2000], ts, exception_id, user_id),
    )
    c.commit()
    try:
        from app.db import audit

        audit("exception_reject", user_id, {"exception_id": exception_id, "rejected_by": rejected_by})
    except Exception:
        pass
    return get_exception(user_id, exception_id)


def revoke_exception(user_id: str, exception_id: str, *, revoked_by: str) -> dict[str, Any] | None:
    """End an approved exception early -- the compensating control turned
    out to be insufficient, or the underlying risk was remediated outright."""
    ensure_schema()
    c = get_conn()
    existing = c.execute(
        "SELECT id FROM securaiq_exceptions WHERE id = ? AND user_id = ?", (exception_id, user_id)
    ).fetchone()
    if not existing:
        return None
    ts = now()
    c.execute(
        "UPDATE securaiq_exceptions SET status = 'revoked', revoked_by = ?, revoked_at = ?, updated_at = ? "
        "WHERE id = ? AND user_id = ?",
        (revoked_by[:200], ts, ts, exception_id, user_id),
    )
    c.commit()
    try:
        from app.db import audit

        audit("exception_revoke", user_id, {"exception_id": exception_id, "revoked_by": revoked_by})
    except Exception:
        pass
    return get_exception(user_id, exception_id)


def delete_exception(user_id: str, exception_id: str) -> bool:
    ensure_schema()
    c = get_conn()
    cur = c.execute("DELETE FROM securaiq_exceptions WHERE id = ? AND user_id = ?", (exception_id, user_id))
    c.commit()
    return cur.rowcount > 0


def exceptions_summary(user_id: str, *, org_id: str | None = None) -> dict[str, Any]:
    """Aggregate counts for the Compliance Center / Audit Center -- never
    hardcoded, always a fresh read of the real table."""
    rows = list_exceptions(user_id, org_id=org_id, limit=1000)
    ts = now()
    soon_cutoff = ts + 30 * 86400
    counts = {"pending_approval": 0, "approved": 0, "rejected": 0, "revoked": 0}
    active_coverage = 0
    expired = 0
    expiring_soon = 0
    for r in rows:
        counts[r["status"]] = counts.get(r["status"], 0) + 1
        if r["is_active_coverage"]:
            active_coverage += 1
            if r["expiry"] <= soon_cutoff:
                expiring_soon += 1
        if r["expired"]:
            expired += 1
    return {
        "total": len(rows),
        "by_status": counts,
        "active_coverage": active_coverage,
        "expired": expired,
        "expiring_soon_30d": expiring_soon,
    }
