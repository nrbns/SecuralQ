"""CMMC / SPRS self-assessment affirmation tracking.

This is a record of what the organization affirms into the DoD's Supplier
Performance Risk System (SPRS) -- it is NOT SecuraIQ certifying anything.
SecuraIQ cannot submit to SPRS, cannot verify a score against a live
assessment on the government's behalf, and does not decide compliance.
What this module does is give the user a durable, auditable place to record
"we affirmed this score on this date, due again on this date" instead of
that fact living in someone's email or nowhere at all -- and to compute the
two real due dates (next annual affirmation, next full self-assessment) from
calendar math, per the current DoD guidance already captured in
data/knowledge/compliance_frameworks.md:

  - Level 1 (FAR 52.204-21, 15 practices): annual self-assessment + annual
    affirmation into SPRS. No SPRS score is submitted for Level 1.
  - Level 2 (110 NIST SP 800-171 Rev 2 practices): self-assessment every
    3 years + annual affirmation into SPRS in between. A numeric score
    (-203 to 110) is submitted.

Every write here is a self-reported fact the user typed in (score,
assessment date, affirming official) -- never inferred or fabricated by
SecuraIQ. The optional `assessment_id` link, when present, ties the record
back to a real SecuraIQ gap assessment so the affirmed score can be
cross-checked against that assessment's computed SPRS preview
(app.services.cmmc_documents.compute_sprs_preview) -- but the affirmed score
itself is whatever the user enters, since only they can attest to the full
DoD assessment methodology (including partial-credit rules this app does
not model).
"""

from __future__ import annotations

from typing import Any

from app.db import get_conn, new_id, now, row_to_dict

VALID_LEVELS = {"Level 1", "Level 2"}
DAY = 86400.0
ANNUAL_DAYS = 365
LEVEL2_ASSESSMENT_CYCLE_DAYS = 3 * 365
# Official DoD scale for a Level 2 self-assessment score (32 CFR 170 / DoD
# NIST SP 800-171 Assessment Methodology): perfect score 110, floor -203.
MIN_LEVEL2_SCORE = -203
MAX_LEVEL2_SCORE = 110


def ensure_schema() -> None:
    c = get_conn()
    c.execute(
        """
        CREATE TABLE IF NOT EXISTS cmmc_affirmations (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL DEFAULT 'local',
            org_id TEXT,
            framework_id TEXT NOT NULL DEFAULT 'cmmc_l2',
            assessment_id TEXT,
            level TEXT NOT NULL,
            score INTEGER,
            assessment_date REAL NOT NULL,
            affirming_official TEXT NOT NULL,
            next_affirmation_due REAL NOT NULL,
            next_assessment_due REAL NOT NULL,
            notes TEXT NOT NULL DEFAULT '',
            superseded_by TEXT,
            created_at REAL NOT NULL,
            updated_at REAL NOT NULL
        )
        """
    )
    c.execute("CREATE INDEX IF NOT EXISTS idx_cmmc_affirm_user ON cmmc_affirmations(user_id, assessment_date DESC)")
    c.commit()


def _validate(
    *,
    level: str,
    score: int | None,
    assessment_date: float,
    affirming_official: str,
) -> tuple[str, int | None]:
    level = (level or "").strip()
    if level not in VALID_LEVELS:
        raise ValueError(f"level must be one of {sorted(VALID_LEVELS)}")
    if not affirming_official.strip():
        raise ValueError("affirming_official is required -- SPRS affirmation requires a named senior official")
    ts = now()
    if assessment_date > ts + DAY:  # small grace window for clock skew
        raise ValueError("assessment_date cannot be in the future")

    if level == "Level 1":
        if score is not None:
            raise ValueError("Level 1 has no SPRS score -- leave score empty")
        return level, None

    # Level 2 requires a real score in the official -203..110 range.
    if score is None:
        raise ValueError("score is required for a Level 2 affirmation")
    if not (MIN_LEVEL2_SCORE <= score <= MAX_LEVEL2_SCORE):
        raise ValueError(f"score must be between {MIN_LEVEL2_SCORE} and {MAX_LEVEL2_SCORE}")
    return level, score


def create_affirmation(
    user_id: str,
    *,
    level: str,
    assessment_date: float,
    affirming_official: str,
    score: int | None = None,
    framework_id: str = "cmmc_l2",
    assessment_id: str | None = None,
    notes: str = "",
    org_id: str | None = None,
) -> dict[str, Any]:
    level, score = _validate(
        level=level, score=score, assessment_date=assessment_date, affirming_official=affirming_official
    )
    ensure_schema()

    next_affirmation_due = assessment_date + ANNUAL_DAYS * DAY
    cycle_days = ANNUAL_DAYS if level == "Level 1" else LEVEL2_ASSESSMENT_CYCLE_DAYS
    next_assessment_due = assessment_date + cycle_days * DAY

    aid = new_id()
    ts = now()
    c = get_conn()
    c.execute(
        """
        INSERT INTO cmmc_affirmations
        (id, user_id, org_id, framework_id, assessment_id, level, score, assessment_date,
         affirming_official, next_affirmation_due, next_assessment_due, notes, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            aid, user_id, org_id, framework_id.strip() or "cmmc_l2", assessment_id, level, score,
            assessment_date, affirming_official.strip()[:200], next_affirmation_due, next_assessment_due,
            (notes or "").strip()[:4000], ts, ts,
        ),
    )
    c.commit()
    try:
        from app.db import audit

        audit(
            "cmmc_affirmation_create",
            user_id,
            {"id": aid, "level": level, "score": score, "framework_id": framework_id},
        )
    except Exception:
        pass
    try:
        from app.services.evidence import record_evidence

        record_evidence(
            user_id,
            entity_type="cmmc_affirmation",
            entity_id=aid,
            source="declared",
            summary=f"{level} self-assessment affirmed by {affirming_official.strip()}"
            + (f" (score {score})" if score is not None else ""),
            detail={"level": level, "score": score, "framework_id": framework_id, "assessment_id": assessment_id},
            created_by=user_id,
        )
    except Exception:
        pass
    return get_affirmation(user_id, aid)


def _decorate(d: dict[str, Any]) -> dict[str, Any]:
    ts = now()
    d["affirmation_overdue"] = bool(d.get("next_affirmation_due") and float(d["next_affirmation_due"]) <= ts)
    d["assessment_overdue"] = bool(d.get("next_assessment_due") and float(d["next_assessment_due"]) <= ts)
    d["days_until_affirmation_due"] = (
        round((float(d["next_affirmation_due"]) - ts) / DAY, 1) if d.get("next_affirmation_due") else None
    )
    d["days_until_assessment_due"] = (
        round((float(d["next_assessment_due"]) - ts) / DAY, 1) if d.get("next_assessment_due") else None
    )
    return d


def get_affirmation(user_id: str, affirmation_id: str) -> dict[str, Any] | None:
    ensure_schema()
    row = get_conn().execute(
        "SELECT * FROM cmmc_affirmations WHERE id = ? AND user_id = ?", (affirmation_id, user_id)
    ).fetchone()
    if not row:
        return None
    return _decorate(row_to_dict(row))


def list_affirmations(user_id: str, framework_id: str | None = None) -> list[dict[str, Any]]:
    ensure_schema()
    c = get_conn()
    if framework_id:
        rows = c.execute(
            "SELECT * FROM cmmc_affirmations WHERE user_id = ? AND framework_id = ? ORDER BY assessment_date DESC",
            (user_id, framework_id),
        ).fetchall()
    else:
        rows = c.execute(
            "SELECT * FROM cmmc_affirmations WHERE user_id = ? ORDER BY assessment_date DESC", (user_id,)
        ).fetchall()
    return [_decorate(row_to_dict(r)) for r in rows]


def latest_affirmation(user_id: str, framework_id: str = "cmmc_l2") -> dict[str, Any] | None:
    rows = list_affirmations(user_id, framework_id=framework_id)
    return rows[0] if rows else None


def delete_affirmation(user_id: str, affirmation_id: str) -> bool:
    ensure_schema()
    c = get_conn()
    cur = c.execute("DELETE FROM cmmc_affirmations WHERE id = ? AND user_id = ?", (affirmation_id, user_id))
    c.commit()
    if cur.rowcount:
        try:
            from app.db import audit

            audit("cmmc_affirmation_delete", user_id, {"id": affirmation_id})
        except Exception:
            pass
        return True
    return False
