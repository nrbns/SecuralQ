"""Per-framework compliance attestation tracking -- the generalized version
of app.services.cmmc_affirmation (SPRS affirmation, cmmc_l2-only) extended
to every framework in the catalog.

cmmc_l2 already has a dedicated, purpose-built system (app.services.cmmc_affirmation
/ /api/cmmc/affirmations) that models the official DoD SPRS score range
(-203..110) and the Level 1 vs Level 2 cadence split exactly -- that module
is untouched and remains the system of record for CMMC/SPRS. This module
covers the other frameworks, each of which has its own real-world attestation
concept and cadence instead of a generic "affirmation":

  - iso27001 / iso27701 : management review sign-off, annual; recertification
                           audit, 3 years (ISO/IEC 17021-1 surveillance cycle)
  - soc2                 : Type II report issuance, annual observation period
  - pci_dss              : SAQ / Attestation of Compliance (AOC), annual
                           (quarterly ASV scans are a separate technical
                           control, not modeled as an attestation cycle here)
  - hipaa                : Security Risk Assessment sign-off -- HIPAA sets no
                           fixed interval; annual is the HHS-recommended
                           baseline, disclosed as such rather than presented
                           as a legal requirement
  - gdpr                 : Article 32 / RoPA review sign-off -- GDPR sets no
                           fixed interval either; annual or on material change
                           is standard practice, disclosed as such
  - nis2                 : risk-management measures review sign-off -- cadence
                           varies by EU member-state transposition; annual
                           internal review is a common baseline, disclosed as
                           not an official fixed deadline
  - everything else       : generic internal control review sign-off, annual,
    (cis_controls, owasp_asvs,   with no external attestation body
     owasp_top10, nist_csf,
     nist_800_53, nist_800_171)

Every write here is a fact the user typed in (attesting official, assessment
date, optional notes) -- SecuraIQ computes only the deterministic calendar-math
due dates from the chosen cadence. No score is recorded for any framework in
this module (only cmmc_l2's dedicated system tracks a numeric SPRS score,
because only that catalog carries the official DoD point weights needed to
compute one) -- and no attestation here is ever presented as accepted by, or
submitted to, any external authority, auditor, or certification body.
"""

from __future__ import annotations

from typing import Any

from app.db import get_conn, new_id, now, row_to_dict

DAY = 86400.0
ANNUAL_DAYS = 365
RECERT_CYCLE_DAYS = 3 * 365

# Per-framework attestation identity and cadence. `affirmation_cycle_days` is
# the periodic sign-off (e.g. annual management review); `reassessment_cycle_days`
# is the deeper recurring assessment/audit (equal to the affirmation cycle for
# frameworks that don't distinguish the two). `mandated` is False wherever the
# cadence is industry practice rather than a fixed legal/standard deadline --
# surfaced to the user rather than presented as an official requirement.
FRAMEWORK_ATTESTATION_PROFILES: dict[str, dict[str, Any]] = {
    "iso27001": {
        "attestation_label": "Management review sign-off",
        "reassessment_label": "Recertification / surveillance audit",
        "affirmation_cycle_days": ANNUAL_DAYS,
        "reassessment_cycle_days": RECERT_CYCLE_DAYS,
        "mandated": True,
        "cadence_note": "Annual management review (ISO/IEC 27001 clause 9.3) plus a 3-year certification cycle with annual surveillance audits (ISO/IEC 17021-1) once certified.",
    },
    "iso27701": {
        "attestation_label": "Management review sign-off",
        "reassessment_label": "Recertification / surveillance audit",
        "affirmation_cycle_days": ANNUAL_DAYS,
        "reassessment_cycle_days": RECERT_CYCLE_DAYS,
        "mandated": True,
        "cadence_note": "Same management-review and 3-year certification cycle as ISO/IEC 27001, applied to the PIMS extension.",
    },
    "soc2": {
        "attestation_label": "Type II report issuance",
        "reassessment_label": "Type II observation period",
        "affirmation_cycle_days": ANNUAL_DAYS,
        "reassessment_cycle_days": ANNUAL_DAYS,
        "mandated": False,
        "cadence_note": "SOC 2 has no fixed legal interval -- annual Type II reports covering a 6-12 month observation period are standard market practice.",
    },
    "pci_dss": {
        "attestation_label": "SAQ / Attestation of Compliance (AOC)",
        "reassessment_label": "Annual PCI DSS assessment",
        "affirmation_cycle_days": ANNUAL_DAYS,
        "reassessment_cycle_days": ANNUAL_DAYS,
        "mandated": True,
        "cadence_note": "PCI DSS requires annual validation (SAQ or QSA assessment plus AOC). Quarterly ASV external vulnerability scans are a separate technical requirement, not tracked as an attestation cycle here.",
    },
    "hipaa": {
        "attestation_label": "Security Risk Assessment sign-off",
        "reassessment_label": "Security Risk Assessment",
        "affirmation_cycle_days": ANNUAL_DAYS,
        "reassessment_cycle_days": ANNUAL_DAYS,
        "mandated": False,
        "cadence_note": "HIPAA (45 CFR 164.308(a)(1)) requires periodic risk assessment but sets no fixed interval -- annual, or upon significant change, is the HHS-recommended baseline.",
    },
    "gdpr": {
        "attestation_label": "Article 32 / RoPA review sign-off",
        "reassessment_label": "Processing register and security-measures review",
        "affirmation_cycle_days": ANNUAL_DAYS,
        "reassessment_cycle_days": ANNUAL_DAYS,
        "mandated": False,
        "cadence_note": "GDPR sets no fixed review interval -- annual review, or review on material change to processing, is standard practice.",
    },
    "nis2": {
        "attestation_label": "Risk-management measures review sign-off",
        "reassessment_label": "Article 21 risk-management review",
        "affirmation_cycle_days": ANNUAL_DAYS,
        "reassessment_cycle_days": ANNUAL_DAYS,
        "mandated": False,
        "cadence_note": "NIS2 cadence varies by EU member-state transposition -- annual internal review is a common baseline, not a single EU-wide fixed deadline.",
    },
    "nist_800_53": {
        "attestation_label": "Authorizing Official risk-acceptance",
        "reassessment_label": "Security authorization reassessment",
        "affirmation_cycle_days": ANNUAL_DAYS,
        "reassessment_cycle_days": RECERT_CYCLE_DAYS,
        "mandated": True,
        "cadence_note": "Traditional 3-year reauthorization (ATO) with annual continuous-monitoring attestation in between; many agencies now use ongoing authorization instead of a fixed 3-year cycle.",
    },
    "nist_800_171": {
        "attestation_label": "DFARS 252.204-7020 self-assessment affirmation",
        "reassessment_label": "NIST SP 800-171 self-assessment",
        "affirmation_cycle_days": ANNUAL_DAYS,
        "reassessment_cycle_days": RECERT_CYCLE_DAYS,
        "mandated": True,
        "cadence_note": "DFARS 252.204-7020 requires a current NIST SP 800-171 assessment score in SPRS, valid for 3 years unless superseded. SecuraIQ does not yet compute a scored preview for this framework id (see cmmc_l2 for the CMMC-branded, SPRS-scored version of the same 110 practices) -- record the score you calculated separately in notes if needed.",
    },
}

DEFAULT_PROFILE: dict[str, Any] = {
    "attestation_label": "Internal control review sign-off",
    "reassessment_label": "Internal control assessment",
    "affirmation_cycle_days": ANNUAL_DAYS,
    "reassessment_cycle_days": ANNUAL_DAYS,
    "mandated": False,
    "cadence_note": "No external attestation body for this framework in SecuraIQ -- annual internal review is a reasonable default cadence, adjust to your own governance calendar.",
}


def attestation_profile(framework_id: str) -> dict[str, Any]:
    return dict(FRAMEWORK_ATTESTATION_PROFILES.get(framework_id, DEFAULT_PROFILE))


def ensure_schema() -> None:
    c = get_conn()
    c.execute(
        """
        CREATE TABLE IF NOT EXISTS compliance_attestations (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL DEFAULT 'local',
            org_id TEXT,
            framework_id TEXT NOT NULL,
            assessment_id TEXT,
            assessment_date REAL NOT NULL,
            attesting_official TEXT NOT NULL,
            next_affirmation_due REAL NOT NULL,
            next_reassessment_due REAL NOT NULL,
            notes TEXT NOT NULL DEFAULT '',
            created_at REAL NOT NULL,
            updated_at REAL NOT NULL
        )
        """
    )
    c.execute(
        "CREATE INDEX IF NOT EXISTS idx_compliance_attest_user "
        "ON compliance_attestations(user_id, framework_id, assessment_date DESC)"
    )
    c.commit()


def _validate(*, assessment_date: float, attesting_official: str) -> None:
    if not attesting_official.strip():
        raise ValueError("attesting_official is required -- an attestation needs a named responsible person")
    ts = now()
    if assessment_date > ts + DAY:  # small grace window for clock skew
        raise ValueError("assessment_date cannot be in the future")


def create_attestation(
    user_id: str,
    *,
    framework_id: str,
    assessment_date: float,
    attesting_official: str,
    assessment_id: str | None = None,
    notes: str = "",
    org_id: str | None = None,
) -> dict[str, Any]:
    from app.tenancy import primary_org_id

    framework_id = (framework_id or "").strip()
    if not framework_id:
        raise ValueError("framework_id is required")
    _validate(assessment_date=assessment_date, attesting_official=attesting_official)
    ensure_schema()
    oid = org_id or primary_org_id(user_id)

    profile = attestation_profile(framework_id)
    next_affirmation_due = assessment_date + profile["affirmation_cycle_days"] * DAY
    next_reassessment_due = assessment_date + profile["reassessment_cycle_days"] * DAY

    aid = new_id()
    ts = now()
    c = get_conn()
    c.execute(
        """
        INSERT INTO compliance_attestations
        (id, user_id, org_id, framework_id, assessment_id, assessment_date,
         attesting_official, next_affirmation_due, next_reassessment_due, notes, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            aid, user_id, oid, framework_id, assessment_id, assessment_date,
            attesting_official.strip()[:200], next_affirmation_due, next_reassessment_due,
            (notes or "").strip()[:4000], ts, ts,
        ),
    )
    c.commit()
    try:
        from app.db import audit

        audit(
            "compliance_attestation_create",
            user_id,
            {"id": aid, "framework_id": framework_id, "attesting_official": attesting_official.strip(), "org_id": oid},
        )
    except Exception:
        pass
    try:
        from app.services.evidence import record_evidence

        record_evidence(
            user_id,
            entity_type="compliance_attestation",
            entity_id=aid,
            source="declared",
            summary=f"{profile['attestation_label']} for {framework_id} by {attesting_official.strip()}",
            detail={"framework_id": framework_id, "assessment_id": assessment_id},
            created_by=user_id,
            org_id=oid,
        )
    except Exception:
        pass
    return get_attestation(user_id, aid)


def _decorate(d: dict[str, Any]) -> dict[str, Any]:
    ts = now()
    d["profile"] = attestation_profile(d.get("framework_id") or "")
    d["affirmation_overdue"] = bool(d.get("next_affirmation_due") and float(d["next_affirmation_due"]) <= ts)
    d["reassessment_overdue"] = bool(d.get("next_reassessment_due") and float(d["next_reassessment_due"]) <= ts)
    d["days_until_affirmation_due"] = (
        round((float(d["next_affirmation_due"]) - ts) / DAY, 1) if d.get("next_affirmation_due") else None
    )
    d["days_until_reassessment_due"] = (
        round((float(d["next_reassessment_due"]) - ts) / DAY, 1) if d.get("next_reassessment_due") else None
    )
    return d


def get_attestation(user_id: str, attestation_id: str) -> dict[str, Any] | None:
    from app.tenancy import row_visible_to_user

    ensure_schema()
    row = get_conn().execute(
        "SELECT * FROM compliance_attestations WHERE id = ?", (attestation_id,)
    ).fetchone()
    if not row:
        return None
    d = row_to_dict(row)
    if not row_visible_to_user(user_id, d):
        return None
    return _decorate(d)


def list_attestations(
    user_id: str, framework_id: str | None = None, *, org_id: str | None = None
) -> list[dict[str, Any]]:
    from app.tenancy import tenant_visibility_sql

    ensure_schema()
    where, args = tenant_visibility_sql(user_id, org_id=org_id)
    q = f"SELECT * FROM compliance_attestations WHERE {where}"
    if framework_id:
        q += " AND framework_id = ?"
        args.append(framework_id)
    q += " ORDER BY assessment_date DESC"
    rows = get_conn().execute(q, args).fetchall()
    return [_decorate(row_to_dict(r)) for r in rows]


def latest_attestation(user_id: str, framework_id: str, *, org_id: str | None = None) -> dict[str, Any] | None:
    rows = list_attestations(user_id, framework_id=framework_id, org_id=org_id)
    return rows[0] if rows else None


def delete_attestation(user_id: str, attestation_id: str) -> bool:
    if not get_attestation(user_id, attestation_id):
        return False
    ensure_schema()
    c = get_conn()
    cur = c.execute("DELETE FROM compliance_attestations WHERE id = ?", (attestation_id,))
    c.commit()
    if cur.rowcount:
        try:
            from app.db import audit

            audit("compliance_attestation_delete", user_id, {"id": attestation_id})
        except Exception:
            pass
        return True
    return False
