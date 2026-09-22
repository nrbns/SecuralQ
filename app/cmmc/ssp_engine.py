"""CMMC SSP engine — implementation statements + evidence matrix per requirement.

Builds on live_ssp (never invents statements). Adds Examine/Interview/Test
matrix, objective rollup, and last-verified timestamps.

Honesty: not a certified System Security Plan; export/review still required.
"""

from __future__ import annotations

from typing import Any

from app.cmmc.objectives import get_control_assessment, seed_objectives_for_framework
from app.cmmc.readiness import control_readiness_confidence
from app.cmmc.schema import ensure_cmmc_assessment_schema
from app.controls.catalog import list_framework_controls
from app.db import get_conn, now, row_to_dict
from app.services.live_ssp import LIVE_SSP_DISCLAIMER, live_ssp_snapshot


def _stored_implementation(user_id: str, framework_id: str, control_id: str) -> dict[str, Any] | None:
    ensure_cmmc_assessment_schema()
    row = get_conn().execute(
        """
        SELECT * FROM cmmc_ssp_implementations
        WHERE user_id = ? AND framework_id = ? AND control_id = ?
        """,
        (user_id, framework_id, control_id),
    ).fetchone()
    return row_to_dict(row) if row else None


def upsert_implementation_statement(
    user_id: str,
    *,
    framework_id: str,
    control_id: str,
    statement: str,
    responsibilities: str = "",
    people: str = "",
    processes: str = "",
    technology: str = "",
    external_services: str = "",
    connections: str = "",
    org_id: str | None = None,
) -> dict[str, Any]:
    """Persist how the org implements a requirement (human-authored)."""
    ensure_cmmc_assessment_schema()
    from app.db import new_id
    from app.tenancy import primary_org_id

    if not (statement or "").strip():
        raise ValueError("implementation statement is required")
    oid = org_id or primary_org_id(user_id)
    t = now()
    existing = get_conn().execute(
        """
        SELECT id FROM cmmc_ssp_implementations
        WHERE user_id = ? AND framework_id = ? AND control_id = ?
        """,
        (user_id, framework_id, control_id),
    ).fetchone()
    if existing:
        get_conn().execute(
            """
            UPDATE cmmc_ssp_implementations SET
                statement = ?, responsibilities = ?, people = ?, processes = ?,
                technology = ?, external_services = ?, connections = ?,
                updated_at = ?, org_id = COALESCE(?, org_id)
            WHERE id = ?
            """,
            (
                statement[:8000],
                responsibilities[:2000],
                people[:2000],
                processes[:2000],
                technology[:2000],
                external_services[:2000],
                connections[:2000],
                t,
                oid,
                existing["id"],
            ),
        )
        get_conn().commit()
        return get_control_ssp_pack(user_id, framework_id, control_id)
    rid = new_id()
    get_conn().execute(
        """
        INSERT INTO cmmc_ssp_implementations
        (id, user_id, org_id, framework_id, control_id, statement, responsibilities,
         people, processes, technology, external_services, connections, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            rid,
            user_id,
            oid,
            framework_id,
            control_id,
            statement[:8000],
            responsibilities[:2000],
            people[:2000],
            processes[:2000],
            technology[:2000],
            external_services[:2000],
            connections[:2000],
            t,
            t,
        ),
    )
    get_conn().commit()
    return get_control_ssp_pack(user_id, framework_id, control_id)


def get_control_ssp_pack(
    user_id: str,
    framework_id: str,
    control_id: str,
) -> dict[str, Any]:
    """One requirement: How implemented + technical/doc/test/interview evidence + status."""
    ensure_cmmc_assessment_schema()
    assessment = get_control_assessment(user_id, framework_id, control_id)
    stored = _stored_implementation(user_id, framework_id, control_id)
    methods = assessment.get("method_evidence") or []
    examine = [m for m in methods if m.get("method") == "examine"]
    interview = [m for m in methods if m.get("method") == "interview"]
    test = [m for m in methods if m.get("method") == "test"]

    last_verified = None
    for m in methods:
        ca = m.get("collected_at")
        if ca is not None and (last_verified is None or ca > last_verified):
            last_verified = ca

    ssp_live = assessment.get("live_ssp") or {}
    auto_summary = ssp_live.get("implementation_summary") or ssp_live.get("evidence_status")
    if stored and stored.get("statement"):
        implementation = {
            "source": "authored",
            "statement": stored["statement"],
            "responsibilities": stored.get("responsibilities") or "",
            "people": stored.get("people") or "",
            "processes": stored.get("processes") or "",
            "technology": stored.get("technology") or "",
            "external_services": stored.get("external_services") or "",
            "connections": stored.get("connections") or "",
            "updated_at": stored.get("updated_at"),
        }
    else:
        implementation = {
            "source": "derived",
            "statement": auto_summary
            or "No authored implementation statement — derive from evidence or write one.",
            "responsibilities": "",
            "people": "",
            "processes": "",
            "technology": "",
            "external_services": "",
            "connections": "",
            "updated_at": None,
        }

    confidence = control_readiness_confidence(user_id, framework_id, control_id)

    return {
        "ok": True,
        "framework_id": framework_id,
        "control_id": control_id,
        "current_status": assessment.get("rollup_status"),
        "implementation": implementation,
        "evidence_matrix": {
            "document_examine": examine,
            "interview": interview,
            "technical_test": test,
        },
        "objectives": assessment.get("objectives"),
        "live_ssp": ssp_live,
        "last_verified": last_verified,
        "readiness_confidence": confidence,
        "poam_policy": assessment.get("poam_policy"),
        "computed_at": now(),
        "disclaimer": LIVE_SSP_DISCLAIMER,
    }


def ssp_engine_snapshot(
    user_id: str,
    framework_id: str = "cmmc_l2",
) -> dict[str, Any]:
    """Full SSP engine view: environment + per-control packs (summarized)."""
    seed_objectives_for_framework(framework_id)
    live = live_ssp_snapshot(user_id, framework_id)

    # CUI program boundary
    cui = []
    try:
        from app.cmmc.cui_program import list_cui_programs

        cui = list_cui_programs(user_id)
    except Exception:
        cui = []

    controls_out = []
    for c in list_framework_controls(framework_id):
        pack = get_control_ssp_pack(user_id, framework_id, c.id)
        impl = pack.get("implementation") or {}
        conf = pack.get("readiness_confidence") or {}
        controls_out.append(
            {
                "control_id": c.id,
                "title": c.title,
                "domain": c.domain,
                "current_status": pack.get("current_status"),
                "implementation_source": impl.get("source"),
                "implementation_preview": (impl.get("statement") or "")[:240],
                "last_verified": pack.get("last_verified"),
                "readiness_band": (conf.get("overall") or {}).get("band"),
                "evidence_counts": {
                    "examine": len((pack.get("evidence_matrix") or {}).get("document_examine") or []),
                    "interview": len((pack.get("evidence_matrix") or {}).get("interview") or []),
                    "test": len((pack.get("evidence_matrix") or {}).get("technical_test") or []),
                },
            }
        )

    return {
        "ok": True,
        "framework_id": framework_id,
        "system": live.get("environment"),
        "cui_programs": cui,
        "controls_total": live.get("controls_total"),
        "live_counts": live.get("counts"),
        "controls": controls_out,
        "last_synchronized": now(),
        "disclaimer": LIVE_SSP_DISCLAIMER,
    }
