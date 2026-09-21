"""Assessment objectives — executable Examine/Interview/Test scaffolds per control."""

from __future__ import annotations

import json
from typing import Any

from app.cmmc.schema import ensure_cmmc_assessment_schema
from app.controls.catalog import list_framework_controls
from app.db import get_conn, new_id, now, row_to_dict
from app.gap_analysis import load_framework

METHODS = ("examine", "interview", "test")
VALID_STATUS = frozenset({"unknown", "met", "not_met", "partial", "not_applicable"})

_SEED_DISCLAIMER = (
    "Objective titles are SecuraIQ Examine/Interview/Test scaffolds for assessment "
    "workflow — not verbatim DoD CMMC Assessment Guide determination statements. "
    "Replace/refine with your assessor pack as needed."
)


def seed_objectives_for_framework(
    framework_id: str = "cmmc_l2",
    *,
    force: bool = False,
) -> dict[str, Any]:
    """Idempotent seed: 3 method objectives per catalog control."""
    ensure_cmmc_assessment_schema()
    fw = load_framework(framework_id)
    fid = str(fw.get("id") or framework_id)
    version = str(fw.get("version") or "")
    existing = get_conn().execute(
        "SELECT COUNT(*) AS n FROM cmmc_assessment_objectives WHERE framework_id = ?",
        (fid,),
    ).fetchone()["n"]
    if existing and not force:
        return {"ok": True, "seeded": 0, "existing": int(existing), "note": "already seeded"}

    if force:
        get_conn().execute(
            "DELETE FROM cmmc_assessment_objectives WHERE framework_id = ?", (fid,)
        )
        get_conn().commit()

    t = now()
    n = 0
    method_titles = {
        "examine": "Examine — policies, configs, records, and system outputs",
        "interview": "Interview — roles responsible for implementation",
        "test": "Test — technical or procedural verification",
    }
    for ctrl in list_framework_controls(fid):
        for i, method in enumerate(METHODS):
            oid = f"{fid}:{ctrl.id}:{method[0]}"
            title = f"{method_titles[method]} ({ctrl.id})"
            desc = (
                f"Assessment method scaffold for {ctrl.id} — {ctrl.title}. "
                f"Method={method}. {_SEED_DISCLAIMER}"
            )
            get_conn().execute(
                """
                INSERT OR IGNORE INTO cmmc_assessment_objectives
                (id, framework_id, framework_version, control_id, objective_key, title,
                 description, method, determination_hint, sort_order, seed_source, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'securaiq_scaffold', ?)
                """,
                (
                    oid,
                    fid,
                    version,
                    ctrl.id,
                    method[0],  # e / i / t
                    title[:500],
                    desc[:2000],
                    method,
                    f"Document how {ctrl.id} is implemented; attach evidence via Evidence Spine.",
                    i,
                    t,
                ),
            )
            n += 1
    get_conn().commit()
    return {"ok": True, "seeded": n, "framework_id": fid, "version": version, "disclaimer": _SEED_DISCLAIMER}


def list_objectives(
    framework_id: str,
    *,
    control_id: str = "",
) -> list[dict[str, Any]]:
    ensure_cmmc_assessment_schema()
    q = "SELECT * FROM cmmc_assessment_objectives WHERE framework_id = ?"
    args: list[Any] = [framework_id]
    if control_id:
        q += " AND control_id = ?"
        args.append(control_id)
    q += " ORDER BY control_id, sort_order"
    return [row_to_dict(r) for r in get_conn().execute(q, args).fetchall()]


def set_objective_status(
    user_id: str,
    objective_id: str,
    *,
    status: str,
    evidence_ids: list[str] | None = None,
    reviewer: str = "",
    notes: str = "",
    org_id: str | None = None,
) -> dict[str, Any]:
    ensure_cmmc_assessment_schema()
    st = (status or "unknown").strip().lower()
    if st not in VALID_STATUS:
        raise ValueError(f"status must be one of {sorted(VALID_STATUS)}")
    obj = get_conn().execute(
        "SELECT * FROM cmmc_assessment_objectives WHERE id = ?", (objective_id,)
    ).fetchone()
    if not obj:
        raise ValueError("objective not found — seed framework first")
    from app.tenancy import primary_org_id

    oid = org_id or primary_org_id(user_id)
    t = now()
    rid = new_id()
    # freshness from linked evidence
    fresh = "unknown"
    eids = evidence_ids or []
    if eids:
        try:
            from app.services.evidence import get_evidence

            statuses = []
            for eid in eids[:20]:
                ev = get_evidence(user_id, eid)
                if ev:
                    statuses.append(ev.get("freshness_status") or "fresh")
            if any(s == "expired" for s in statuses):
                fresh = "expired"
            elif any(s == "stale" for s in statuses):
                fresh = "stale"
            elif statuses:
                fresh = "fresh"
        except Exception:
            fresh = "unknown"

    existing = get_conn().execute(
        "SELECT id FROM cmmc_objective_status WHERE user_id = ? AND objective_id = ?",
        (user_id, objective_id),
    ).fetchone()
    if existing:
        get_conn().execute(
            """
            UPDATE cmmc_objective_status SET
                status = ?, evidence_ids_json = ?, reviewer = ?, notes = ?,
                assessed_at = ?, freshness_status = ?, updated_at = ?, org_id = COALESCE(?, org_id)
            WHERE id = ?
            """,
            (
                st,
                json.dumps(eids)[:4000],
                (reviewer or "")[:200],
                (notes or "")[:2000],
                t,
                fresh,
                t,
                oid,
                existing["id"],
            ),
        )
        row_id = existing["id"]
    else:
        get_conn().execute(
            """
            INSERT INTO cmmc_objective_status
            (id, user_id, org_id, framework_id, control_id, objective_id, status,
             evidence_ids_json, reviewer, notes, assessed_at, freshness_status, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                rid,
                user_id,
                oid,
                obj["framework_id"],
                obj["control_id"],
                objective_id,
                st,
                json.dumps(eids)[:4000],
                (reviewer or "")[:200],
                (notes or "")[:2000],
                t,
                fresh,
                t,
            ),
        )
        row_id = rid
    get_conn().commit()
    try:
        from app.realtime_bus import publish

        publish(
            type="cmmc",
            event_type="cmmc.objective.updated",
            user_id=user_id,
            org_id=oid,
            objective_id=objective_id,
            control_id=obj["control_id"],
            status=st,
        )
    except Exception:
        pass
    return get_objective_status_row(user_id, objective_id) or {"id": row_id, "status": st}


def get_objective_status_row(user_id: str, objective_id: str) -> dict[str, Any] | None:
    ensure_cmmc_assessment_schema()
    row = get_conn().execute(
        "SELECT * FROM cmmc_objective_status WHERE user_id = ? AND objective_id = ?",
        (user_id, objective_id),
    ).fetchone()
    if not row:
        return None
    d = row_to_dict(row)
    try:
        d["evidence_ids"] = json.loads(d.get("evidence_ids_json") or "[]")
    except Exception:
        d["evidence_ids"] = []
    return d


def get_control_assessment(
    user_id: str,
    framework_id: str,
    control_id: str,
) -> dict[str, Any]:
    """Per-control assessment: objectives with status + method evidence rollup."""
    ensure_cmmc_assessment_schema()
    objs = list_objectives(framework_id, control_id=control_id)
    if not objs:
        seed_objectives_for_framework(framework_id)
        objs = list_objectives(framework_id, control_id=control_id)

    from app.cmmc.methods import list_method_evidence
    from app.cmmc.poam_policy import poam_policy_for_control
    from app.services.live_ssp import live_ssp_control_detail

    statuses = []
    met = partial = not_met = unknown = 0
    out_objs = []
    for o in objs:
        st_row = get_objective_status_row(user_id, o["id"])
        st = (st_row or {}).get("status") or "unknown"
        if st == "met":
            met += 1
        elif st == "partial":
            partial += 1
        elif st == "not_met":
            not_met += 1
        else:
            unknown += 1
        statuses.append(st)
        out_objs.append(
            {
                **o,
                "assessment": st_row
                or {
                    "status": "unknown",
                    "evidence_ids": [],
                    "freshness_status": "unknown",
                },
            }
        )

    if not_met:
        rollup = "not_met"
    elif partial or (met and unknown):
        rollup = "partial"
    elif met and not unknown:
        rollup = "met"
    else:
        rollup = "unknown"

    ssp = None
    try:
        ssp = live_ssp_control_detail(user_id, framework_id, control_id)
    except Exception:
        ssp = None

    methods = list_method_evidence(user_id, framework_id=framework_id, control_id=control_id)

    return {
        "ok": True,
        "framework_id": framework_id,
        "control_id": control_id,
        "rollup_status": rollup,
        "counts": {"met": met, "partial": partial, "not_met": not_met, "unknown": unknown},
        "objectives": out_objs,
        "method_evidence": methods,
        "poam_policy": poam_policy_for_control(framework_id, control_id),
        "live_ssp": ssp,
        "disclaimer": _SEED_DISCLAIMER,
    }
