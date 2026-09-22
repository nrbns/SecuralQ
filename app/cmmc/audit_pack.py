"""CMMC full audit package — ZIP for assessor prep (not certification).

Includes SSP, readiness, objectives, method evidence, interviews, POA&M,
SPRS prep, CUI programs. Reuses Evidence Spine / attestation tables.
"""

from __future__ import annotations

import csv
import io
import json
import zipfile
from typing import Any

from app.db import now


def build_cmmc_audit_pack_zip(
    user_id: str,
    *,
    framework_id: str = "cmmc_l2",
) -> bytes:
    """Build assessor preparation ZIP. Not a C3PAO package or SPRS submission."""
    from app.cmmc.gap_plan import build_evidence_gap_plan
    from app.cmmc.interviews import list_interviews
    from app.cmmc.methods import list_method_evidence
    from app.cmmc.objectives import list_objectives, seed_objectives_for_framework
    from app.cmmc.poam_items import list_poam_items
    from app.cmmc.readiness import framework_readiness_summary
    from app.cmmc.sprs_prep import sprs_preparation_snapshot
    from app.cmmc.ssp_engine import ssp_engine_snapshot
    from app.cmmc.cui_program import list_cui_programs
    from app.cmmc.versioning import framework_version_info

    seed_objectives_for_framework(framework_id)
    ver = framework_version_info(framework_id)
    ssp = ssp_engine_snapshot(user_id, framework_id)
    readiness = framework_readiness_summary(user_id, framework_id)
    sprs = sprs_preparation_snapshot(user_id, framework_id=framework_id)
    gap = build_evidence_gap_plan(user_id, framework_id)
    poams = list_poam_items(user_id, framework_id=framework_id)
    methods = list_method_evidence(user_id, framework_id=framework_id, limit=500)
    interviews = list_interviews(user_id, framework_id=framework_id, limit=500)
    cui = list_cui_programs(user_id)
    objs = list_objectives(framework_id)

    # Objective status CSV
    obj_buf = io.StringIO()
    obj_w = csv.writer(obj_buf)
    obj_w.writerow(
        ["objective_id", "control_id", "method", "title", "status", "freshness", "reviewer"]
    )
    from app.cmmc.objectives import get_objective_status_row

    for o in objs:
        st = get_objective_status_row(user_id, o["id"]) or {}
        obj_w.writerow(
            [
                o.get("id"),
                o.get("control_id"),
                o.get("method"),
                (o.get("title") or "")[:200],
                st.get("status") or "unknown",
                st.get("freshness_status") or "unknown",
                st.get("reviewer") or "",
            ]
        )

    meth_buf = io.StringIO()
    meth_w = csv.writer(meth_buf)
    meth_w.writerow(
        ["id", "control_id", "method", "title", "result", "evidence_id", "reviewer", "collected_at"]
    )
    for m in methods:
        meth_w.writerow(
            [
                m.get("id"),
                m.get("control_id"),
                m.get("method"),
                (m.get("title") or "")[:200],
                m.get("result"),
                m.get("evidence_id"),
                m.get("reviewer"),
                m.get("collected_at"),
            ]
        )

    poam_buf = io.StringIO()
    poam_w = csv.writer(poam_buf)
    poam_w.writerow(
        ["id", "control_id", "status", "owner", "risk_level", "due_at", "weakness"]
    )
    for p in poams:
        poam_w.writerow(
            [
                p.get("id"),
                p.get("control_id"),
                p.get("status"),
                p.get("owner"),
                p.get("risk_level"),
                p.get("due_at"),
                (p.get("weakness") or "")[:300],
            ]
        )

    iv_buf = io.StringIO()
    iv_w = csv.writer(iv_buf)
    iv_w.writerow(
        ["id", "control_id", "person", "role", "status", "question", "reviewer", "evidence_id"]
    )
    for iv in interviews:
        iv_w.writerow(
            [
                iv.get("id"),
                iv.get("control_id"),
                iv.get("person"),
                iv.get("role"),
                iv.get("status"),
                (iv.get("question") or "")[:200],
                iv.get("reviewer"),
                iv.get("evidence_id"),
            ]
        )

    ready_buf = io.StringIO()
    ready_w = csv.writer(ready_buf)
    ready_w.writerow(["control_id", "title", "rollup_status", "overall_band", "overall_score", "recommendation"])
    for c in readiness.get("controls") or []:
        ready_w.writerow(
            [
                c.get("control_id"),
                (c.get("title") or "")[:120],
                c.get("rollup_status"),
                c.get("overall_band"),
                c.get("overall_score"),
                (c.get("recommendation") or "")[:200],
            ]
        )

    readme = f"""# SecuraIQ CMMC Audit Preparation Pack

Framework: {framework_id}
Version: {ver.get('version') or ''}
Generated: {now()}

## Honesty

This pack is **assessor preparation material** from SecuraIQ local data.
It is **not** a C3PAO assessment, **not** SPRS submission, and **not** certification.

## Contents

- manifest.json
- framework_version.json
- ssp_engine.json
- sprs_preparation.json
- readiness_summary.json
- evidence_gap_plan.json
- cui_programs.json
- objectives_status.csv
- method_evidence.csv
- poam_items.csv
- interviews.csv
- readiness_by_control.csv
"""

    manifest: dict[str, Any] = {
        "product": "SecuraIQ",
        "pack_type": "cmmc_audit_preparation",
        "framework_id": framework_id,
        "framework_version": ver.get("version"),
        "generated_at": now(),
        "counts": {
            "controls": ssp.get("controls_total"),
            "objectives": len(objs),
            "method_evidence": len(methods),
            "poam_open": sum(1 for p in poams if (p.get("status") or "") == "open"),
            "interviews": len(interviews),
            "cui_programs": len(cui),
            "gap_tasks": (gap.get("summary") or {}).get("tasks_generated"),
            "readiness_bands": readiness.get("bands"),
        },
        "disclaimer": (
            "Not a C3PAO package, SPRS submission, or certification. "
            "Counsel and assessor judgment required."
        ),
    }

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("README.md", readme)
        zf.writestr("manifest.json", json.dumps(manifest, indent=2, default=str))
        zf.writestr("framework_version.json", json.dumps(ver, indent=2, default=str))
        zf.writestr("ssp_engine.json", json.dumps(ssp, indent=2, default=str))
        zf.writestr("sprs_preparation.json", json.dumps(sprs, indent=2, default=str))
        zf.writestr("readiness_summary.json", json.dumps(readiness, indent=2, default=str))
        zf.writestr("evidence_gap_plan.json", json.dumps(gap, indent=2, default=str))
        zf.writestr("cui_programs.json", json.dumps(cui, indent=2, default=str))
        zf.writestr("objectives_status.csv", obj_buf.getvalue())
        zf.writestr("method_evidence.csv", meth_buf.getvalue())
        zf.writestr("poam_items.csv", poam_buf.getvalue())
        zf.writestr("interviews.csv", iv_buf.getvalue())
        zf.writestr("readiness_by_control.csv", ready_buf.getvalue())
    return buf.getvalue()
