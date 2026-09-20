"""Evaluate a control from all mapped Evidence (observed + document)."""

from __future__ import annotations

from typing import Any

from app.evidence_spine.mapping import list_evidence_for_control


def evaluate_control_from_evidence(
    user_id: str,
    *,
    control_id: str,
    framework_id: str = "",
) -> dict[str, Any]:
    """Roll up mapped evidence into a control result.

    Rules (honest):
    - Fresh **observed** FAIL → overall ``fail``
    - Fresh **observed** PASS and no fresh FAIL → ``pass``
    - Only **document/declared** evidence → ``partial`` (supports, not runtime proof)
    - Only stale/expired observed → ``unknown`` (stale)
    - Nothing mapped → ``unknown``
    """
    rows = list_evidence_for_control(
        user_id, control_id=control_id, framework_id=framework_id, limit=200
    )
    observed_fresh_pass = 0
    observed_fresh_fail = 0
    observed_stale = 0
    documents = 0
    evidence_ids: list[str] = []
    for r in rows:
        eid = str(r.get("id") or "")
        if eid:
            evidence_ids.append(eid)
        src = (r.get("source") or "").lower()
        et = (r.get("entity_type") or "").lower()
        fresh = (r.get("freshness_status") or "fresh").lower()
        detail = r.get("detail") if isinstance(r.get("detail"), dict) else {}
        status = str(detail.get("result") or detail.get("status") or "").lower()
        # Infer from summary host_control:fail style
        if not status and ":" in (r.get("summary") or ""):
            part = (r.get("summary") or "").split(":", 1)[-1]
            if part.lower().startswith("fail"):
                status = "fail"
            elif part.lower().startswith("pass"):
                status = "pass"

        is_doc = et == "document" or src == "declared" or (r.get("map_role") == "documents")
        is_obs = et in {"observation", "agent_host_control", "control_result"} or src == "observed"

        if is_doc and not is_obs:
            documents += 1
            continue
        if is_obs:
            if fresh == "fresh":
                if status == "fail":
                    observed_fresh_fail += 1
                elif status == "pass":
                    observed_fresh_pass += 1
            else:
                observed_stale += 1

    if observed_fresh_fail > 0:
        result = "fail"
        note = "Fresh observed FAIL evidence present — control not satisfied at runtime."
    elif observed_fresh_pass > 0:
        result = "pass"
        note = "Fresh observed PASS evidence; no fresh FAIL."
    elif documents > 0 and observed_fresh_pass == 0 and observed_fresh_fail == 0:
        result = "partial"
        note = (
            "Document/declared evidence supports the control but does not prove "
            "live operating effectiveness. Add agent observation for PASS."
        )
    elif observed_stale > 0:
        result = "unknown"
        note = "Only stale/expired observed evidence — re-check required."
    else:
        result = "unknown"
        note = "No mapped evidence for this control yet."

    return {
        "ok": True,
        "control_id": control_id,
        "framework_id": framework_id or "",
        "result": result,
        "counts": {
            "evidence_total": len(rows),
            "observed_fresh_pass": observed_fresh_pass,
            "observed_fresh_fail": observed_fresh_fail,
            "observed_stale": observed_stale,
            "documents": documents,
        },
        "evidence_ids": evidence_ids,
        "note": note,
        "honesty": (
            "Evaluation is work/assessment signal only — not a certification "
            "or legal determination of compliance."
        ),
    }
