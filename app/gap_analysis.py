"""Gap analysis engine — current GRC / AppSec framework catalogs."""

from __future__ import annotations

import json
import re
from typing import Any, Literal

from app.db import audit, get_conn, new_id, now, row_to_dict
from app.paths import resource_root

Status = Literal["implemented", "partial", "missing", "not_applicable"]

_FRAMEWORKS_DIR = resource_root() / "data" / "frameworks"

# Legacy UI / catalog aliases → current JSON ids
_FRAMEWORK_ALIASES = {
    "cis": "cis_controls",
    "pci": "pci_dss",
    "asvs": "owasp_asvs",
    "nist": "nist_csf",
    "cmmc": "cmmc_l2",
    "800-53": "nist_800_53",
    "800-171": "nist_800_171",
}

_STATUS_SCORE = {
    "implemented": 1.0,
    "partial": 0.5,
    "missing": 0.0,
    "not_applicable": None,
}


def list_frameworks() -> list[dict[str, Any]]:
    out = []
    for path in sorted(_FRAMEWORKS_DIR.glob("*.json")):
        data = json.loads(path.read_text(encoding="utf-8"))
        out.append(
            {
                "id": data["id"],
                "name": data["name"],
                "version": data.get("version", ""),
                "control_count": len(data.get("controls") or []),
                "description": data.get("description") or "",
            }
        )
    return out


def load_framework(framework_id: str) -> dict[str, Any]:
    fid = _FRAMEWORK_ALIASES.get((framework_id or "").strip().lower(), framework_id)
    path = _FRAMEWORKS_DIR / f"{fid}.json"
    if not path.exists():
        for p in _FRAMEWORKS_DIR.glob("*.json"):
            data = json.loads(p.read_text(encoding="utf-8"))
            if data.get("id") == fid or data.get("id") == framework_id:
                return data
        raise ValueError(f"Unknown framework: {framework_id}")
    return json.loads(path.read_text(encoding="utf-8"))


def _normalize(text: str) -> str:
    return re.sub(r"\s+", " ", (text or "").lower()).strip()


def score_control_against_evidence(control: dict[str, Any], evidence: str) -> dict[str, Any]:
    """Heuristic keyword mapping against evidence text for gap scoring."""
    ev = _normalize(evidence)
    if not ev:
        return {
            "status": "missing",
            "confidence": 0.2,
            "matched_keywords": [],
            "recommendation": (
                f"No evidence provided for {control['id']}. "
                "Collect policy/procedure/screenshots."
            ),
        }

    kws = [k.lower() for k in (control.get("keywords") or [])]
    if not kws:
        # Fall back to description/title tokens when catalogs omit keywords
        blob = f"{control.get('description') or ''} {control.get('title') or ''}"
        kws = [w for w in re.split(r"\W+", blob.lower()) if len(w) > 4][:8]
    matched = [k for k in kws if k in ev]
    ratio = len(matched) / max(len(kws), 1)

    title_bits = [w for w in re.split(r"\W+", control.get("title", "").lower()) if len(w) > 4]
    title_hits = sum(1 for w in title_bits if w in ev)
    if title_hits >= 2:
        ratio = min(1.0, ratio + 0.25)
    desc = _normalize(str(control.get("description") or ""))
    if desc:
        desc_bits = [w for w in re.split(r"\W+", desc) if len(w) > 5][:6]
        if sum(1 for w in desc_bits if w in ev) >= 2:
            ratio = min(1.0, ratio + 0.15)

    if ratio >= 0.45 or len(matched) >= 2:
        status: Status = "implemented"
        conf = min(0.9, 0.55 + ratio)
        rec = (
            f"Evidence appears to cover {control['id']}. "
            "Verify with owner and attach formal artifact."
        )
    elif ratio >= 0.2 or matched:
        status = "partial"
        conf = 0.45 + ratio * 0.3
        missing_kw = [k for k in kws if k not in matched][:3]
        rec = (
            f"Partial coverage for {control['id']}. Strengthen: "
            + (", ".join(missing_kw) if missing_kw else "document residual gaps")
            + "."
        )
    else:
        status = "missing"
        conf = 0.35
        rec = (
            f"Gap: {control['id']} — {control['title']}. "
            "Recommended: define control owner, write/update procedure, and collect evidence "
            f"(look for: {', '.join(kws[:4])})."
        )

    return {
        "status": status,
        "confidence": round(conf, 2),
        "matched_keywords": matched,
        "recommendation": rec,
    }


SCORING_METHODOLOGY = {
    "type": "heuristic_keyword",
    "auditor_grade": False,
    "version": "1.0",
    "summary": (
        "Compliance % is a keyword/evidence heuristic — not an auditor attestation. "
        "implemented=1.0, partial=0.5, missing=0.0; not_applicable excluded from denominator. "
        "Manual overrides set confidence=1.0 for that control only."
    ),
    "formula": (
        "compliance_percent = 100 * sum(status_weight) / count(applicable_controls); "
        "status_weight: implemented=1, partial=0.5, missing=0, N/A=excluded"
    ),
    "limits": (
        "Does not prove control operating effectiveness, sampling, or SOC 2 / ISO certification. "
        "Use evidence queue + human attestation for audit packs."
    ),
}


def run_gap_analysis(
    *,
    framework_id: str,
    evidence: str,
    title: str = "Gap assessment",
    engagement_id: str | None = None,
    user_id: str = "local",
    overrides: dict[str, str] | None = None,
) -> dict[str, Any]:
    fw = load_framework(framework_id)
    controls = fw.get("controls") or []
    overrides = {k.upper(): v for k, v in (overrides or {}).items()}

    try:
        from app.services.control_testing import run_live_tests_for_control
    except Exception:
        run_live_tests_for_control = None  # type: ignore[assignment]

    results = []
    for c in controls:
        scored = score_control_against_evidence(c, evidence)
        ov = overrides.get(c["id"].upper()) or overrides.get(c["id"])
        if ov in _STATUS_SCORE:
            scored["status"] = ov
            scored["confidence"] = 1.0
            scored["recommendation"] = scored["recommendation"] + f" (manual status: {ov})"
        # Live tests (app.services.control_testing) are a SEPARATE, additive
        # signal computed straight from real product data -- never blended
        # into the pasted-evidence status/confidence above. A control's
        # declared status can disagree with its live test result; showing
        # both, rather than letting one silently override the other, is the
        # honest behavior (same principle as attack-graph declared vs
        # inferred edges).
        live_tests: list[dict[str, Any]] = []
        if run_live_tests_for_control is not None:
            try:
                live_tests = run_live_tests_for_control(user_id, fw["id"], c["id"])
            except Exception:
                live_tests = []
        results.append(
            {
                "control_id": c["id"],
                "title": c["title"],
                "domain": c.get("domain", ""),
                **scored,
                "live_tests": live_tests,
            }
        )

    applicable = [r for r in results if r["status"] != "not_applicable"]
    score_sum = sum(_STATUS_SCORE[r["status"]] or 0.0 for r in applicable)
    pct = round(100.0 * score_sum / max(len(applicable), 1), 1)

    counts: dict[str, int] = {s: 0 for s in _STATUS_SCORE}
    for r in results:
        counts[r["status"]] = counts.get(r["status"], 0) + 1

    gaps = [r for r in results if r["status"] in {"missing", "partial"}]
    gaps.sort(key=lambda x: (0 if x["status"] == "missing" else 1, x["control_id"]))

    roadmap = _build_roadmap(gaps)
    exec_summary = _exec_summary(fw["name"], pct, counts, gaps)

    assessment_id = new_id()
    created = now()
    payload = {
        "id": assessment_id,
        "title": title,
        "framework_id": fw["id"],
        "framework_name": fw["name"],
        "engagement_id": engagement_id,
        "user_id": user_id,
        "compliance_percent": pct,
        "counts": counts,
        "control_count": len(results),
        "results": results,
        "top_gaps": gaps[:15],
        "roadmap": roadmap,
        "executive_summary": exec_summary,
        "methodology": SCORING_METHODOLOGY,
        "created_at": created,
    }

    c = get_conn()
    c.execute(
        """
        INSERT INTO gap_assessments
        (id, user_id, engagement_id, framework_id, title, evidence, result_json, compliance_percent, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            assessment_id,
            user_id,
            engagement_id,
            fw["id"],
            title,
            evidence[:200_000],
            json.dumps(payload),
            pct,
            created,
        ),
    )
    c.commit()
    audit("gap_assessment", user_id, {"id": assessment_id, "framework": fw["id"], "pct": pct})

    from app.enterprise import create_remediations_from_assessment

    remediations = create_remediations_from_assessment(
        user_id, assessment_id, gaps, engagement_id=engagement_id
    )
    payload["remediations_created"] = len(remediations)
    payload["remediations"] = remediations[:20]
    # refresh stored JSON with remediations
    get_conn().execute(
        "UPDATE gap_assessments SET result_json = ? WHERE id = ?",
        (json.dumps(payload), assessment_id),
    )
    get_conn().commit()
    try:
        from app.realtime_bus import publish

        publish(
            type="gap",
            id=assessment_id,
            framework_id=fw["id"],
            compliance_percent=pct,
            user_id=user_id,
        )
    except Exception:
        pass
    return payload


def get_assessment(user_id: str, assessment_id: str) -> dict[str, Any] | None:
    c = get_conn()
    row = c.execute(
        "SELECT * FROM gap_assessments WHERE id = ? AND user_id = ?",
        (assessment_id, user_id),
    ).fetchone()
    if not row:
        return None
    data = json.loads(row["result_json"])
    data["evidence_preview"] = (row["evidence"] or "")[:500]
    return data


def delete_assessment(user_id: str, assessment_id: str) -> bool:
    """Delete a gap assessment and cascade-clean its remediation tasks —
    a remediation with no owning assessment is orphaned and would otherwise
    linger in the Controls list forever."""
    c = get_conn()
    row = c.execute(
        "SELECT id FROM gap_assessments WHERE id = ? AND user_id = ?", (assessment_id, user_id)
    ).fetchone()
    if not row:
        return False
    c.execute("DELETE FROM gap_remediations WHERE assessment_id = ? AND user_id = ?", (assessment_id, user_id))
    cur = c.execute("DELETE FROM gap_assessments WHERE id = ? AND user_id = ?", (assessment_id, user_id))
    c.commit()
    if cur.rowcount:
        from app.db import audit

        audit("gap_assessment_delete", user_id, {"id": assessment_id})
        try:
            from app.realtime_bus import publish

            publish(type="gap", id=assessment_id, user_id=user_id, action="delete")
        except Exception:
            pass
        return True
    return False


def list_assessments(user_id: str, engagement_id: str | None = None) -> list[dict[str, Any]]:
    c = get_conn()
    if engagement_id:
        rows = c.execute(
            """
            SELECT id, title, framework_id, compliance_percent, engagement_id, created_at
            FROM gap_assessments WHERE user_id = ? AND engagement_id = ?
            ORDER BY created_at DESC LIMIT 50
            """,
            (user_id, engagement_id),
        ).fetchall()
    else:
        rows = c.execute(
            """
            SELECT id, title, framework_id, compliance_percent, engagement_id, created_at
            FROM gap_assessments WHERE user_id = ?
            ORDER BY created_at DESC LIMIT 50
            """,
            (user_id,),
        ).fetchall()
    return [row_to_dict(r) for r in rows]


def dashboard_scores(user_id: str) -> dict[str, Any]:
    c = get_conn()
    rows = c.execute(
        """
        SELECT framework_id, compliance_percent, created_at, title, id
        FROM gap_assessments WHERE user_id = ?
        ORDER BY created_at DESC LIMIT 20
        """,
        (user_id,),
    ).fetchall()
    latest_by_fw: dict[str, dict[str, Any]] = {}
    for r in rows:
        fid = r["framework_id"]
        if fid not in latest_by_fw:
            latest_by_fw[fid] = row_to_dict(r)

    scores = list(latest_by_fw.values())
    overall = (
        round(sum(s["compliance_percent"] for s in scores) / max(len(scores), 1), 1) if scores else 0.0
    )

    recommendations: list[str] = []
    if scores:
        # Build tips from real missing/partial controls in the newest assessment
        try:
            newest = rows[0]
            detail = get_assessment(user_id, newest["id"])
            gaps = (detail or {}).get("top_gaps") or []
            for g in gaps[:5]:
                cid = g.get("control_id") or g.get("id") or ""
                title = g.get("title") or g.get("control_title") or "control"
                status = g.get("status") or "missing"
                recommendations.append(f"Close {status} control {cid}: {title}".strip()[:180])
            if not recommendations:
                recommendations.append(
                    f"Continue remediating gaps for {(detail or {}).get('framework_name') or newest['framework_id']}"
                )
            recommendations.append("Export executive report for engagement delivery")
        except Exception:
            recommendations = [
                "Review open remediations from your latest gap assessment",
                "Export executive report for engagement delivery",
            ]

    return {
        "security_score": overall,
        "compliance_score": overall,
        "frameworks": scores,
        "assessment_count": len(rows),
        "methodology": SCORING_METHODOLOGY,
        "recommendations": recommendations,
    }


def export_gap_markdown(user_id: str, assessment_id: str) -> str:
    data = get_assessment(user_id, assessment_id)
    if not data:
        raise ValueError("Assessment not found")

    lines = [
        f"# Gap Analysis Report — {data.get('title')}",
        "",
        f"**Framework:** {data.get('framework_name')} (`{data.get('framework_id')}`)",
        f"**Compliance score:** **{data.get('compliance_percent')}%**",
        f"**Assessment ID:** `{assessment_id}`",
        "",
        "## Executive summary",
        "",
        data.get("executive_summary") or "",
        "",
        "## Status counts",
        "",
    ]
    for k, v in (data.get("counts") or {}).items():
        lines.append(f"- **{k}:** {v}")

    lines += ["", "## Top gaps & recommendations", ""]
    for g in data.get("top_gaps") or []:
        lines.append(f"### {g['control_id']} — {g['title']} ({g['status']})")
        lines.append("")
        lines.append(g.get("recommendation") or "")
        if g.get("matched_keywords"):
            lines.append(f"- Matched: {', '.join(g['matched_keywords'])}")
        lines.append("")

    lines += ["", "## 30 / 60 / 90 day roadmap", ""]
    for phase, items in (data.get("roadmap") or {}).items():
        lines.append(f"### {phase}")
        for it in items:
            lines.append(f"- {it}")
        lines.append("")

    lines += [
        "",
        "## Full control results",
        "",
        "| Control | Domain | Status | Confidence |",
        "|---|---|---|---|",
    ]
    for r in data.get("results") or []:
        lines.append(
            f"| {r['control_id']} | {r.get('domain', '')} | {r['status']} | {r.get('confidence', '')} |"
        )

    lines += [
        "",
        "---",
        "_Generated by SecuraIQ for authorized consulting / internal assessments "
        "(e.g. Swana Techno engagements)._",
    ]
    return "\n".join(lines)


def _build_roadmap(gaps: list[dict[str, Any]]) -> dict[str, list[str]]:
    missing = [g for g in gaps if g["status"] == "missing"]
    partial = [g for g in gaps if g["status"] == "partial"]
    d30 = [f"Close critical gap {g['control_id']}: {g['title']}" for g in missing[:5]]
    d60 = [f"Complete partial control {g['control_id']}: {g['title']}" for g in partial[:5]]
    if not d60:
        d60 = [f"Document evidence for {g['control_id']}" for g in missing[5:10]]
    d90 = [
        "Internal audit dry-run against remaining gaps",
        "Management review of residual risk & acceptance",
        "Schedule external certification / customer assurance review",
    ]
    if not d30:
        d30 = ["Maintain continuous evidence collection and quarterly control review"]
    return {
        "30_days": d30,
        "60_days": d60 or ["Harden residual technical controls"],
        "90_days": d90,
    }


def _exec_summary(
    fw_name: str, pct: float, counts: dict[str, int], gaps: list[dict[str, Any]]
) -> str:
    top = ", ".join(f"{g['control_id']}" for g in gaps[:5]) or "none"
    tone = "strong" if pct >= 75 else "moderate" if pct >= 50 else "early-stage"
    return (
        f"Against **{fw_name}**, the organization shows a **{tone}** posture with an estimated "
        f"**{pct}%** control coverage (implemented={counts.get('implemented', 0)}, "
        f"partial={counts.get('partial', 0)}, missing={counts.get('missing', 0)}). "
        f"Priority gaps: {top}. "
        f"Recommended next step: assign owners, collect formal evidence, and execute the 30/60/90 roadmap."
    )


def ensure_gap_schema() -> None:
    c = get_conn()
    c.execute(
        """
        CREATE TABLE IF NOT EXISTS gap_assessments (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            engagement_id TEXT,
            framework_id TEXT NOT NULL,
            title TEXT NOT NULL,
            evidence TEXT NOT NULL DEFAULT '',
            result_json TEXT NOT NULL,
            compliance_percent REAL NOT NULL DEFAULT 0,
            created_at REAL NOT NULL
        )
        """
    )
    c.commit()
