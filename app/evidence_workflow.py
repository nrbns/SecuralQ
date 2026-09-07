"""Evidence-collection loop helpers + auditor export packs.

Closes the gap between gap-analysis scores and linked evidence artifacts:
  - missing-evidence queue (controls without accepted evidence)
  - ZIP audit pack (matrix + index + accepted files)
"""

from __future__ import annotations

import csv
import io
import json
import zipfile
from pathlib import Path
from typing import Any

from app.commercial_ext import list_evidence_links
from app.db import get_conn, row_to_dict
from app.gap_analysis import export_gap_markdown, get_assessment, list_assessments
from app.uploads import uploads_root


def _controls_from_assessment(data: dict[str, Any]) -> list[dict[str, Any]]:
    controls = data.get("controls") or data.get("results") or []
    if isinstance(controls, dict):
        controls = list(controls.values())
    return [c for c in controls if isinstance(c, dict)]


def _accepted_control_ids(user_id: str, engagement_id: str | None = None) -> set[str]:
    ids: set[str] = set()
    for link in list_evidence_links(user_id, engagement_id=engagement_id):
        if (link.get("status") or "").lower() != "accepted":
            continue
        cid = (link.get("control_id") or "").strip()
        if cid:
            ids.add(cid.upper())
    return ids


def missing_evidence_queue(
    user_id: str,
    *,
    assessment_id: str | None = None,
    limit: int = 100,
) -> dict[str, Any]:
    """Controls scored missing/partial with zero accepted evidence links."""
    assessments: list[dict[str, Any]] = []
    if assessment_id:
        one = get_assessment(user_id, assessment_id)
        if not one:
            raise ValueError("Assessment not found")
        assessments = [one]
        assessment_id = one.get("id") or assessment_id
    else:
        for row in list_assessments(user_id)[:8]:
            full = get_assessment(user_id, row["id"])
            if full:
                full["id"] = row["id"]
                assessments.append(full)

    accepted = _accepted_control_ids(user_id)
    queue: list[dict[str, Any]] = []
    total = 0
    for a in assessments:
        aid = a.get("id") or assessment_id or ""
        for c in _controls_from_assessment(a):
            status = (c.get("status") or "").lower()
            if status not in {"missing", "partial"}:
                continue
            cid = str(c.get("control_id") or c.get("id") or "").strip()
            if not cid:
                continue
            if cid.upper() in accepted:
                continue
            total += 1
            if len(queue) >= limit:
                continue
            queue.append(
                {
                    "assessment_id": aid,
                    "framework_id": a.get("framework_id"),
                    "control_id": cid,
                    "title": c.get("title") or "",
                    "status": status,
                    "recommendation": (c.get("recommendation") or "")[:500],
                    "suggested_artifacts": _suggest_artifacts(c),
                }
            )

    return {
        "count": total,
        "accepted_controls": len(accepted),
        "items": queue,
    }


def _suggest_artifacts(control: dict[str, Any]) -> list[str]:
    title = f"{control.get('title') or ''} {control.get('recommendation') or ''}".lower()
    suggestions = ["Policy or standard (PDF/MD)", "Configuration export / screenshot"]
    if any(x in title for x in ("access", "mfa", "identity", "sso", "account")):
        suggestions.append("IdP / MFA enrollment report")
    if any(x in title for x in ("log", "monitor", "siem", "detect")):
        suggestions.append("SIEM alert rule export or dashboard screenshot")
    if any(x in title for x in ("backup", "recover", "continuity")):
        suggestions.append("Backup job success report")
    if any(x in title for x in ("vuln", "patch", "harden")):
        suggestions.append("Vulnerability scan / hardening report CSV")
    if any(x in title for x in ("incident", "response", "ir ")):
        suggestions.append("IR playbook + tabletop notes")
    return suggestions[:4]


def evidence_coverage_for_assessment(user_id: str, assessment_id: str) -> dict[str, Any]:
    data = get_assessment(user_id, assessment_id)
    if not data:
        raise ValueError("Assessment not found")
    accepted = _accepted_control_ids(user_id, data.get("engagement_id"))
    controls = _controls_from_assessment(data)
    covered = 0
    rows = []
    for c in controls:
        cid = str(c.get("control_id") or c.get("id") or "").strip()
        has = bool(cid and cid.upper() in accepted)
        if has:
            covered += 1
        rows.append(
            {
                "control_id": cid,
                "title": c.get("title") or "",
                "gap_status": c.get("status"),
                "has_accepted_evidence": has,
            }
        )
    total = len(controls) or 1
    return {
        "assessment_id": assessment_id,
        "framework_id": data.get("framework_id"),
        "controls_total": len(controls),
        "controls_with_evidence": covered,
        "coverage_percent": round(100.0 * covered / total, 1),
        "controls": rows,
    }


def build_audit_pack_zip(user_id: str, assessment_id: str) -> bytes:
    """ZIP: report.md, control_matrix.csv, evidence_index.csv, evidence/* files."""
    data = get_assessment(user_id, assessment_id)
    if not data:
        raise ValueError("Assessment not found")

    md = export_gap_markdown(user_id, assessment_id)
    coverage = evidence_coverage_for_assessment(user_id, assessment_id)
    links = [
        l
        for l in list_evidence_links(user_id, engagement_id=data.get("engagement_id"))
        if (l.get("status") or "").lower() == "accepted"
    ]

    # Remediations for this assessment
    rem_rows = get_conn().execute(
        """
        SELECT control_id, title, status, owner, due_date, notes, recommendation
        FROM gap_remediations WHERE assessment_id = ? AND user_id = ?
        ORDER BY control_id
        """,
        (assessment_id, user_id),
    ).fetchall()
    remediations = [row_to_dict(r) for r in rem_rows]

    matrix_buf = io.StringIO()
    matrix_w = csv.writer(matrix_buf)
    matrix_w.writerow(
        ["control_id", "title", "gap_status", "has_accepted_evidence", "recommendation"]
    )
    for c in _controls_from_assessment(data):
        cid = str(c.get("control_id") or c.get("id") or "")
        has = any(
            (l.get("control_id") or "").upper() == cid.upper()
            for l in links
            if l.get("control_id")
        )
        matrix_w.writerow(
            [
                cid,
                c.get("title") or "",
                c.get("status") or "",
                "yes" if has else "no",
                (c.get("recommendation") or "")[:300],
            ]
        )

    index_buf = io.StringIO()
    index_w = csv.writer(index_buf)
    index_w.writerow(
        ["link_id", "control_id", "filename", "owner", "status", "expiry", "notes", "file_id"]
    )
    for l in links:
        index_w.writerow(
            [
                l.get("id"),
                l.get("control_id"),
                l.get("filename"),
                l.get("owner"),
                l.get("status"),
                l.get("expiry"),
                (l.get("notes") or "")[:200],
                l.get("file_id"),
            ]
        )

    rem_buf = io.StringIO()
    rem_w = csv.writer(rem_buf)
    rem_w.writerow(["control_id", "title", "status", "owner", "due_date", "notes"])
    for r in remediations:
        rem_w.writerow(
            [
                r.get("control_id"),
                r.get("title"),
                r.get("status"),
                r.get("owner"),
                r.get("due_date"),
                (r.get("notes") or r.get("recommendation") or "")[:300],
            ]
        )

    manifest = {
        "product": "SecuraIQ",
        "pack_type": "compliance_audit_pack",
        "assessment_id": assessment_id,
        "framework_id": data.get("framework_id"),
        "framework_name": data.get("framework_name"),
        "compliance_percent": data.get("compliance_percent"),
        "evidence_coverage_percent": coverage.get("coverage_percent"),
        "evidence_files": len(links),
        "disclaimer": (
            "Not a certification. Maps controls and linked evidence for authorized audits. "
            "Counsel and auditor judgment still required."
        ),
    }

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("README.md", md)
        zf.writestr("manifest.json", json.dumps(manifest, indent=2))
        zf.writestr("control_matrix.csv", matrix_buf.getvalue())
        zf.writestr("evidence_index.csv", index_buf.getvalue())
        zf.writestr("remediations.csv", rem_buf.getvalue())
        zf.writestr(
            "coverage.json",
            json.dumps(
                {
                    "coverage_percent": coverage.get("coverage_percent"),
                    "controls_with_evidence": coverage.get("controls_with_evidence"),
                    "controls_total": coverage.get("controls_total"),
                },
                indent=2,
            ),
        )

        for l in links:
            fid = l.get("file_id") or ""
            row = get_conn().execute(
                "SELECT filename, stored_path FROM files WHERE id = ? AND user_id = ?",
                (fid, user_id),
            ).fetchone()
            if not row:
                continue
            path = Path(row["stored_path"])
            if not path.is_file():
                # fallback under uploads root
                alt = uploads_root() / user_id
                matches = list(alt.glob(f"{fid}_*")) if alt.exists() else []
                path = matches[0] if matches else path
            if not path.is_file():
                continue
            safe_name = Path(row["filename"] or path.name).name
            arc = f"evidence/{(l.get('control_id') or 'unmapped')[:40]}_{safe_name}"
            try:
                zf.write(path, arcname=arc)
            except OSError:
                continue

    return buf.getvalue()
