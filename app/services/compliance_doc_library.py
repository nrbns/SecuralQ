"""Compliance document library: author policy/procedure documents from a
template, review and modify them in-app, and — the moment one is approved —
turn it into *real* evidence, not a decorative wrapper around one.

Design intent, matching the rest of SecuraIQ's evidence model:
  - A document here is a normal, editable draft until a reviewer approves it.
    Approving is the one action that has a real side effect: the approved
    content is written to disk as a real file (via app.uploads.save_upload,
    the same path a manual file upload takes — same quota checks, same
    magic-byte validation, same optional RAG ingest) and linked into
    evidence_links (app.commercial_ext.link_evidence) against the control(s)
    the document targets. That evidence_links row is what Live SSP, the
    Evidence Control Center, and the Control Center evidence panel already
    read from — so approving a document shows up as real evidence in those
    views immediately, with no separate "sync" step to fake.
  - Editing an approved document knocks it back to draft. An approved
    document whose text changed out from under its evidence link would be
    exactly the kind of silent drift this product refuses to paper over.
  - Templates are authoring skeletons (standard policy section headings +
    guidance prompts for what belongs in each section) — never pre-filled
    with invented compliance claims. The org's own words go in every
    section; nothing here asserts a control is met.
"""

from __future__ import annotations

from typing import Any

from app.db import audit, get_conn, new_id, now, row_to_dict

DOC_STATUSES = ("draft", "in_review", "approved", "rejected")


def ensure_doc_library_schema() -> None:
    c = get_conn()
    c.executescript(
        """
        CREATE TABLE IF NOT EXISTS compliance_documents (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            title TEXT NOT NULL,
            template_id TEXT NOT NULL DEFAULT '',
            family TEXT NOT NULL DEFAULT '',
            framework_id TEXT NOT NULL DEFAULT '',
            control_id TEXT NOT NULL DEFAULT '',
            sections_json TEXT NOT NULL DEFAULT '[]',
            status TEXT NOT NULL DEFAULT 'draft',
            version INTEGER NOT NULL DEFAULT 1,
            owner TEXT NOT NULL DEFAULT '',
            reviewer TEXT NOT NULL DEFAULT '',
            review_comments TEXT NOT NULL DEFAULT '',
            evidence_link_id TEXT NOT NULL DEFAULT '',
            file_id TEXT NOT NULL DEFAULT '',
            created_at REAL NOT NULL,
            updated_at REAL NOT NULL,
            approved_at REAL
        );
        CREATE INDEX IF NOT EXISTS idx_compliance_documents_user
            ON compliance_documents(user_id);
        """
    )
    c.commit()


# --- Templates -------------------------------------------------------------
# Standard policy-document skeleton. Every template shares the same section
# shape (heading + a short prompt describing what to write there) so the
# renderer and editor stay generic; only the title/family/description/prompt
# text differs per template. `family` is a real NIST SP 800-171 / CMMC L2
# control-family prefix (AC, IR, CM, MP, RA, PE, ...) used only to help the
# user filter the real control catalog to a relevant starting point in the
# UI — it is never used to assert a specific control is satisfied.
def _standard_sections(focus: str) -> list[dict[str, str]]:
    return [
        {
            "heading": "Purpose",
            "prompt": f"State in your own words why this {focus} policy exists and what risk it addresses.",
            "content": "",
        },
        {
            "heading": "Scope",
            "prompt": "Which systems, data, and personnel does this policy apply to?",
            "content": "",
        },
        {
            "heading": "Policy",
            "prompt": f"The actual {focus} rules your organization follows — be specific and concrete, not aspirational.",
            "content": "",
        },
        {
            "heading": "Roles & responsibilities",
            "prompt": "Who owns this policy, who enforces it, who is accountable when it's violated?",
            "content": "",
        },
        {
            "heading": "Review & exceptions",
            "prompt": "How often is this reviewed, and how are exceptions requested/approved/tracked?",
            "content": "",
        },
    ]


TEMPLATES: list[dict[str, Any]] = [
    {
        "id": "access_control_policy",
        "title": "Access Control Policy",
        "family": "AC",
        "description": "Who can access what, how access is granted/revoked, and least-privilege rules.",
        "sections": _standard_sections("access control"),
    },
    {
        "id": "incident_response_plan",
        "title": "Incident Response Plan",
        "family": "IR",
        "description": "Detection, reporting, containment, and recovery steps for security incidents.",
        "sections": _standard_sections("incident response"),
    },
    {
        "id": "configuration_management_policy",
        "title": "Configuration Management Policy",
        "family": "CM",
        "description": "Baseline configurations, change control, and unauthorized-change detection.",
        "sections": _standard_sections("configuration management"),
    },
    {
        "id": "media_protection_policy",
        "title": "Media Protection Policy",
        "family": "MP",
        "description": "Handling, storage, transport, sanitization, and destruction of media containing CUI/sensitive data.",
        "sections": _standard_sections("media protection"),
    },
    {
        "id": "risk_assessment_policy",
        "title": "Risk Assessment Policy",
        "family": "RA",
        "description": "How and how often risk assessments and vulnerability scans are performed and acted on.",
        "sections": _standard_sections("risk assessment"),
    },
    {
        "id": "physical_security_policy",
        "title": "Physical & Environmental Protection Policy",
        "family": "PE",
        "description": "Physical access to facilities/equipment housing systems and CUI.",
        "sections": _standard_sections("physical and environmental protection"),
    },
    {
        "id": "awareness_training_policy",
        "title": "Security Awareness & Training Policy",
        "family": "AT",
        "description": "Who gets trained, on what, how often, and how training is tracked.",
        "sections": _standard_sections("security awareness and training"),
    },
    {
        "id": "audit_accountability_policy",
        "title": "Audit & Accountability Policy",
        "family": "AU",
        "description": "What gets logged, how logs are protected/reviewed, and retention.",
        "sections": _standard_sections("audit and accountability"),
    },
    {
        "id": "blank",
        "title": "Blank document",
        "family": "",
        "description": "Start from an empty document with the standard section headings.",
        "sections": _standard_sections("this"),
    },
]

_TEMPLATES_BY_ID = {t["id"]: t for t in TEMPLATES}


def list_templates() -> list[dict[str, Any]]:
    return [
        {k: v for k, v in t.items() if k != "sections"} | {"section_count": len(t["sections"])}
        for t in TEMPLATES
    ]


def _clean_sections(sections: Any, fallback: list[dict[str, str]]) -> list[dict[str, str]]:
    if not isinstance(sections, list) or not sections:
        return [dict(s) for s in fallback]
    out = []
    for s in sections:
        if not isinstance(s, dict):
            continue
        out.append(
            {
                "heading": str(s.get("heading") or "Section")[:120],
                "prompt": str(s.get("prompt") or "")[:400],
                "content": str(s.get("content") or "")[:20000],
            }
        )
    return out or [dict(s) for s in fallback]


def create_document(
    user_id: str,
    *,
    title: str,
    template_id: str = "blank",
    control_id: str = "",
    framework_id: str = "",
    owner: str = "",
    sections: list[dict[str, str]] | None = None,
) -> dict[str, Any]:
    ensure_doc_library_schema()
    tpl = _TEMPLATES_BY_ID.get(template_id) or _TEMPLATES_BY_ID["blank"]
    doc_id = new_id()
    ts = now()
    final_sections = _clean_sections(sections, tpl["sections"])
    import json as _json

    c = get_conn()
    c.execute(
        """
        INSERT INTO compliance_documents
        (id, user_id, title, template_id, family, framework_id, control_id, sections_json,
         status, version, owner, reviewer, review_comments, evidence_link_id, file_id,
         created_at, updated_at, approved_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'draft', 1, ?, '', '', '', '', ?, ?, NULL)
        """,
        (
            doc_id,
            user_id,
            (title or tpl["title"]).strip()[:200],
            tpl["id"],
            tpl.get("family", ""),
            (framework_id or "")[:40],
            (control_id or "")[:80],
            _json.dumps(final_sections),
            (owner or "")[:120],
            ts,
            ts,
        ),
    )
    c.commit()
    audit("compliance_doc_create", user_id, {"id": doc_id, "template_id": tpl["id"], "title": title})
    return get_document(user_id, doc_id)  # type: ignore[return-value]


def _row_out(row: dict[str, Any]) -> dict[str, Any]:
    import json as _json

    try:
        row["sections"] = _json.loads(row.get("sections_json") or "[]")
    except Exception:
        row["sections"] = []
    row.pop("sections_json", None)
    return row


def get_document(user_id: str, doc_id: str) -> dict[str, Any] | None:
    ensure_doc_library_schema()
    row = get_conn().execute(
        "SELECT * FROM compliance_documents WHERE id = ? AND user_id = ?", (doc_id, user_id)
    ).fetchone()
    d = row_to_dict(row)
    return _row_out(d) if d else None


def list_documents(
    user_id: str, *, control_id: str | None = None, status: str | None = None
) -> list[dict[str, Any]]:
    ensure_doc_library_schema()
    q = "SELECT * FROM compliance_documents WHERE user_id = ?"
    args: list[Any] = [user_id]
    if control_id:
        q += " AND control_id = ?"
        args.append(control_id)
    if status:
        q += " AND status = ?"
        args.append(status)
    q += " ORDER BY updated_at DESC LIMIT 300"
    rows = get_conn().execute(q, args).fetchall()
    return [_row_out(row_to_dict(r)) for r in rows]  # type: ignore[misc]


def render_markdown(doc: dict[str, Any]) -> str:
    lines = [f"# {doc.get('title') or 'Compliance Document'}", ""]
    lines.append(f"*Status: {doc.get('status', 'draft')} · Version {doc.get('version', 1)}*")
    if doc.get("control_id"):
        lines.append(f"*Mapped control: `{doc['control_id']}`{' (' + doc['framework_id'] + ')' if doc.get('framework_id') else ''}*")
    if doc.get("owner"):
        lines.append(f"*Owner: {doc['owner']}*")
    lines.append("")
    for s in doc.get("sections") or []:
        heading = s.get("heading") or "Section"
        content = (s.get("content") or "").strip()
        lines.append(f"## {heading}")
        lines.append(content if content else "_(not yet written)_")
        lines.append("")
    return "\n".join(lines)


def update_document(user_id: str, doc_id: str, fields: dict[str, Any]) -> dict[str, Any] | None:
    ensure_doc_library_schema()
    existing = get_document(user_id, doc_id)
    if not existing:
        return None
    import json as _json

    sets: list[str] = []
    args: list[Any] = []
    content_changed = False

    if "title" in fields and fields["title"]:
        sets.append("title = ?")
        args.append(str(fields["title"])[:200])
        content_changed = True  # title is rendered into the approved evidence text
    if "control_id" in fields:
        sets.append("control_id = ?")
        args.append(str(fields["control_id"] or "")[:80])
        content_changed = True
    if "framework_id" in fields:
        sets.append("framework_id = ?")
        args.append(str(fields["framework_id"] or "")[:40])
    if "owner" in fields:
        sets.append("owner = ?")
        args.append(str(fields["owner"] or "")[:120])
        content_changed = True  # owner is rendered into the approved evidence text
    if "sections" in fields:
        tpl = _TEMPLATES_BY_ID.get(existing.get("template_id") or "blank", _TEMPLATES_BY_ID["blank"])
        new_sections = _clean_sections(fields["sections"], tpl["sections"])
        sets.append("sections_json = ?")
        args.append(_json.dumps(new_sections))
        content_changed = True

    if not sets:
        return existing

    # Editing an approved document invalidates the approval — the evidence
    # it produced no longer reflects the current text. Rather than silently
    # leaving stale evidence marked "approved", drop it back to draft so a
    # reviewer has to look at it again before it counts as evidence once more.
    if content_changed and existing.get("status") == "approved":
        sets.append("status = 'draft'")
        sets.append("approved_at = NULL")

    sets.append("version = version + 1")
    sets.append("updated_at = ?")
    args.append(now())
    args.extend([doc_id, user_id])
    get_conn().execute(
        f"UPDATE compliance_documents SET {', '.join(sets)} WHERE id = ? AND user_id = ?", args
    )
    get_conn().commit()
    audit("compliance_doc_update", user_id, {"id": doc_id})
    return get_document(user_id, doc_id)


def delete_document(user_id: str, doc_id: str) -> bool:
    ensure_doc_library_schema()
    cur = get_conn().execute(
        "DELETE FROM compliance_documents WHERE id = ? AND user_id = ?", (doc_id, user_id)
    )
    get_conn().commit()
    if cur.rowcount:
        audit("compliance_doc_delete", user_id, {"id": doc_id})
    return bool(cur.rowcount)


def submit_for_review(user_id: str, doc_id: str) -> dict[str, Any] | None:
    ensure_doc_library_schema()
    doc = get_document(user_id, doc_id)
    if not doc:
        return None
    get_conn().execute(
        "UPDATE compliance_documents SET status = 'in_review', updated_at = ? WHERE id = ? AND user_id = ?",
        (now(), doc_id, user_id),
    )
    get_conn().commit()
    audit("compliance_doc_submit", user_id, {"id": doc_id})
    return get_document(user_id, doc_id)


def review_document(
    user_id: str,
    doc_id: str,
    *,
    decision: str,
    reviewer: str = "",
    comments: str = "",
) -> dict[str, Any] | None:
    """Approve or reject a document. Approving is the only path that creates
    real evidence: the rendered markdown is saved as a real file (same
    machinery a manual upload uses) and linked to the document's control via
    a real evidence_links row, so it shows up in the Evidence Control Center
    and Live SSP the moment this call returns."""
    ensure_doc_library_schema()
    doc = get_document(user_id, doc_id)
    if not doc:
        return None
    decision = (decision or "").lower().strip()
    if decision not in ("approve", "reject"):
        raise ValueError("decision must be 'approve' or 'reject'")

    ts = now()
    if decision == "reject":
        get_conn().execute(
            """
            UPDATE compliance_documents
            SET status = 'rejected', reviewer = ?, review_comments = ?, updated_at = ?
            WHERE id = ? AND user_id = ?
            """,
            (reviewer[:120], comments[:2000], ts, doc_id, user_id),
        )
        get_conn().commit()
        audit("compliance_doc_reject", user_id, {"id": doc_id, "reviewer": reviewer})
        return get_document(user_id, doc_id)

    # Approve: render -> real file on disk -> real evidence link.
    from app.commercial_ext import link_evidence
    from app.uploads import save_upload

    markdown = render_markdown(doc)
    safe_title = "".join(c if c.isalnum() or c in " _-" else "_" for c in (doc.get("title") or "document"))[:80]
    filename = f"{safe_title.strip().replace(' ', '_') or 'compliance_document'}_v{doc.get('version', 1)}.md"
    upload = save_upload(user_id, filename, markdown.encode("utf-8"), engagement_id=None, ingest=True)

    link = link_evidence(
        user_id,
        file_id=upload["id"],
        control_id=doc.get("control_id") or "",
        notes=f"Generated from compliance document '{doc.get('title')}' (v{doc.get('version', 1)}), approved by {reviewer or 'reviewer'}",
        owner=doc.get("owner") or "",
        status="accepted",
    )

    get_conn().execute(
        """
        UPDATE compliance_documents
        SET status = 'approved', reviewer = ?, review_comments = ?, evidence_link_id = ?,
            file_id = ?, approved_at = ?, updated_at = ?
        WHERE id = ? AND user_id = ?
        """,
        (reviewer[:120], comments[:2000], link["id"], upload["id"], ts, ts, doc_id, user_id),
    )
    get_conn().commit()
    audit(
        "compliance_doc_approve",
        user_id,
        {"id": doc_id, "reviewer": reviewer, "evidence_link_id": link["id"], "file_id": upload["id"]},
    )
    return get_document(user_id, doc_id)
