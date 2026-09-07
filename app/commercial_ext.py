"""Organizations, RBAC, evidence links, PDF export, Jira issues."""

from __future__ import annotations

import re
from typing import Any

import httpx

from app.config import settings
from app.db import audit, get_conn, new_id, now, row_to_dict

ROLES = ("admin", "analyst", "viewer", "client")


def ensure_org_schema() -> None:
    c = get_conn()
    c.executescript(
        """
        CREATE TABLE IF NOT EXISTS organizations (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            slug TEXT UNIQUE NOT NULL,
            owner_user_id TEXT NOT NULL,
            created_at REAL NOT NULL,
            updated_at REAL NOT NULL
        );
        CREATE TABLE IF NOT EXISTS org_members (
            id TEXT PRIMARY KEY,
            org_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
            user_id TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'analyst',
            created_at REAL NOT NULL,
            UNIQUE(org_id, user_id)
        );
        CREATE TABLE IF NOT EXISTS evidence_links (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            engagement_id TEXT,
            file_id TEXT NOT NULL,
            remediation_id TEXT,
            control_id TEXT NOT NULL DEFAULT '',
            notes TEXT NOT NULL DEFAULT '',
            owner TEXT NOT NULL DEFAULT '',
            status TEXT NOT NULL DEFAULT 'accepted',
            expiry TEXT NOT NULL DEFAULT '',
            created_at REAL NOT NULL
        );
        """
    )
    ev_cols = {r[1] for r in c.execute("PRAGMA table_info(evidence_links)").fetchall()}
    for col, ddl in (
        ("owner", "ALTER TABLE evidence_links ADD COLUMN owner TEXT NOT NULL DEFAULT ''"),
        ("status", "ALTER TABLE evidence_links ADD COLUMN status TEXT NOT NULL DEFAULT 'accepted'"),
        ("expiry", "ALTER TABLE evidence_links ADD COLUMN expiry TEXT NOT NULL DEFAULT ''"),
    ):
        if col not in ev_cols:
            c.execute(ddl)
    cols = {r[1] for r in c.execute("PRAGMA table_info(engagements)").fetchall()}
    if "org_id" not in cols:
        c.execute("ALTER TABLE engagements ADD COLUMN org_id TEXT")
    c.commit()


def _slugify(name: str) -> str:
    s = re.sub(r"[^a-z0-9]+", "-", (name or "").lower()).strip("-")
    return s[:48] or new_id()[:8]


def create_org(user_id: str, name: str) -> dict[str, Any]:
    ensure_org_schema()
    oid = new_id()
    ts = now()
    slug = _slugify(name)
    base = slug
    n = 1
    c = get_conn()
    while c.execute("SELECT 1 FROM organizations WHERE slug = ?", (slug,)).fetchone():
        n += 1
        slug = f"{base}-{n}"
    c.execute(
        "INSERT INTO organizations (id, name, slug, owner_user_id, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)",
        (oid, name.strip(), slug, user_id, ts, ts),
    )
    c.execute(
        "INSERT INTO org_members (id, org_id, user_id, role, created_at) VALUES (?, ?, ?, ?, ?)",
        (new_id(), oid, user_id, "admin", ts),
    )
    c.commit()
    audit("org_create", user_id, {"id": oid, "name": name})
    return get_org(user_id, oid)  # type: ignore[return-value]


def get_org(user_id: str, org_id: str) -> dict[str, Any] | None:
    ensure_org_schema()
    row = get_conn().execute(
        """
        SELECT o.*, m.role AS member_role
        FROM organizations o
        JOIN org_members m ON m.org_id = o.id
        WHERE o.id = ? AND m.user_id = ?
        """,
        (org_id, user_id),
    ).fetchone()
    return row_to_dict(row)


def list_orgs(user_id: str) -> list[dict[str, Any]]:
    ensure_org_schema()
    rows = get_conn().execute(
        """
        SELECT o.*, m.role AS member_role
        FROM organizations o
        JOIN org_members m ON m.org_id = o.id
        WHERE m.user_id = ?
        ORDER BY o.updated_at DESC
        """,
        (user_id,),
    ).fetchall()
    return [row_to_dict(r) for r in rows]  # type: ignore[misc]


def add_org_member(actor_id: str, org_id: str, username: str, role: str = "analyst") -> dict[str, Any]:
    ensure_org_schema()
    if role not in ROLES:
        raise ValueError(f"role must be one of {ROLES}")
    org = get_org(actor_id, org_id)
    if not org or org.get("member_role") != "admin":
        raise PermissionError("Admin role required")
    c = get_conn()
    user = c.execute(
        "SELECT id, username, role FROM users WHERE username = ?", (username.strip(),)
    ).fetchone()
    if not user:
        raise ValueError("User not found — ask them to register first")
    mid = new_id()
    try:
        c.execute(
            "INSERT INTO org_members (id, org_id, user_id, role, created_at) VALUES (?, ?, ?, ?, ?)",
            (mid, org_id, user["id"], role, now()),
        )
        c.commit()
    except Exception as exc:
        raise ValueError("Member already exists or invalid") from exc
    audit("org_member_add", actor_id, {"org_id": org_id, "user_id": user["id"], "role": role})
    return {
        "id": mid,
        "org_id": org_id,
        "user_id": user["id"],
        "username": user["username"],
        "role": role,
    }


def list_org_members(user_id: str, org_id: str) -> list[dict[str, Any]]:
    ensure_org_schema()
    if not get_org(user_id, org_id):
        raise PermissionError("Not a member")
    rows = get_conn().execute(
        """
        SELECT m.id, m.org_id, m.user_id, m.role, m.created_at,
               COALESCE(u.username, m.user_id) AS username
        FROM org_members m
        LEFT JOIN users u ON u.id = m.user_id
        WHERE m.org_id = ?
        ORDER BY m.created_at
        """,
        (org_id,),
    ).fetchall()
    return [row_to_dict(r) for r in rows]  # type: ignore[misc]


def link_evidence(
    user_id: str,
    *,
    file_id: str,
    remediation_id: str | None = None,
    control_id: str = "",
    notes: str = "",
    owner: str = "",
    status: str = "accepted",
    expiry: str = "",
    engagement_id: str | None = None,
) -> dict[str, Any]:
    ensure_org_schema()
    c = get_conn()
    f = c.execute("SELECT id FROM files WHERE id = ? AND user_id = ?", (file_id, user_id)).fetchone()
    if not f:
        raise ValueError("File not found")
    eid = new_id()
    st = (status or "accepted").lower()[:40]
    if st not in {"draft", "accepted", "expired", "rejected", "review"}:
        st = "accepted"
    c.execute(
        """
        INSERT INTO evidence_links
        (id, user_id, engagement_id, file_id, remediation_id, control_id, notes,
         owner, status, expiry, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            eid,
            user_id,
            engagement_id,
            file_id,
            remediation_id,
            (control_id or "")[:80],
            (notes or "")[:2000],
            (owner or "")[:120],
            st,
            (expiry or "")[:40],
            now(),
        ),
    )
    c.commit()
    audit("evidence_link", user_id, {"id": eid, "file_id": file_id, "remediation_id": remediation_id})
    return get_evidence_link(user_id, eid)  # type: ignore[return-value]


def update_evidence_link(user_id: str, link_id: str, fields: dict[str, Any]) -> dict[str, Any] | None:
    ensure_org_schema()
    allowed = {"control_id", "notes", "owner", "status", "expiry", "remediation_id"}
    sets: list[str] = []
    args: list[Any] = []
    for k, v in fields.items():
        if k not in allowed or v is None:
            continue
        if k == "status":
            v = str(v).lower()[:40]
            if v not in {"draft", "accepted", "expired", "rejected", "review"}:
                continue
        sets.append(f"{k} = ?")
        args.append(v)
    if not sets:
        return get_evidence_link(user_id, link_id)
    args.extend([link_id, user_id])
    cur = get_conn().execute(
        f"UPDATE evidence_links SET {', '.join(sets)} WHERE id = ? AND user_id = ?",
        args,
    )
    get_conn().commit()
    if not cur.rowcount:
        return None
    audit("evidence_update", user_id, {"id": link_id})
    return get_evidence_link(user_id, link_id)


def get_evidence_link(user_id: str, link_id: str) -> dict[str, Any] | None:
    row = get_conn().execute(
        """
        SELECT e.*, f.filename, f.size_bytes
        FROM evidence_links e
        LEFT JOIN files f ON f.id = e.file_id
        WHERE e.id = ? AND e.user_id = ?
        """,
        (link_id, user_id),
    ).fetchone()
    return row_to_dict(row)


def list_evidence_links(
    user_id: str,
    *,
    remediation_id: str | None = None,
    engagement_id: str | None = None,
) -> list[dict[str, Any]]:
    ensure_org_schema()
    q = """
        SELECT e.*, f.filename, f.size_bytes,
               r.title AS remediation_title, r.owner AS remediation_owner, r.status AS remediation_status
        FROM evidence_links e
        LEFT JOIN files f ON f.id = e.file_id
        LEFT JOIN gap_remediations r ON r.id = e.remediation_id
        WHERE e.user_id = ?
    """
    args: list[Any] = [user_id]
    if remediation_id:
        q += " AND e.remediation_id = ?"
        args.append(remediation_id)
    if engagement_id:
        q += " AND e.engagement_id = ?"
        args.append(engagement_id)
    q += " ORDER BY e.created_at DESC LIMIT 200"
    return [row_to_dict(r) for r in get_conn().execute(q, args).fetchall()]  # type: ignore[misc]


def delete_evidence_link(user_id: str, link_id: str) -> bool:
    cur = get_conn().execute(
        "DELETE FROM evidence_links WHERE id = ? AND user_id = ?", (link_id, user_id)
    )
    get_conn().commit()
    return bool(cur.rowcount)


def _pdf_escape(text: str) -> str:
    return text.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")


def _pdf_wrap(text: str, width: int = 92) -> list[str]:
    text = re.sub(r"\s+", " ", (text or "").strip())
    if not text:
        return [""]
    out: list[str] = []
    while len(text) > width:
        cut = text.rfind(" ", 0, width)
        if cut < 40:
            cut = width
        out.append(text[:cut].rstrip())
        text = text[cut:].lstrip()
    if text:
        out.append(text)
    return out


def _pdf_plain(line: str) -> str:
    s = re.sub(r"[#>*`]+", "", line or "")
    s = re.sub(r"\*\*([^*]+)\*\*", r"\1", s)
    s = re.sub(r"\*([^*]+)\*", r"\1", s)
    return s.strip()


def markdown_to_simple_pdf(md: str, title: str = "SecuraIQ Report") -> bytes:
    """Render Markdown VA/scan reports as a structured multi-page PDF.

    Layout: branded header, severity summary when present, section headings,
    per-finding detail, and a footer with title + page number. Pure stdlib —
    no reportlab dependency.
    """
    from datetime import datetime, timezone

    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    body_rows: list[tuple[str, str]] = []  # (style, text) style: h1|h2|h3|body|bullet|rule|blank

    body_rows.append(("h1", title))
    body_rows.append(("body", f"Generated {generated}  |  SecuraIQ authorized security report"))
    body_rows.append(("rule", ""))

    for raw in (md or "").splitlines():
        plain = raw.rstrip()
        if not plain.strip():
            body_rows.append(("blank", ""))
            continue
        if plain.startswith("### "):
            body_rows.append(("h3", _pdf_plain(plain[4:])))
            continue
        if plain.startswith("## "):
            body_rows.append(("blank", ""))
            body_rows.append(("h2", _pdf_plain(plain[3:])))
            body_rows.append(("rule", ""))
            continue
        if plain.startswith("# "):
            # Skip duplicate top-level title when it matches our header.
            t = _pdf_plain(plain[2:])
            if t.lower() not in {title.lower(), "securaiq scan report", "securaiq va report"}:
                body_rows.append(("h1", t))
            continue
        if plain.lstrip().startswith(("- ", "* ")):
            body_rows.append(("bullet", _pdf_plain(plain.lstrip()[2:])))
            continue
        if re.match(r"^\d+\.\s+", plain.lstrip()):
            body_rows.append(("bullet", _pdf_plain(re.sub(r"^\d+\.\s+", "", plain.lstrip()))))
            continue
        body_rows.append(("body", _pdf_plain(plain)))

    # Expand wrapped lines into draw ops (style, text).
    draw: list[tuple[str, str]] = []
    for style, text in body_rows:
        if style in {"blank", "rule"}:
            draw.append((style, ""))
            continue
        width = 88 if style == "bullet" else 92
        wrapped = _pdf_wrap(text, width=width)
        for i, w in enumerate(wrapped):
            st = style if i == 0 else ("body" if style != "bullet" else "bullet")
            draw.append((st, w))

    # Paginate (~48 content lines / page, leave room for header/footer).
    lines_per_page = 46
    pages: list[list[tuple[str, str]]] = []
    chunk: list[tuple[str, str]] = []
    for row in draw:
        chunk.append(row)
        if len(chunk) >= lines_per_page:
            pages.append(chunk)
            chunk = []
    if chunk:
        pages.append(chunk)
    if not pages:
        pages = [[("h1", title), ("body", "(empty report)")]]

    def _page_stream(page_lines: list[tuple[str, str]], page_no: int, page_count: int) -> bytes:
        # Content stream with bold/regular fonts and a footer.
        parts: list[str] = []
        y = 752
        # Top header bar (simple line)
        parts.append("0.15 0.25 0.45 rg 40 770 532 18 re f")
        parts.append("1 1 1 rg BT /F2 10 Tf 48 775 Td (SecuraIQ) Tj ET")
        parts.append("0 0 0 rg")
        parts.append("BT")
        first = True
        for style, text in page_lines:
            if style == "blank":
                y -= 10
                continue
            if style == "rule":
                parts.append("ET")
                parts.append(f"0.75 0.75 0.75 rg 50 {y} 512 0.8 re f 0 0 0 rg")
                parts.append("BT")
                first = True
                y -= 12
                continue
            if y < 72:
                break
            esc = _pdf_escape(text[:220])
            if style == "h1":
                font, size, leading = "/F2", 16, 20
            elif style == "h2":
                font, size, leading = "/F2", 13, 17
            elif style == "h3":
                font, size, leading = "/F2", 11, 15
            elif style == "bullet":
                font, size, leading = "/F1", 10, 13
                esc = _pdf_escape(("• " + text)[:220])
            else:
                font, size, leading = "/F1", 10, 13
            if first:
                parts.append(f"{font} {size} Tf 50 {y} Td")
                first = False
            else:
                parts.append(f"0 -{leading} Td {font} {size} Tf")
            parts.append(f"({esc}) Tj")
            y -= leading
        parts.append("ET")
        # Footer
        foot = _pdf_escape(f"{title[:60]}  |  page {page_no}/{page_count}  |  {generated}")
        parts.append(f"0.45 0.45 0.45 rg BT /F1 8 Tf 50 36 Td ({foot}) Tj ET 0 0 0 rg")
        parts.append(f"0.8 0.8 0.8 rg 50 48 512 0.6 re f")
        stream = "\n".join(parts).encode("latin-1", errors="replace")
        return stream

    pdf_objs: dict[int, bytes] = {}
    pdf_objs[1] = b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>"
    pdf_objs[2] = b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold >>"
    next_id = 3
    content_refs: list[int] = []
    page_count = len(pages)
    for idx, page_lines in enumerate(pages, start=1):
        stream = _page_stream(page_lines, idx, page_count)
        pdf_objs[next_id] = (
            f"<< /Length {len(stream)} >>\nstream\n".encode() + stream + b"\nendstream"
        )
        content_refs.append(next_id)
        next_id += 1

    pages_id = next_id + len(content_refs)
    page_ids: list[int] = []
    for cref in content_refs:
        pid = next_id
        next_id += 1
        page_ids.append(pid)
        pdf_objs[pid] = (
            f"<< /Type /Page /Parent {pages_id} 0 R /MediaBox [0 0 612 792] "
            f"/Contents {cref} 0 R /Resources << /Font << /F1 1 0 R /F2 2 0 R >> >> >>"
        ).encode()
    kids = " ".join(f"{pid} 0 R" for pid in page_ids)
    pdf_objs[pages_id] = f"<< /Type /Pages /Kids [{kids}] /Count {len(page_ids)} >>".encode()
    catalog_id = pages_id + 1
    pdf_objs[catalog_id] = f"<< /Type /Catalog /Pages {pages_id} 0 R >>".encode()

    buf = bytearray(b"%PDF-1.4\n")
    offsets = {0: 0}
    for i in sorted(pdf_objs):
        offsets[i] = len(buf)
        buf.extend(f"{i} 0 obj\n".encode())
        buf.extend(pdf_objs[i])
        buf.extend(b"\nendobj\n")
    xref_pos = len(buf)
    max_id = max(pdf_objs)
    buf.extend(f"xref\n0 {max_id + 1}\n".encode())
    buf.extend(b"0000000000 65535 f \n")
    for i in range(1, max_id + 1):
        off = offsets.get(i, 0)
        buf.extend(f"{off:010d} 00000 n \n".encode())
    buf.extend(
        f"trailer\n<< /Size {max_id + 1} /Root {catalog_id} 0 R >>\nstartxref\n{xref_pos}\n%%EOF\n".encode()
    )
    return bytes(buf)


def build_executive_pdf(user_id: str) -> bytes:
    from app.enterprise import enterprise_dashboard

    dash = enterprise_dashboard(user_id)
    lines = [
        "# SecuraIQ Executive Security Report",
        "",
        f"Compliance score: **{dash.get('compliance_score')}%**",
        f"Open risks: **{dash.get('risks_open')}**",
        f"Open vulnerabilities: **{dash.get('vulnerabilities_open')}** "
        f"(crit/high: {dash.get('vulnerabilities_critical_high')})",
        f"Open remediations: **{dash.get('remediations_open')}**",
        f"Assets: **{dash.get('assets_total')}**",
        "",
        "## Recommendations",
    ]
    for r in dash.get("recommendations") or []:
        if isinstance(r, dict):
            lines.append(f"- [{r.get('priority', 'med').upper()}] {r.get('title')}")
        else:
            lines.append(f"- {r}")
    lines += ["", "## Frameworks"]
    for f in dash.get("frameworks") or []:
        lines.append(
            f"- {f.get('framework_id')}: {f.get('compliance_percent')}% — {f.get('title')}"
        )
    lines += ["", "---", "_Generated by SecuraIQ for authorized security work._"]
    return markdown_to_simple_pdf("\n".join(lines), title="SecuraIQ Executive Report")


async def jira_create_issue(
    *,
    summary: str,
    description: str,
    issue_type: str = "Task",
) -> dict[str, Any]:
    base = (settings.jira_base_url or "").rstrip("/")
    email = settings.jira_email or ""
    token = settings.jira_api_token or ""
    project = settings.jira_project_key or ""
    if not (base and email and token and project):
        raise ValueError(
            "Jira not configured. Set JIRA_BASE_URL, JIRA_EMAIL, JIRA_API_TOKEN, JIRA_PROJECT_KEY"
        )
    payload = {
        "fields": {
            "project": {"key": project},
            "summary": summary[:255],
            "description": description[:5000],
            "issuetype": {"name": issue_type},
        }
    }
    async with httpx.AsyncClient(timeout=30.0) as client:
        resp = await client.post(
            f"{base}/rest/api/2/issue",
            json=payload,
            auth=(email, token),
            headers={"Accept": "application/json", "Content-Type": "application/json"},
        )
    if resp.status_code >= 400:
        raise ValueError(f"Jira error {resp.status_code}: {resp.text[:400]}")
    data = resp.json()
    key = data.get("key")
    return {
        "ok": True,
        "key": key,
        "id": data.get("id"),
        "url": f"{base}/browse/{key}" if key else None,
        "raw": data,
    }
