"""Ops surfaces: incidents, threat intel watchlist, reports catalog, global search."""

from __future__ import annotations

from typing import Any

from app.db import audit, get_conn, new_id, now, row_to_dict
from app.enterprise import (
    list_assets,
    list_campaigns,
    list_playbooks,
    list_remediations,
    list_risks,
    list_vulnerabilities,
)


def create_incident(
    user_id: str,
    *,
    title: str,
    severity: str = "high",
    status: str = "open",
    source: str = "manual",
    owner: str = "",
    playbook_id: str | None = None,
    summary: str = "",
    engagement_id: str | None = None,
    org_id: str | None = None,
) -> dict[str, Any]:
    from app.tenancy import ensure_tenant_schema, primary_org_id

    ensure_tenant_schema()
    oid = org_id or primary_org_id(user_id)
    iid = new_id()
    ts = now()
    c = get_conn()
    c.execute(
        """
        INSERT INTO incidents
        (id, user_id, engagement_id, org_id, title, severity, status, source, owner, playbook_id, summary, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            iid,
            user_id,
            engagement_id,
            oid,
            title.strip(),
            severity,
            status,
            source,
            owner,
            playbook_id,
            summary,
            ts,
            ts,
        ),
    )
    c.commit()
    audit("incident_create", user_id, {"id": iid, "title": title, "org_id": oid})

    from app.notifications import notify

    notify(
        user_id,
        "incident",
        f"New incident: {title.strip()}",
        f"Severity: {severity} · Source: {source}" + (f" · {summary}" if summary else ""),
        link=f"/api/incidents/{iid}",
        email=(severity in ("critical", "high")),
    )

    try:
        from app.realtime_bus import publish

        publish(type="incident", id=iid, severity=severity, user_id=user_id, org_id=oid)
    except Exception:
        pass

    if severity in ("critical", "high"):
        import asyncio

        from app.connectors import slack, teams

        alert_text = f"🚨 *New incident* ({severity}): {title.strip()}" + (f"\n{summary}" if summary else "")
        if slack.is_configured():
            asyncio.create_task(slack.send_message(alert_text))
        if teams.is_configured():
            asyncio.create_task(teams.send_message(f"Incident: {title.strip()}", alert_text))

    return get_incident(user_id, iid)  # type: ignore[return-value]


def get_incident(user_id: str, incident_id: str) -> dict[str, Any] | None:
    from app.tenancy import ensure_tenant_schema, row_visible_to_user

    ensure_tenant_schema()
    row = get_conn().execute("SELECT * FROM incidents WHERE id = ?", (incident_id,)).fetchone()
    d = row_to_dict(row)
    if d and not row_visible_to_user(user_id, d):
        return None
    return d


def list_incidents(
    user_id: str,
    engagement_id: str | None = None,
    status: str | None = None,
    *,
    org_id: str | None = None,
) -> list[dict[str, Any]]:
    from app.tenancy import ensure_tenant_schema, tenant_visibility_sql

    ensure_tenant_schema()
    where, args = tenant_visibility_sql(user_id, org_id=org_id)
    q = f"SELECT * FROM incidents WHERE {where}"
    if engagement_id:
        q += " AND engagement_id = ?"
        args.append(engagement_id)
    if status:
        q += " AND status = ?"
        args.append(status)
    q += " ORDER BY updated_at DESC LIMIT 200"
    return [row_to_dict(r) for r in get_conn().execute(q, args).fetchall()]  # type: ignore[misc]


def update_incident(user_id: str, incident_id: str, patch: dict[str, Any]) -> dict[str, Any] | None:
    row = get_incident(user_id, incident_id)
    if not row:
        return None
    allowed = {"title", "severity", "status", "source", "owner", "playbook_id", "summary", "engagement_id"}
    data = {k: v for k, v in patch.items() if k in allowed and v is not None}
    if not data:
        return row
    data["updated_at"] = now()
    sets = ", ".join(f"{k} = ?" for k in data)
    get_conn().execute(
        f"UPDATE incidents SET {sets} WHERE id = ?",
        (*data.values(), incident_id),
    )
    get_conn().commit()
    audit("incident_update", user_id, {"id": incident_id, **data})
    return get_incident(user_id, incident_id)


def delete_incident(user_id: str, incident_id: str) -> bool:
    if not get_incident(user_id, incident_id):
        return False
    cur = get_conn().execute("DELETE FROM incidents WHERE id = ?", (incident_id,))
    get_conn().commit()
    if cur.rowcount:
        audit("incident_delete", user_id, {"id": incident_id})
        return True
    return False


def ensure_seed_incidents(user_id: str) -> None:
    """No-op — workspaces start empty (no demo incidents)."""
    return


def purge_demo_seed(user_id: str) -> dict[str, int]:
    """Remove well-known demo seed rows if present (idempotent)."""
    c = get_conn()
    titles = (
        "Suspicious MFA fatigue attempts",
        "Critical CVE observed on internet-facing host",
    )
    removed_inc = 0
    for title in titles:
        cur = c.execute(
            "DELETE FROM incidents WHERE user_id = ? AND title = ?",
            (user_id, title),
        )
        removed_inc += int(cur.rowcount or 0)
    pb_titles = (
        "Ransomware — workstation containment",
        "Phishing / BEC triage",
        "Suspected insider data staging",
    )
    removed_pb = 0
    for title in pb_titles:
        cur = c.execute(
            "DELETE FROM playbooks WHERE user_id = ? AND title = ?",
            (user_id, title),
        )
        removed_pb += int(cur.rowcount or 0)
    try:
        from app.enterprise import _DEFAULT_PLAYBOOKS

        for pb in _DEFAULT_PLAYBOOKS:
            t = (pb.get("title") or "").strip()
            if not t:
                continue
            cur = c.execute(
                "DELETE FROM playbooks WHERE user_id = ? AND title = ?",
                (user_id, t),
            )
            removed_pb += int(cur.rowcount or 0)
    except Exception:
        pass
    if removed_inc or removed_pb:
        c.commit()
    return {"incidents": removed_inc, "playbooks": removed_pb}


def add_intel_watch(
    user_id: str, *, kind: str, value: str, notes: str = "", org_id: str | None = None
) -> dict[str, Any]:
    from app.tenancy import ensure_tenant_schema, primary_org_id

    ensure_tenant_schema()
    oid = org_id or primary_org_id(user_id)
    wid = new_id()
    ts = now()
    get_conn().execute(
        "INSERT INTO intel_watch (id, user_id, org_id, kind, value, notes, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
        (wid, user_id, oid, kind.strip() or "cve", value.strip(), notes, ts),
    )
    get_conn().commit()
    audit("intel_watch_add", user_id, {"id": wid, "value": value, "org_id": oid})
    row = get_conn().execute("SELECT * FROM intel_watch WHERE id = ?", (wid,)).fetchone()
    result = row_to_dict(row)
    try:
        from app.realtime_bus import publish

        publish(type="intel_watch", id=wid, kind=kind, value=value, user_id=user_id, org_id=oid)
    except Exception:
        pass
    return result  # type: ignore[return-value]


def list_intel_watch(user_id: str, *, org_id: str | None = None) -> list[dict[str, Any]]:
    from app.tenancy import ensure_tenant_schema, tenant_visibility_sql

    ensure_tenant_schema()
    where, args = tenant_visibility_sql(user_id, org_id=org_id)
    rows = get_conn().execute(
        f"SELECT * FROM intel_watch WHERE {where} ORDER BY created_at DESC LIMIT 100",
        args,
    ).fetchall()
    return [row_to_dict(r) for r in rows]  # type: ignore[misc]


def delete_intel_watch(user_id: str, watch_id: str) -> bool:
    from app.tenancy import ensure_tenant_schema, row_visible_to_user

    ensure_tenant_schema()
    row = get_conn().execute("SELECT * FROM intel_watch WHERE id = ?", (watch_id,)).fetchone()
    d = row_to_dict(row)
    if not d or not row_visible_to_user(user_id, d):
        return False
    cur = get_conn().execute("DELETE FROM intel_watch WHERE id = ?", (watch_id,))
    get_conn().commit()
    ok = bool(cur.rowcount)
    if ok:
        try:
            from app.realtime_bus import publish

            publish(type="intel_watch", id=watch_id, deleted=True, user_id=user_id)
        except Exception:
            pass
    return ok


def reports_catalog(user_id: str) -> dict[str, Any]:
    from app.gap_analysis import list_assessments
    from app.scan_engine.models import ensure_scans_schema, list_scans

    assessments = list_assessments(user_id)
    items: list[dict[str, Any]] = []

    # Per-scan reports first (what users look for after New scan)
    try:
        ensure_scans_schema()
        for s in list_scans(user_id, limit=30):
            if (s.get("status") or "") != "completed":
                continue
            sid = s.get("id")
            target = s.get("target") or "target"
            scanner = s.get("scanner") or "scan"
            findings = (s.get("summary") or {}).get("findings_created")
            title = f"Scan - {target} ({scanner})"
            if findings is not None:
                title += f" - {findings} findings"
            items.append(
                {
                    "id": f"scan-{sid}",
                    "title": title,
                    "href": f"/api/scans/{sid}/report",
                    "kind": "scan",
                    "scan_id": sid,
                    "created_at": s.get("created_at"),
                }
            )
            items.append(
                {
                    "id": f"scan-pdf-{sid}",
                    "title": f"{title} (PDF)",
                    "href": f"/api/scans/{sid}/report.pdf",
                    "kind": "pdf",
                    "scan_id": sid,
                    "created_at": s.get("created_at"),
                }
            )
    except Exception:
        pass

    # Archived scans (survives clear / workspace reset)
    try:
        from app.archive import list_archives

        items.extend(list_archives(user_id, limit=20))
    except Exception:
        pass

    items.extend(
        [
        {
            "id": "exec-pdf",
            "title": "Executive security report (PDF)",
            "href": "/api/reports/executive.pdf",
            "kind": "pdf",
        },
        {
            "id": "exec-docx",
            "title": "Executive security report (DOCX)",
            "href": "/api/reports/executive.docx",
            "kind": "docx",
        },
        {
            "id": "compliance-docx",
            "title": "Compliance report (DOCX)",
            "href": "/api/reports/compliance.docx",
            "kind": "docx",
        },
        {
            "id": "risks-pdf",
            "title": "Risk register (PDF)",
            "href": "/api/reports/risks.pdf",
            "kind": "pdf",
        },
        {
            "id": "risks-xlsx",
            "title": "Risk register (Excel)",
            "href": "/api/reports/risks.xlsx",
            "kind": "xlsx",
        },
        {
            "id": "vulns-pdf",
            "title": "Vulnerability summary (PDF)",
            "href": "/api/reports/vulns.pdf",
            "kind": "pdf",
        },
        {
            "id": "vulns-xlsx",
            "title": "Vulnerability summary (Excel)",
            "href": "/api/reports/vulns.xlsx",
            "kind": "xlsx",
        },
        {
            "id": "risks",
            "title": "Risk register (Markdown)",
            "href": "/api/risks/export",
            "kind": "risk",
        },
        {
            "id": "vulns",
            "title": "Vulnerability summary (Markdown)",
            "href": "/api/vulnerabilities/export",
            "kind": "vuln",
        },
        ]
    )
    for a in assessments[:20]:
        items.append(
            {
                "id": a.get("id"),
                "title": f"Gap — {a.get('framework_id')} — {a.get('title')} ({a.get('compliance_percent')}%)",
                "href": f"/api/gap/assessments/{a.get('id')}/export",
                "kind": "gap",
            }
        )
        items.append(
            {
                "id": f"audit-pack-{a.get('id')}",
                "title": f"Audit pack ZIP — {a.get('framework_id')} — {a.get('title')}",
                "href": f"/api/gap/assessments/{a.get('id')}/audit-pack",
                "kind": "audit_pack",
            }
        )
    return {"reports": items, "count": len(items)}


def global_search(user_id: str, q: str) -> dict[str, Any]:
    query = (q or "").strip().lower()
    if not query:
        return {"query": q, "results": []}
    results: list[dict[str, Any]] = []

    def add(kind: str, title: str, meta: str = "", ref: str = "") -> None:
        results.append({"kind": kind, "title": title, "meta": meta, "ref": ref})

    for a in list_assets(user_id):
        blob = f"{a.get('name','')} {a.get('asset_type','')} {a.get('owner','')}".lower()
        if query in blob:
            add("asset", a.get("name") or "asset", a.get("criticality") or "", a.get("id") or "")
    for r in list_risks(user_id):
        blob = f"{r.get('threat','')} {r.get('asset_name','')} {r.get('owner','')}".lower()
        if query in blob:
            add("risk", r.get("threat") or "risk", f"score {r.get('risk_score')}", r.get("id") or "")
    for v in list_vulnerabilities(user_id):
        blob = f"{v.get('cve','')} {v.get('title','')} {v.get('asset_name','')}".lower()
        if query in blob:
            add("vuln", f"{v.get('cve') or ''} {v.get('title')}".strip(), v.get("severity") or "", v.get("id") or "")
    for rem in list_remediations(user_id):
        blob = f"{rem.get('control_id','')} {rem.get('title','')}".lower()
        if query in blob:
            add("remediation", f"{rem.get('control_id')} — {rem.get('title')}", rem.get("status") or "", rem.get("id") or "")
    for p in list_playbooks(user_id):
        if query in (p.get("title") or "").lower():
            add("playbook", p.get("title") or "playbook", p.get("severity") or "", p.get("id") or "")
    for camp in list_campaigns(user_id):
        if query in (camp.get("name") or "").lower():
            add("campaign", camp.get("name") or "campaign", camp.get("status") or "", camp.get("id") or "")
    for inc in list_incidents(user_id):
        if query in (inc.get("title") or "").lower():
            add("incident", inc.get("title") or "incident", inc.get("severity") or "", inc.get("id") or "")
    for w in list_intel_watch(user_id):
        if query in (w.get("value") or "").lower():
            add("intel", w.get("value") or "watch", w.get("kind") or "", w.get("id") or "")

    return {"query": q, "results": results[:40], "count": len(results[:40])}


def soc_overview(user_id: str) -> dict[str, Any]:
    purge_demo_seed(user_id)
    incidents = list_incidents(user_id)
    open_inc = [i for i in incidents if (i.get("status") or "") == "open"]
    vulns = [v for v in list_vulnerabilities(user_id) if (v.get("status") or "") == "open"]
    crit = [v for v in vulns if (v.get("severity") or "") in {"critical", "high"}]
    playbooks = list_playbooks(user_id)
    return {
        "incidents_open": len(open_inc),
        "incidents_total": len(incidents),
        "critical_vulns": len(crit),
        "playbooks": len(playbooks),
        "incidents": open_inc[:10],
        "alerts": [
            *[{"kind": "vuln", "title": f"{v.get('severity')}: {v.get('cve') or ''} {v.get('title')}".strip()} for v in crit[:5]],
            *[{"kind": "incident", "title": i.get("title")} for i in open_inc[:5]],
        ],
    }
