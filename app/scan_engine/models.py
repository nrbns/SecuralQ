"""Scan persistence — scans table + evidence paths."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from app.config import settings
from app.db import get_conn, new_id, now, row_to_dict

SCAN_STATUSES = (
    "queued",
    "scope_check",
    "running",
    "collecting",
    "parsing",
    "normalizing",
    "completed",
    "failed",
    "blocked",
)

DEFAULT_PROGRESS = [
    {"id": "queued", "label": "Queued", "status": "pending"},
    {"id": "scope", "label": "Scope check", "status": "pending"},
    {"id": "discovery", "label": "Discovery", "status": "pending"},
    {"id": "port_scan", "label": "Port scanning", "status": "pending"},
    {"id": "service_detect", "label": "Service detection", "status": "pending"},
    {"id": "collecting", "label": "Collecting evidence", "status": "pending"},
    {"id": "parsing", "label": "Parsing", "status": "pending"},
    {"id": "normalizing", "label": "Normalization", "status": "pending"},
    {"id": "risk", "label": "Risk analysis", "status": "pending"},
    {"id": "report", "label": "Report ready", "status": "pending"},
]

# Same step ids as DEFAULT_PROGRESS (executor + web_builtin map onto them),
# but labels match SecuraIQ Web Scanner work — not nmap port/service phases.
WEB_DEFAULT_PROGRESS = [
    {"id": "queued", "label": "Queued", "status": "pending"},
    {"id": "scope", "label": "Scope check", "status": "pending"},
    {"id": "discovery", "label": "Fetching URL", "status": "pending"},
    {"id": "port_scan", "label": "Headers & cookies", "status": "pending"},
    {"id": "service_detect", "label": "Path probes", "status": "pending"},
    {"id": "collecting", "label": "Active checks", "status": "pending"},
    {"id": "parsing", "label": "Parsing findings", "status": "pending"},
    {"id": "normalizing", "label": "Normalization", "status": "pending"},
    {"id": "risk", "label": "Risk analysis", "status": "pending"},
    {"id": "report", "label": "Report ready", "status": "pending"},
]


def progress_template_for(*, scanner: str = "", profile: str = "") -> list[dict[str, str]]:
    sid = (scanner or "").lower().strip()
    prof = (profile or "").lower().strip()
    if sid == "zap" or prof == "web":
        return [dict(s) for s in WEB_DEFAULT_PROGRESS]
    return [dict(s) for s in DEFAULT_PROGRESS]


def ensure_scans_schema() -> None:
    c = get_conn()
    c.execute(
        """
        CREATE TABLE IF NOT EXISTS scans (
            id TEXT PRIMARY KEY,
            org_id TEXT,
            engagement_id TEXT,
            user_id TEXT NOT NULL,
            target TEXT NOT NULL,
            scope_json TEXT NOT NULL DEFAULT '[]',
            scanner TEXT NOT NULL DEFAULT 'securaiq',
            profile TEXT NOT NULL DEFAULT 'discovery',
            status TEXT NOT NULL DEFAULT 'queued',
            authorized INTEGER NOT NULL DEFAULT 0,
            job_id TEXT,
            progress_json TEXT NOT NULL DEFAULT '[]',
            error TEXT NOT NULL DEFAULT '',
            summary_json TEXT NOT NULL DEFAULT '{}',
            evidence_dir TEXT NOT NULL DEFAULT '',
            started_at REAL,
            completed_at REAL,
            created_at REAL NOT NULL
        )
        """
    )
    c.commit()


def evidence_root(scan_id: str) -> Path:
    root = Path(settings.data_dir) / "evidence" / "scans" / scan_id
    root.mkdir(parents=True, exist_ok=True)
    return root


def create_scan(
    *,
    user_id: str,
    target: str,
    scanner: str = "securaiq",
    profile: str = "discovery",
    scope: list[str] | None = None,
    engagement_id: str | None = None,
    org_id: str | None = None,
    authorized: bool = False,
) -> dict[str, Any]:
    from app.tenancy import ensure_tenant_schema, primary_org_id

    ensure_scans_schema()
    ensure_tenant_schema()
    oid = org_id or primary_org_id(user_id)
    sid = new_id()
    ev = evidence_root(sid)
    scanner_id = (scanner or "securaiq").lower()
    profile_id = (profile or "discovery").lower()
    progress = json.dumps(progress_template_for(scanner=scanner_id, profile=profile_id))
    c = get_conn()
    c.execute(
        """
        INSERT INTO scans (
            id, org_id, engagement_id, user_id, target, scope_json, scanner, profile,
            status, authorized, progress_json, evidence_dir, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'queued', ?, ?, ?, ?)
        """,
        (
            sid,
            oid,
            engagement_id,
            user_id,
            target.strip(),
            json.dumps(scope or []),
            scanner_id,
            profile_id,
            1 if authorized else 0,
            progress,
            str(ev),
            now(),
        ),
    )
    c.commit()
    return get_scan(sid)  # type: ignore[return-value]


def get_scan(scan_id: str) -> dict[str, Any] | None:
    ensure_scans_schema()
    row = get_conn().execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
    return _hydrate(row_to_dict(row) if row else None)


def get_scan_for_user(user_id: str, scan_id: str) -> dict[str, Any] | None:
    """Fail-closed get — only return scans visible to the caller."""
    from app.tenancy import row_visible_to_user

    scan = get_scan(scan_id)
    if not scan or not row_visible_to_user(user_id, scan):
        return None
    return scan


def list_scans(
    user_id: str,
    *,
    org_id: str | None = None,
    limit: int = 50,
) -> list[dict[str, Any]]:
    from app.tenancy import ensure_tenant_schema, tenant_visibility_sql

    ensure_scans_schema()
    ensure_tenant_schema()
    where, args = tenant_visibility_sql(user_id, org_id=org_id)
    rows = get_conn().execute(
        f"SELECT * FROM scans WHERE {where} ORDER BY created_at DESC LIMIT ?",
        [*args, max(1, min(limit, 200))],
    ).fetchall()
    return [_hydrate(dict(r)) for r in rows]


def update_scan(scan_id: str, **fields: Any) -> dict[str, Any] | None:
    ensure_scans_schema()
    allowed = {
        "status",
        "job_id",
        "error",
        "progress_json",
        "summary_json",
        "started_at",
        "completed_at",
        "evidence_dir",
    }
    sets: list[str] = []
    args: list[Any] = []
    for k, v in fields.items():
        if k not in allowed:
            continue
        if k in ("progress_json", "summary_json") and not isinstance(v, str):
            v = json.dumps(v)
        sets.append(f"{k} = ?")
        args.append(v)
    if not sets:
        return get_scan(scan_id)
    args.append(scan_id)
    get_conn().execute(f"UPDATE scans SET {', '.join(sets)} WHERE id = ?", args)
    get_conn().commit()
    return get_scan(scan_id)


def set_progress(scan_id: str, step_id: str, status: str = "done") -> None:
    scan = get_scan(scan_id)
    if not scan:
        return
    steps = list(scan.get("progress") or DEFAULT_PROGRESS)
    found = False
    for step in steps:
        if step.get("id") == step_id:
            step["status"] = status
            found = True
            break
        if not found and step.get("status") == "pending":
            # mark prior pending as done when advancing
            pass
    # Mark all steps before step_id as done; step_id as status; later pending
    passed = False
    for step in steps:
        if step.get("id") == step_id:
            step["status"] = status if status != "active" else "active"
            passed = True
        elif not passed:
            if step.get("status") == "pending":
                step["status"] = "done"
        # leave later as-is
    update_scan(scan_id, progress_json=steps)
    try:
        from app.realtime_bus import publish

        publish(type="scan", id=scan_id, step=step_id, status=status)
    except Exception:
        pass


def _hydrate(d: dict[str, Any] | None) -> dict[str, Any] | None:
    if not d:
        return None
    for key, alias in (("progress_json", "progress"), ("summary_json", "summary"), ("scope_json", "scope")):
        try:
            d[alias] = json.loads(d.get(key) or ("[]" if "progress" in key or "scope" in key else "{}"))
        except Exception:
            d[alias] = [] if "progress" in key or "scope" in key else {}
    d["authorized"] = bool(d.get("authorized"))
    return d


def clear_user_scan_data(user_id: str, *, archive: bool = True) -> dict[str, Any]:
    """Remove scan records/evidence after optionally archiving them (no-loss default)."""
    import shutil

    ensure_scans_schema()
    archived: dict[str, Any] = {"ok": False, "archived_count": 0}
    if archive:
        try:
            from app.archive import archive_user_scans

            archived = archive_user_scans(user_id)
        except Exception as exc:
            archived = {"ok": False, "error": str(exc), "archived_count": 0}

    c = get_conn()
    scans = c.execute("SELECT id, evidence_dir FROM scans WHERE user_id = ?", (user_id,)).fetchall()
    evidence_removed = 0
    for row in scans:
        d = row_to_dict(row) or {}
        sid = d.get("id")
        ed = Path(d.get("evidence_dir") or "") if d.get("evidence_dir") else evidence_root(str(sid))
        try:
            if ed.exists():
                shutil.rmtree(ed, ignore_errors=True)
                evidence_removed += 1
        except Exception:
            pass
    cur_scans = c.execute("DELETE FROM scans WHERE user_id = ?", (user_id,))
    scans_deleted = int(cur_scans.rowcount or 0)

    # Drop findings that came from scan engine or live tool palette
    tool_sources = (
        "ports",
        "http",
        "tls",
        "hardening_baseline",
        "openvas",
        "nmap",
        "nuclei",
        "zap",
        "securaiq",
        "netvuln_scan",
    )
    vulns = c.execute(
        "SELECT id, source, raw_json FROM vulnerabilities WHERE user_id = ?",
        (user_id,),
    ).fetchall()
    to_delete: list[str] = []
    for row in vulns:
        d = row_to_dict(row) or {}
        src = (d.get("source") or "").lower()
        raw = d.get("raw_json") or ""
        if src.startswith("scan:") or src in tool_sources:
            to_delete.append(d["id"])
            continue
        if isinstance(raw, str) and '"scan_id"' in raw:
            to_delete.append(d["id"])
    vulns_deleted = 0
    if to_delete:
        placeholders = ",".join("?" * len(to_delete))
        cur = c.execute(
            f"DELETE FROM vulnerabilities WHERE user_id = ? AND id IN ({placeholders})",
            [user_id, *to_delete],
        )
        vulns_deleted = int(cur.rowcount or 0)
    c.commit()
    try:
        from app.realtime_bus import publish

        publish(
            type="scan_clear",
            user_id=user_id,
            scans_deleted=scans_deleted,
            archived_count=archived.get("archived_count") or 0,
            batch_dir=archived.get("batch_dir"),
        )
    except Exception:
        pass
    return {
        "scans_deleted": scans_deleted,
        "vulnerabilities_deleted": vulns_deleted,
        "evidence_dirs_removed": evidence_removed,
        "archived": archived,
        "archive_batch": archived.get("batch_dir"),
        "archived_count": archived.get("archived_count") or 0,
    }
