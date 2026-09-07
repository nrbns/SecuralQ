"""Local realtime archive — keep scan evidence when clearing live workspace.

Prototype rule: never throw away completed scan reports/evidence. Clear moves
them under ``data/archive/`` and realtime clients get an ``archive`` event.
"""

from __future__ import annotations

import json
import shutil
import time
from pathlib import Path
from typing import Any

from app.config import settings
from app.db import get_conn, now, row_to_dict


def data_root() -> Path:
    return Path(settings.data_dir)


def evidence_root() -> Path:
    return data_root() / "evidence" / "scans"


def archive_root() -> Path:
    return data_root() / "archive" / "scans"


def ensure_data_layout() -> dict[str, str]:
    """Create persistent dirs used by scans, evidence, and archive."""
    paths = {
        "data": data_root(),
        "evidence": evidence_root(),
        "archive": archive_root(),
        "uploads": data_root() / "uploads",
        "kpi_snaps": data_root() / "kpi_snaps",
        "chroma": Path(settings.chroma_persist_dir),
    }
    for p in paths.values():
        p.mkdir(parents=True, exist_ok=True)
    return {k: str(v) for k, v in paths.items()}


def _safe_name(value: str) -> str:
    raw = (value or "item").strip()
    out = "".join(ch if ch.isalnum() or ch in "-._" else "_" for ch in raw)
    return (out or "item")[:80]


def archive_user_scans(user_id: str) -> dict[str, Any]:
    """Copy each scan's evidence + JSON manifest into data/archive before wipe."""
    from app.scan_engine.models import ensure_scans_schema, evidence_root as scan_evidence_root

    ensure_scans_schema()
    ensure_data_layout()
    c = get_conn()
    rows = c.execute(
        "SELECT * FROM scans WHERE user_id = ? ORDER BY created_at DESC",
        (user_id,),
    ).fetchall()
    stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    batch_dir = archive_root() / f"{_safe_name(user_id)}_{stamp}"
    batch_dir.mkdir(parents=True, exist_ok=True)

    archived: list[dict[str, Any]] = []
    for row in rows:
        scan = row_to_dict(row) or {}
        sid = str(scan.get("id") or "")
        if not sid:
            continue
        src = Path(scan.get("evidence_dir") or "") if scan.get("evidence_dir") else scan_evidence_root(sid)
        dest = batch_dir / sid
        try:
            if src.exists():
                if dest.exists():
                    shutil.rmtree(dest, ignore_errors=True)
                shutil.copytree(src, dest)
            else:
                dest.mkdir(parents=True, exist_ok=True)
            # Real gap found live: report.pdf is only ever written the first
            # time someone clicks "PDF" on a live scan (lazy, on-demand in
            # scans_api.py) — a scan archived before that click carried no
            # PDF into the archive, so "Archived" rows showed Markdown only
            # with no explanation. The Markdown report is already generated
            # at scan completion, so build the PDF from it now too, honestly,
            # from the same real report content — not a fake placeholder.
            report_md = dest / "report.md"
            report_pdf = dest / "report.pdf"
            if report_md.is_file() and not report_pdf.is_file():
                try:
                    from app.commercial_ext import markdown_to_simple_pdf

                    md_text = report_md.read_text(encoding="utf-8")
                    pdf_bytes = markdown_to_simple_pdf(
                        md_text, title=f"SecuraIQ VA Report — {scan.get('target') or sid[:8]}"
                    )
                    report_pdf.write_bytes(pdf_bytes)
                except Exception:
                    pass  # keep archiving even if PDF rendering fails — Markdown still available
            meta = {
                "scan_id": sid,
                "user_id": user_id,
                "target": scan.get("target"),
                "scanner": scan.get("scanner"),
                "profile": scan.get("profile"),
                "status": scan.get("status"),
                "summary": scan.get("summary_json"),
                "created_at": scan.get("created_at"),
                "completed_at": scan.get("completed_at"),
                "archived_at": now(),
                "evidence_dir": str(dest),
            }
            try:
                if isinstance(meta["summary"], str):
                    meta["summary"] = json.loads(meta["summary"] or "{}")
            except Exception:
                meta["summary"] = {}
            (dest / "archive_meta.json").write_text(
                json.dumps(meta, indent=2, ensure_ascii=False, default=str),
                encoding="utf-8",
            )
            archived.append(
                {
                    "scan_id": sid,
                    "target": scan.get("target"),
                    "scanner": scan.get("scanner"),
                    "status": scan.get("status"),
                    "path": str(dest),
                    "has_report": (dest / "report.md").is_file(),
                    "has_pdf": (dest / "report.pdf").is_file(),
                }
            )
        except Exception as exc:
            archived.append({"scan_id": sid, "error": str(exc)})

    manifest = {
        "user_id": user_id,
        "archived_at": now(),
        "batch_dir": str(batch_dir),
        "count": len(archived),
        "scans": archived,
    }
    (batch_dir / "manifest.json").write_text(
        json.dumps(manifest, indent=2, ensure_ascii=False, default=str),
        encoding="utf-8",
    )

    try:
        from app.realtime_bus import publish

        publish(
            type="archive",
            user_id=user_id,
            count=len(archived),
            batch_dir=str(batch_dir),
            status="saved",
        )
    except Exception:
        pass

    return {
        "ok": True,
        "batch_dir": str(batch_dir),
        "archived_count": len(archived),
        "scans": archived,
    }


def list_archives(user_id: str, *, limit: int = 40) -> list[dict[str, Any]]:
    """List archived scan report cards for Reports / prototype demos."""
    ensure_data_layout()
    root = archive_root()
    if not root.is_dir():
        return []
    items: list[dict[str, Any]] = []
    batches = sorted(
        [p for p in root.iterdir() if p.is_dir()],
        key=lambda p: p.stat().st_mtime,
        reverse=True,
    )
    uid = (user_id or "").strip()
    for batch in batches:
        if uid and uid != "local" and not batch.name.startswith(f"{_safe_name(uid)}_"):
            # Still allow local open-mode archives
            if not batch.name.startswith("local_"):
                continue
        for scan_dir in sorted(batch.iterdir(), key=lambda p: p.stat().st_mtime, reverse=True):
            if not scan_dir.is_dir() or scan_dir.name.startswith("."):
                continue
            meta_path = scan_dir / "archive_meta.json"
            meta: dict[str, Any] = {}
            if meta_path.is_file():
                try:
                    meta = json.loads(meta_path.read_text(encoding="utf-8"))
                except Exception:
                    meta = {}
            if uid and meta.get("user_id") and meta.get("user_id") not in {uid, "local"}:
                continue
            sid = meta.get("scan_id") or scan_dir.name
            target = meta.get("target") or "target"
            scanner = meta.get("scanner") or "scan"
            title = f"Archive - {target} ({scanner})"
            # Real UI bug found live: unlike the live-scan title format in
            # app/ops.py reports_catalog ("Scan - target (scanner) - N
            # findings"), this archive title never included a findings
            # count, so the Reports page's Findings column parses nothing
            # and always shows "—" for every archived scan, even ones with
            # real findings.
            summary = meta.get("summary")
            if isinstance(summary, dict):
                fcount = summary.get("findings_created")
                if fcount is None:
                    fcount = summary.get("findings")
                if fcount is not None:
                    title += f" - {fcount} findings"
            if (scan_dir / "report.md").is_file():
                items.append(
                    {
                        "id": f"archive-md-{sid}",
                        "title": title,
                        "href": f"/api/archive/scans/{sid}/report",
                        "kind": "archive",
                        "scan_id": sid,
                        "created_at": meta.get("archived_at") or meta.get("created_at"),
                        "path": str(scan_dir),
                    }
                )
            # Mirror the live-scan report listing (app/ops.py reports_catalog):
            # the PDF entry is offered whenever report.md exists, even if
            # report.pdf hasn't been written yet, because
            # /api/archive/scans/{id}/report.pdf now lazily renders it from
            # the Markdown on first download (same pattern as live scans).
            # Real UI gap this closes: archived scans predating that lazy
            # render showed a Markdown button but no PDF button at all, with
            # no way to get a PDF for an already-archived scan.
            if (scan_dir / "report.pdf").is_file() or (scan_dir / "report.md").is_file():
                items.append(
                    {
                        "id": f"archive-pdf-{sid}",
                        "title": f"{title} (PDF)",
                        "href": f"/api/archive/scans/{sid}/report.pdf",
                        "kind": "archive-pdf",
                        "scan_id": sid,
                        "created_at": meta.get("archived_at") or meta.get("created_at"),
                        "path": str(scan_dir),
                    }
                )
            if len(items) >= limit:
                return items[:limit]
    return items[:limit]


def find_archived_scan(scan_id: str) -> Path | None:
    ensure_data_layout()
    sid = (scan_id or "").strip()
    if not sid:
        return None
    root = archive_root()
    if not root.is_dir():
        return None
    for batch in root.iterdir():
        if not batch.is_dir():
            continue
        candidate = batch / sid
        if candidate.is_dir():
            return candidate
    return None


def delete_archived_scan(scan_id: str, user_id: str) -> dict[str, Any]:
    """Permanently remove one archived scan folder (Markdown/PDF/evidence).

    Ownership: allow when archive_meta.user_id matches the caller, is missing
    (legacy), or either side is local open-mode. Reject cross-user deletes.
    """
    path = find_archived_scan(scan_id)
    if not path:
        raise FileNotFoundError("Archived scan not found")

    meta: dict[str, Any] = {}
    meta_path = path / "archive_meta.json"
    if meta_path.is_file():
        try:
            meta = json.loads(meta_path.read_text(encoding="utf-8"))
        except Exception:
            meta = {}

    uid = (user_id or "").strip()
    owner = str(meta.get("user_id") or "").strip()
    if owner and uid and owner not in {uid, "local"} and uid != "local":
        raise PermissionError("Not allowed to delete this archive")

    batch = path.parent
    shutil.rmtree(path, ignore_errors=False)

    # Drop empty batch dirs so archive/scans stays tidy
    try:
        if batch.is_dir() and not any(batch.iterdir()):
            batch.rmdir()
    except OSError:
        pass

    try:
        from app.realtime_bus import publish

        publish(
            type="archive_delete",
            user_id=uid or owner or "local",
            scan_id=scan_id,
            status="deleted",
        )
    except Exception:
        pass

    return {"ok": True, "scan_id": scan_id, "deleted": True}


def prototype_status() -> dict[str, Any]:
    """Compact readiness signal for Mission Control / health."""
    layout = ensure_data_layout()
    zero = bool(getattr(settings, "workspace_zero_start", False))
    auth = bool(getattr(settings, "auth_enabled", False))
    evidence_n = 0
    archive_n = 0
    try:
        evidence_n = sum(1 for _ in evidence_root().glob("*") if _.is_dir())
    except Exception:
        pass
    try:
        archive_n = sum(1 for _ in archive_root().glob("*") if _.is_dir())
    except Exception:
        pass
    return {
        "ok": True,
        "data_persists": True,
        "live_resets_on_boot": bool(zero and not auth),
        "workspace_zero_start": zero,
        "auth_enabled": auth,
        "realtime": True,
        "paths": layout,
        "live_evidence_scans": evidence_n,
        "archive_batches": archive_n,
        "hint": (
            "Lab zero-start: live workspace empty on boot · prior scans in data/archive"
            if zero and not auth
            else "Live data kept across restarts · clear still archives first"
        ),
    }
