"""Archive API — download reports that survived clear / workspace reset."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, Header, HTTPException
from fastapi.responses import FileResponse, PlainTextResponse, Response

from app.archive import (
    delete_archived_scan,
    find_archived_scan_for_user,
    list_archives,
    prototype_status,
)
from app.auth import AuthUser
from app.commercial_api import require_user
from app.tenancy import resolve_request_org

router = APIRouter(prefix="/api/archive", tags=["archive"])


@router.get("/status")
async def archive_status(
    user: Annotated[AuthUser, Depends(require_user)],
    x_securaiq_org: str | None = Header(default=None, alias="X-SecuraIQ-Org"),
):
    oid = resolve_request_org(user, org_id=None, header_org=x_securaiq_org)
    st = prototype_status()
    st["archives"] = list_archives(user.id, limit=20, org_id=oid)
    st["org_id"] = oid
    return st


@router.get("/scans")
async def archive_list(
    user: Annotated[AuthUser, Depends(require_user)],
    limit: int = 40,
    x_securaiq_org: str | None = Header(default=None, alias="X-SecuraIQ-Org"),
):
    oid = resolve_request_org(user, org_id=None, header_org=x_securaiq_org)
    return {
        "archives": list_archives(user.id, limit=max(1, min(limit, 100)), org_id=oid),
        "org_id": oid,
    }


@router.delete("/scans/{scan_id}")
async def archive_delete(scan_id: str, user: Annotated[AuthUser, Depends(require_user)]):
    """Permanently delete one archived scan report (Markdown + PDF + evidence)."""
    try:
        return delete_archived_scan(scan_id, user.id)
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except OSError as exc:
        raise HTTPException(status_code=500, detail=f"Delete failed: {exc}") from exc


@router.get("/scans/{scan_id}/report")
async def archive_report_md(scan_id: str, user: Annotated[AuthUser, Depends(require_user)]):
    path = find_archived_scan_for_user(scan_id, user.id)
    if not path:
        raise HTTPException(status_code=404, detail="Archived scan not found")
    report = path / "report.md"
    if not report.is_file():
        raise HTTPException(status_code=404, detail="Archived report.md missing")
    return PlainTextResponse(
        report.read_text(encoding="utf-8"),
        media_type="text/markdown; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="securaiq-archive-{scan_id[:8]}.md"'},
    )


@router.get("/scans/{scan_id}/report.pdf")
async def archive_report_pdf(scan_id: str, user: Annotated[AuthUser, Depends(require_user)]):
    path = find_archived_scan_for_user(scan_id, user.id)
    if not path:
        raise HTTPException(status_code=404, detail="Archived scan not found")
    pdf = path / "report.pdf"
    if not pdf.is_file():
        # Same lazy-render-on-first-download pattern as live scans
        # (app/scans_api.py scans_report_pdf) — generate the PDF from the
        # real archived Markdown report instead of 404ing on archives that
        # predate this behavior or were never downloaded as PDF before
        # archiving.
        report = path / "report.md"
        if not report.is_file():
            raise HTTPException(status_code=404, detail="Archived report.md missing — cannot build PDF")
        from app.commercial_ext import markdown_to_simple_pdf

        md_text = report.read_text(encoding="utf-8")
        pdf_bytes = markdown_to_simple_pdf(md_text, title="SecuraIQ VA Report (archived)")
        try:
            pdf.write_bytes(pdf_bytes)
        except Exception:
            pass  # serve it even if persisting back to disk fails
        return Response(
            content=pdf_bytes,
            media_type="application/pdf",
            headers={"Content-Disposition": f'attachment; filename="securaiq-archive-{scan_id[:8]}.pdf"'},
        )
    return FileResponse(
        path=str(pdf),
        media_type="application/pdf",
        filename=f"securaiq-archive-{scan_id[:8]}.pdf",
    )
