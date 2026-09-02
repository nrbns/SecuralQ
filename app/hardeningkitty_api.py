"""API routes for HardeningKitty + CIS Downloads workflow."""

from __future__ import annotations

from typing import Annotated, Literal

from fastapi import APIRouter, Depends, File, HTTPException, UploadFile
from pydantic import BaseModel

from app.auth import AuthUser
from app.commercial_api import require_user
from app import hardeningkitty as hk

router = APIRouter(prefix="/api/hardeningkitty", tags=["hardeningkitty"])


class AuditRequest(BaseModel):
    mode: Literal["Audit", "Config"] = "Audit"
    finding_list: str = ""
    import_findings: bool = True


@router.get("/status")
async def get_status(user: Annotated[AuthUser, Depends(require_user)]):
    st = hk.status()
    st["recent_runs"] = hk.recent_runs(5)
    return st


@router.get("/lists")
async def get_lists(user: Annotated[AuthUser, Depends(require_user)]):
    return {"lists": hk.list_finding_lists(), "cis_downloads": hk.cis_downloads_url()}


@router.post("/import")
async def import_report(
    user: Annotated[AuthUser, Depends(require_user)],
    file: UploadFile = File(...),
    include_passed: bool = False,
):
    raw = await file.read()
    text = raw.decode("utf-8", errors="replace")
    name = file.filename or "hardeningkitty_report.csv"
    if not hk.is_hardeningkitty_report(text, name) and "hardeningkitty" not in name.lower():
        # still try if columns look right
        if not hk.is_hardeningkitty_report(text, name):
            raise HTTPException(400, "Not a HardeningKitty report CSV (need ID,Category,Name,Severity,Result,Recommended,TestResult)")
    items = hk.parse_report_csv(text, filename=name, include_passed=include_passed)
    from app.enterprise import create_vulnerability

    created = []
    for it in items[:500]:
        created.append(create_vulnerability(user.id, it))
    summary = hk.summarize_report(text)
    hk.record_run(
        {
            "mode": "Import",
            "list_name": name,
            "report_path": name,
            "score": summary.get("score_estimate"),
            "passed": (summary.get("counts") or {}).get("passed") or 0,
            "failed": (summary.get("counts") or {}).get("failed") or 0,
            "imported": len(created),
            "status": "done",
        }
    )
    return {
        "imported": len(created),
        "summary": summary,
        "vulnerabilities": created[:40],
        "cis_downloads": hk.cis_downloads_url(),
    }


@router.post("/audit")
async def run_audit(req: AuditRequest, user: Annotated[AuthUser, Depends(require_user)]):
    """Queue HardeningKitty Audit/Config as a background job (realtime UI polls status)."""
    from app.jobs import enqueue_job

    if req.mode not in {"Audit", "Config"}:
        raise HTTPException(400, "Only Audit and Config modes are allowed")
    try:
        job = enqueue_job(
            "hardeningkitty_audit",
            {
                "user_id": user.id,
                "mode": req.mode,
                "finding_list": req.finding_list or "",
                "import_findings": req.import_findings,
            },
            engine="local",
        )
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    return {"job": job, "queued": True}
