"""Scan Engine API — create scan → queue → worker → evidence → findings."""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Depends, Header, HTTPException
from fastapi.responses import PlainTextResponse, Response
from pydantic import BaseModel, Field

from app.auth import AuthUser
from app.commercial_api import require_user
from app.rbac import require_perm
from app.scan_engine.executor import enqueue_scan_job
from app.scan_engine.models import create_scan, ensure_scans_schema, get_scan, list_scans
from app.scan_engine.report import build_scan_report_md, findings_for_scan, write_scan_report
from app.scanners.registry import ENGINE_ENABLED, get_scanner, list_scanners
from app.services.tenancy import resolve_request_org
from app.services.tool_policy import assert_structured_scope, normalize_scope_json
from app.workspace import get_engagement

router = APIRouter(prefix="/api/scans", tags=["scans"])

# Preferred order when scanner=all
_ALL_ORDER = ("securaiq", "nmap", "nuclei", "zap")


class ScanCreate(BaseModel):
    target: str = Field(min_length=1, max_length=500)
    scanner: str = "securaiq"  # securaiq|nmap|nuclei|zap|all
    profile: str = Field(default="discovery", pattern="^(discovery|web|vulnerability|full)$")
    scope: list[str] | str | None = None
    engagement_id: str | None = None
    org_id: str | None = None
    authorized: bool = False


def _resolve_scope(user: AuthUser, req: ScanCreate) -> list[str]:
    scope = normalize_scope_json(req.scope)
    if req.engagement_id and not scope:
        eng = get_engagement(user.id, req.engagement_id)
        if eng:
            scope = normalize_scope_json(eng.get("scope_json") or "")
    return scope


def _queue_one(
    *,
    user: AuthUser,
    oid: str | None,
    target: str,
    scanner_id: str,
    profile: str,
    scope: list[str],
    engagement_id: str | None,
) -> dict[str, Any]:
    if scanner_id not in ENGINE_ENABLED:
        raise HTTPException(status_code=400, detail=f"Scanner '{scanner_id}' is not enabled")
    try:
        scanner = get_scanner(scanner_id)
    except KeyError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    ok_scope_req, scope_req_reason = assert_structured_scope(
        scanner_id=scanner_id, profile=profile, scope=scope
    )
    if not ok_scope_req:
        raise HTTPException(status_code=400, detail=f"{scanner_id}: {scope_req_reason}")

    ok_t, target_or_err = scanner.validate_target(target)
    if not ok_t:
        raise HTTPException(status_code=400, detail=f"{scanner_id}: {target_or_err}")

    ok_s, s_reason = scanner.validate_scope(target_or_err, scope)
    if not ok_s:
        raise HTTPException(status_code=403, detail=f"BLOCKED ({scanner_id}): {s_reason}")

    avail, avail_detail = scanner.available()
    if not avail:
        raise HTTPException(status_code=503, detail=f"{scanner_id}: {avail_detail}")

    scan = create_scan(
        user_id=user.id,
        target=target_or_err,
        scanner=scanner_id,
        profile=profile,
        scope=scope,
        engagement_id=engagement_id,
        org_id=oid,
        authorized=True,
    )
    job = enqueue_scan_job(scan["id"])
    return {
        "scan_id": scan["id"],
        "status": "queued",
        "job_id": job.get("id"),
        "scanner": scanner_id,
        "profile": profile,
        "target": target_or_err,
        "scope": scope,
        "auth_decision": scope_req_reason,
    }


@router.get("/scanners")
async def scanners_catalog(user: Annotated[AuthUser, Depends(require_user)]):
    _ = user
    return {
        "scanners": list_scanners(),
        "profiles": ["discovery", "web", "vulnerability", "full"],
        "batch": ["all"],
    }


@router.get("")
async def scans_list(
    user: Annotated[AuthUser, Depends(require_user)],
    org_id: str | None = None,
    x_securaiq_org: str | None = Header(default=None, alias="X-SecuraIQ-Org"),
    limit: int = 50,
):
    ensure_scans_schema()
    oid = resolve_request_org(user, org_id=org_id, header_org=x_securaiq_org)
    return {"scans": list_scans(user.id, org_id=oid, limit=limit), "org_id": oid}


@router.post("/reclassify-exposure")
async def scans_reclassify_exposure(user: Annotated[AuthUser, Depends(require_user)]):
    """Down-rank private Windows SMB/RPC findings that were stored as High before exposure policy."""
    from app.exposure import reclassify_stored_risky_ports

    require_perm(user, "asset.write", org_id=None)
    result = reclassify_stored_risky_ports(user.id)
    return {"ok": True, **result}


@router.post("/clear")
async def scans_clear_old(
    user: Annotated[AuthUser, Depends(require_user)],
    x_securaiq_org: str | None = Header(default=None, alias="X-SecuraIQ-Org"),
):
    """Archive scan evidence, then clear live scan rows/findings (no-loss)."""
    from app.exposure import reclassify_stored_risky_ports
    from app.scan_engine.models import clear_user_scan_data

    ensure_scans_schema()
    oid = resolve_request_org(user, org_id=None, header_org=x_securaiq_org)
    require_perm(user, "asset.write", org_id=oid)
    result = clear_user_scan_data(user.id, archive=True)
    reclass = reclassify_stored_risky_ports(user.id)
    return {"ok": True, **result, "reclassified": reclass.get("updated", 0)}


class ComboAssessmentCreate(BaseModel):
    target: str = Field(min_length=1, max_length=500)
    profile: str = Field(default="discovery", pattern="^(discovery|web|vulnerability|full)$")
    scope: list[str] | str | None = None
    engagement_id: str | None = None
    org_id: str | None = None
    authorized: bool = False
    include_web: bool = False
    auto_triage_high: bool = True
    async_mode: bool = True  # queue job; false = run inline (tests / short lab)


@router.get("/combo/scanners")
async def combo_scanners_preview(user: Annotated[AuthUser, Depends(require_user)]):
    """Which engines the combo workflow would run right now."""
    _ = user
    from app.combo_assessment import resolve_combo_scanners

    return {
        "core": resolve_combo_scanners(include_web=False),
        "with_web": resolve_combo_scanners(include_web=True),
        "workflow": [
            "authorize",
            "scope",
            "scan (securaiq + nmap…)",
            "evidence",
            "investigate-scan",
            "auto-triage high/critical",
        ],
    }


@router.post("/combo")
async def scans_combo_assessment(
    req: ComboAssessmentCreate,
    user: Annotated[AuthUser, Depends(require_user)],
    x_securaiq_org: str | None = Header(default=None, alias="X-SecuraIQ-Org"),
):
    """Integrated combo: scan → evidence → investigate pack → optional auto-triage.

    Default ``async_mode=true`` queues ``combo_assessment`` (poll GET /api/jobs/{id}).
    Set ``async_mode=false`` to run inline and return the full pack in one response.
    """
    ensure_scans_schema()
    oid = resolve_request_org(user, org_id=req.org_id, header_org=x_securaiq_org)
    require_perm(user, "asset.write", org_id=oid)
    require_perm(user, "vuln.read", org_id=oid)

    if not req.authorized:
        raise HTTPException(
            status_code=400,
            detail="Authorization required: confirm you own or are authorized to test this target.",
        )

    scope = normalize_scope_json(req.scope)
    if req.engagement_id and not scope:
        eng = get_engagement(user.id, req.engagement_id)
        if eng:
            scope = normalize_scope_json(eng.get("scope_json") or "")

    payload = {
        "user_id": user.id,
        "target": req.target.strip(),
        "scope": scope,
        "authorized": True,
        "profile": req.profile,
        "engagement_id": req.engagement_id,
        "org_id": oid,
        "include_web": req.include_web or req.profile in {"web", "full", "vulnerability"},
        "auto_triage_high": req.auto_triage_high,
    }

    if not req.async_mode:
        from app.combo_assessment import run_combo_assessment

        result = await run_combo_assessment(**payload)
        if not result.get("ok"):
            status = 403 if result.get("blocked") else 400
            raise HTTPException(status_code=status, detail=result.get("error") or "combo failed")
        return result

    from app.combo_assessment import enqueue_combo_assessment, resolve_combo_scanners

    job = enqueue_combo_assessment(payload)
    prof = payload.get("profile") or "discovery"
    include_web = bool(payload.get("include_web"))
    return {
        "status": "queued",
        "workflow": "combo_assessment",
        "job_id": job.get("id"),
        "poll_url": f"/api/jobs/{job.get('id')}",
        "target": payload["target"],
        "scope": scope,
        "include_web": include_web,
        "auto_triage_high": payload["auto_triage_high"],
        "scanners": resolve_combo_scanners(include_web=include_web or prof in {"web", "full", "vulnerability"}),
    }


@router.get("/{scan_id}/report")
async def scans_report(scan_id: str, user: Annotated[AuthUser, Depends(require_user)]):
    """Download the Markdown scan report (creates it if a completed scan is missing report.md)."""
    from pathlib import Path

    ensure_scans_schema()
    scan = get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    if user.role != "admin" and scan.get("user_id") != user.id:
        raise HTTPException(status_code=404, detail="Scan not found")

    ev = Path(scan.get("evidence_dir") or "")
    report_file = ev / "report.md" if ev else None
    if report_file and report_file.is_file():
        return PlainTextResponse(
            report_file.read_text(encoding="utf-8"),
            media_type="text/markdown; charset=utf-8",
            headers={"Content-Disposition": f'attachment; filename="securaiq-scan-{scan_id[:8]}.md"'},
        )

    findings = findings_for_scan(scan.get("user_id") or user.id, scan_id)
    md = build_scan_report_md(scan, findings=findings)
    if scan.get("status") == "completed" and ev:
        try:
            write_scan_report(ev, scan, findings=findings)
        except Exception:
            pass
    return PlainTextResponse(
        md,
        media_type="text/markdown; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="securaiq-scan-{scan_id[:8]}.md"'},
    )


@router.get("/{scan_id}/report.pdf")
async def scans_report_pdf(scan_id: str, user: Annotated[AuthUser, Depends(require_user)]):
    """VA / scan report as PDF (same content as Markdown report)."""
    from pathlib import Path

    from app.commercial_ext import markdown_to_simple_pdf

    ensure_scans_schema()
    scan = get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    if user.role != "admin" and scan.get("user_id") != user.id:
        raise HTTPException(status_code=404, detail="Scan not found")

    ev = Path(scan.get("evidence_dir") or "")
    report_file = ev / "report.md" if ev else None
    if report_file and report_file.is_file():
        md = report_file.read_text(encoding="utf-8")
    else:
        findings = findings_for_scan(scan.get("user_id") or user.id, scan_id)
        md = build_scan_report_md(scan, findings=findings)
        if scan.get("status") == "completed" and ev:
            try:
                write_scan_report(ev, scan, findings=findings)
            except Exception:
                pass
    pdf = markdown_to_simple_pdf(md, title=f"SecuraIQ VA Report — {scan.get('target') or scan_id[:8]}")
    # Also persist PDF next to markdown when possible
    if ev:
        try:
            ev.mkdir(parents=True, exist_ok=True)
            (ev / "report.pdf").write_bytes(pdf)
        except Exception:
            pass
    return Response(
        content=pdf,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="securaiq-va-{scan_id[:8]}.pdf"'},
    )


@router.get("/{scan_id}")
async def scans_get(scan_id: str, user: Annotated[AuthUser, Depends(require_user)]):
    ensure_scans_schema()
    scan = get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    if user.role != "admin" and scan.get("user_id") != user.id:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan


@router.post("")
async def scans_create(
    req: ScanCreate,
    user: Annotated[AuthUser, Depends(require_user)],
    x_securaiq_org: str | None = Header(default=None, alias="X-SecuraIQ-Org"),
):
    """Create scan(s) and enqueue workers. scanner=all queues every available engine scanner."""
    ensure_scans_schema()
    oid = resolve_request_org(user, org_id=req.org_id, header_org=x_securaiq_org)
    require_perm(user, "asset.write", org_id=oid)

    if not req.authorized:
        raise HTTPException(
            status_code=400,
            detail="Authorization required: confirm you own or are authorized to test this target.",
        )

    scope = _resolve_scope(user, req)
    scanner_id = (req.scanner or "securaiq").lower().strip()

    if scanner_id == "all":
        queued: list[dict[str, Any]] = []
        skipped: list[dict[str, str]] = []
        for sid in _ALL_ORDER:
            if sid not in ENGINE_ENABLED:
                continue
            try:
                sc = get_scanner(sid)
            except KeyError:
                continue
            ok, detail = sc.available()
            if not ok:
                skipped.append({"scanner": sid, "reason": detail})
                continue
            try:
                queued.append(
                    _queue_one(
                        user=user,
                        oid=oid,
                        target=req.target,
                        scanner_id=sid,
                        profile=req.profile,
                        scope=scope,
                        engagement_id=req.engagement_id,
                    )
                )
            except HTTPException as exc:
                skipped.append({"scanner": sid, "reason": str(exc.detail)})
        if not queued:
            raise HTTPException(
                status_code=503,
                detail="No scanners available to run. Use securaiq, combo, or install nmap/nuclei on PATH.",
            )
        return {
            "status": "queued",
            "scanner": "all",
            "profile": req.profile,
            "scan_id": queued[0]["scan_id"],
            "scans": queued,
            "skipped": skipped,
            "count": len(queued),
        }

    return _queue_one(
        user=user,
        oid=oid,
        target=req.target,
        scanner_id=scanner_id,
        profile=req.profile,
        scope=scope,
        engagement_id=req.engagement_id,
    )
