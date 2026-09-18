"""SecuraIQ Code API — branded SAST console backed by a Sonar-compatible engine.

Primary routes: /api/code/*
Compat alias:   /api/sonarqube/* (older clients / settings)
"""

from __future__ import annotations

import json
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field

from app.auth import AuthUser
from app.commercial_api import require_user
from app.connectors import sonarqube as sonar_conn
from app.sonarqube import status as sonar_status

# Shared route table (no prefix) — mounted under /api/code and /api/sonarqube
router = APIRouter(tags=["securaiq-code"])


_ALLOWED_CODE_TOOLS = {"code_scan", "semgrep", "codeql", "securaiq_code"}


class CodeScanBody(BaseModel):
    path: str = Field(default="", description="Local project folder you own / are authorized to scan")
    git_url: str = Field(
        default="", description="Public/authorized http(s) git repo URL to clone (shallow) then scan"
    )
    git_ref: str = Field(default="", description="Optional branch or tag to check out")
    authorized: bool = True
    sync_engine: bool = False
    tools: list[str] = Field(
        default_factory=list,
        description="Which SAST tools to run: code_scan (built-in, always available), "
        "semgrep (real semgrep if installed), codeql (CLI presence check only). "
        "Defaults to code_scan alone.",
    )


@router.get("/status")
async def get_status(user: Annotated[AuthUser, Depends(require_user)]):
    st = sonar_status()
    st["brand"] = "SecuraIQ Code"
    st["engine"] = "sonar_compatible"
    st["local_scan"] = True
    st["ping"] = await sonar_conn.ping() if st.get("configured") else {"ok": False, "error": "not_configured"}
    return st


@router.post("/sync")
async def trigger_sync(user: Annotated[AuthUser, Depends(require_user)]):
    st = sonar_status()
    if not st.get("configured"):
        raise HTTPException(
            400,
            "No code engine configured — use Scan folder for local SAST "
            "(or set SecuraIQ Code / Sonar settings).",
        )
    from app.jobs import enqueue_job

    job = enqueue_job("sonarqube_sync", {"user_id": user.id}, engine="auto")
    return {"job": job, "ok": True, "brand": "SecuraIQ Code"}


@router.post("/test")
async def test_connection(user: Annotated[AuthUser, Depends(require_user)]):
    result = await sonar_conn.ping()
    result["brand"] = "SecuraIQ Code"
    return result


def _build_code_scan_report_md(scan: dict, *, payload: dict) -> str:
    """Human-readable report for a code-scan run — mirrors scan_engine's
    generic report.md so this shows up in Reports identically to a network
    scan, but built from the tool-run payload directly rather than
    findings_for_scan(): individual vulnerabilities created by code_scan /
    semgrep / codeql are not (yet) tagged with a scan_id, so this reports the
    real tool output and the real persisted-findings count instead of
    fabricating a per-finding breakdown it doesn't have."""
    from app.db import now

    runs = payload.get("runs") or []
    vp = payload.get("vulnerabilities_persisted") or {}
    lines = [
        "# SecuraIQ Code — Scan Report",
        "",
        "## Scan metadata",
        "",
        f"- **Scan ID:** `{scan.get('id') or '—'}`",
        f"- **Target:** `{scan.get('target') or payload.get('target') or '—'}`",
        f"- **Tools requested:** {', '.join(payload.get('requested') or []) or '—'}",
        f"- **Authorized:** {'yes' if payload.get('authorized') else 'no'}",
        f"- **Status:** {scan.get('status') or '—'}",
    ]
    if scan.get("created_at"):
        lines.append(f"- **Created:** {scan.get('created_at')}")
    if scan.get("completed_at"):
        lines.append(f"- **Completed:** {scan.get('completed_at')}")
    lines.extend(
        [
            "",
            "## Findings persisted",
            "",
            f"- Findings saved to the vulnerability register: **{vp.get('created', 0)}**",
        ]
    )
    if vp.get("asset_name"):
        lines.append(f"- Asset: `{vp.get('asset_name')}`")
    lines.extend(
        [
            "- A run can detect more raw hits than it saves — duplicates within the run, or "
            "findings already on record for this asset from a prior scan, are skipped rather "
            "than re-saved. See Vulnerabilities, filtered by this asset, for the individual "
            "findings this run contributed.",
            "",
            "## Tool output",
            "",
        ]
    )
    if not runs:
        lines.append("_No tool output recorded._")
    for r in runs:
        tid = r.get("tool") or "tool"
        ok = r.get("ok")
        lines.append(f"### {tid} — {'OK' if ok else 'FAILED'}")
        lines.append("")
        if ok:
            out = str(r.get("output") or "").strip()
            lines.append("```")
            lines.append(out[:8000] if out else "(no output)")
            lines.append("```")
        else:
            lines.append(f"- **Error:** {r.get('error') or 'unknown error'}")
        lines.append("")
    lines.extend(
        [
            "## Notes",
            "",
            "- Only scan code you own or are authorized to test.",
            f"- Generated at `{now()}`.",
            "",
        ]
    )
    return "\n".join(lines)


def _finish_code_scan(scan_id: str, payload: dict | None) -> None:
    """Close out the scans-table row for a code-scan run so it always ends
    terminal (completed/failed) — even if the stream broke before a 'done'
    event ever arrived — and gets a real report.md written, the same way a
    network scan does. This is what makes a code scan show up in the Reports
    page and be coverable by the existing scan archive/delete paths, instead
    of vanishing the moment the stream response closes."""
    from pathlib import Path

    from app.db import now
    from app.scan_engine.models import get_scan, update_scan

    scan = get_scan(scan_id)
    if not scan or scan.get("status") in ("completed", "failed", "blocked"):
        return
    payload = payload or {"ok": False, "error": "Scan stream ended before completion"}
    ok = bool(payload.get("ok"))
    vp = payload.get("vulnerabilities_persisted") or {}
    summary = {
        "findings_created": vp.get("created", 0),
        "asset_name": vp.get("asset_name") or "",
        "tools": payload.get("requested") or [],
        "checked_ports": "—",
    }
    update_scan(
        scan_id,
        status="completed" if ok else "failed",
        completed_at=now(),
        summary_json=summary,
        error="" if ok else str(payload.get("error") or "see tool output")[:2000],
    )
    try:
        scan = get_scan(scan_id) or scan
        ev_dir = Path(scan.get("evidence_dir") or "")
        if str(ev_dir):
            ev_dir.mkdir(parents=True, exist_ok=True)
            md = _build_code_scan_report_md(scan, payload=payload)
            (ev_dir / "report.md").write_text(md, encoding="utf-8")
    except Exception:
        pass
    try:
        from app.realtime_bus import publish

        publish(type="scan", id=scan_id, status="completed" if ok else "failed")
    except Exception:
        pass


@router.post("/scan/stream")
async def scan_folder_stream(
    body: CodeScanBody,
    user: Annotated[AuthUser, Depends(require_user)],
):
    """Realtime NDJSON stream for folder SAST — local path or a cloned git
    repo (Auth required to persist). Runs one or more real SAST tools
    (code_scan/semgrep/codeql) against whichever path results."""
    from app.db import now
    from app.scan_engine.models import create_scan, update_scan
    from app.tools.runner import iter_security_tools

    path = body.path.strip()
    git_url = body.git_url.strip()
    git_ref = body.git_ref.strip()

    if not path and not git_url:
        raise HTTPException(400, "Provide a local project path or a git repo URL")
    if not body.authorized:
        raise HTTPException(400, "Confirm you own or are authorized to scan this target before starting")

    requested = [t for t in (body.tools or []) if t in _ALLOWED_CODE_TOOLS]
    if not requested:
        requested = ["securaiq_code"] if body.sync_engine else ["code_scan"]

    # Give this run a real scan record — the same table/report/archive/delete
    # machinery network scans already use — so it shows up in Reports and gets
    # a downloadable Markdown/PDF report. Previously a code scan wrote
    # vulnerabilities directly with no persisted scan record at all: a
    # finished run left no trace anywhere outside the live findings it made.
    scan: dict | None = None
    try:
        scan = create_scan(
            user_id=user.id,
            target=(git_url or path)[:500],
            scanner="code_scan",
            profile="full",
            authorized=True,
        )
        update_scan(scan["id"], status="running", started_at=now())
    except Exception:
        scan = None

    async def gen():
        clone_result: dict | None = None
        done_payload: dict | None = None
        try:
            scan_path = path
            if scan and scan.get("id"):
                yield json.dumps({"event": "scan_created", "scan_id": scan["id"]}, default=str) + "\n"
            if git_url:
                from app.services.git_ingest import clone_repo

                yield json.dumps({"event": "git_clone_start", "url": git_url, "ref": git_ref or None}, default=str) + "\n"
                clone_result = await clone_repo(git_url, ref=git_ref)
                if not clone_result.get("ok"):
                    err = clone_result.get("error") or "git clone failed"
                    done_payload = {"ok": False, "error": err, "requested": requested}
                    yield json.dumps({"event": "git_clone_failed", "error": err}, default=str) + "\n"
                    yield json.dumps(
                        {"event": "done", "ok": False, "error": err, "scan_id": (scan or {}).get("id")},
                        default=str,
                    ) + "\n"
                    return
                scan_path = clone_result["path"]
                yield json.dumps({"event": "git_clone_done", "path": scan_path}, default=str) + "\n"

            async for ev in iter_security_tools(
                f"authorized code analysis of {scan_path}",
                target=scan_path,
                tools=requested,
                authorized=bool(body.authorized),
                include_heavy=True,
                user_id=user.id,
            ):
                if ev.get("event") == "done":
                    done_payload = ev.get("payload") or ev
                    if scan and scan.get("id"):
                        ev = {**ev, "scan_id": scan["id"]}
                yield json.dumps(ev, default=str) + "\n"
        finally:
            if clone_result and clone_result.get("ok") and clone_result.get("path"):
                from app.services.git_ingest import cleanup_clone

                cleanup_clone(clone_result["path"])
            if scan and scan.get("id"):
                _finish_code_scan(scan["id"], done_payload)

    return StreamingResponse(gen(), media_type="application/x-ndjson")
