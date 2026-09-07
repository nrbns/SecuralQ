"""Integrated combo assessment workflow.

authorize + scope → securaiq (+ nmap/nuclei/zap when available) →
evidence → investigate-scan pack → optional auto-triage high/critical.

Child scanners call ``execute_scan`` directly (not the job queue) so a
single in-process worker cannot deadlock waiting on ``scan_execute``.
"""

from __future__ import annotations

from typing import Any

from app.enterprise import triage_vulnerability
from app.jobs import enqueue_job, register_job
from app.scan_engine.executor import execute_scan
from app.scan_engine.models import create_scan, get_scan
from app.scan_engine.report import findings_for_scan
from app.scanners.registry import ENGINE_ENABLED, get_scanner
from app.services.investigation import investigate_scan
from app.services.tool_policy import (
    assert_structured_scope,
    normalize_scope_json,
)

# Default combo engines (discovery-first). Web engines opt-in via include_web.
_COMBO_CORE = ("securaiq", "nmap")
_COMBO_WEB = ("nuclei", "zap")


def default_scope_for_target(target: str) -> list[str]:
    """Build minimal structured scope from a scan target (IP/URL/hostname)."""
    import re

    from app.scanners.nuclei import _hostname_from_target

    raw = (target or "").strip()
    if not raw:
        return []
    host = (_hostname_from_target(raw) or raw).strip().lower().rstrip(".")
    ip = host.split(":")[0] if host else ""
    scope: list[str] = []
    if host:
        scope.append(host)
    if re.match(r"^\d+\.\d+\.\d+\.\d+$", ip):
        if ip not in scope:
            scope.append(ip)
        if ip.startswith("127."):
            scope.append("127.0.0.0/8")
        elif ip.startswith("10."):
            scope.append("10.0.0.0/8")
        elif ip.startswith("192.168."):
            scope.append("192.168.0.0/16")
        elif ip.startswith("172."):
            second = int(ip.split(".")[1]) if ip.count(".") >= 1 else 0
            if 16 <= second <= 31:
                scope.append("172.16.0.0/12")
    # Dedupe preserving order
    seen: set[str] = set()
    out: list[str] = []
    for tok in scope:
        if tok and tok not in seen:
            seen.add(tok)
            out.append(tok)
    return out


def _combo_publish(**kwargs: Any) -> None:
    try:
        from app.realtime_bus import publish

        publish(type="combo", **kwargs)
    except Exception:
        pass


def resolve_combo_scanners(*, include_web: bool = False) -> list[str]:
    """Return available engine ids in preferred order."""
    order = list(_COMBO_CORE)
    if include_web:
        order.extend(_COMBO_WEB)
    out: list[str] = []
    for sid in order:
        if sid not in ENGINE_ENABLED:
            continue
        try:
            sc = get_scanner(sid)
        except KeyError:
            continue
        ok, _ = sc.available()
        if ok:
            out.append(sid)
    if "securaiq" not in out:
        # Builtin should always be available; force-include if registry says so
        if "securaiq" in ENGINE_ENABLED:
            out.insert(0, "securaiq")
    return out


async def run_combo_assessment(
    *,
    user_id: str,
    target: str,
    scope: list[str] | str | None,
    authorized: bool,
    profile: str = "discovery",
    engagement_id: str | None = None,
    org_id: str | None = None,
    include_web: bool = False,
    auto_triage_high: bool = True,
    scanners: list[str] | None = None,
    job_id: str | None = None,
) -> dict[str, Any]:
    """Run the full combo pipeline and return an investigation pack."""
    if not authorized:
        return {
            "ok": False,
            "blocked": True,
            "error": "Authorization required — only assess systems you own or are authorized to test.",
        }

    scope_list = normalize_scope_json(scope)
    if not scope_list and target:
        scope_list = default_scope_for_target(target)
    profile = (profile or "discovery").lower().strip()
    if profile not in {"discovery", "web", "vulnerability", "full"}:
        profile = "discovery"

    wanted = scanners or resolve_combo_scanners(
        include_web=include_web or profile in {"full", "vulnerability"}
    )
    if not wanted:
        return {"ok": False, "error": "No scanners available for combo assessment"}

    # Scope required whenever any non-legacy engine is in the set, or VA/full profile
    for sid in wanted:
        ok_req, reason = assert_structured_scope(
            scanner_id=sid, profile=profile, scope=scope_list
        )
        if not ok_req:
            return {"ok": False, "blocked": True, "error": reason, "scanner": sid}

    steps: list[dict[str, Any]] = [
        {"id": "authorize", "label": "Authorized", "status": "done"},
        {"id": "scope", "label": "Scope verified", "status": "done"},
        {"id": "scan", "label": "Scanners running", "status": "active"},
        {"id": "evidence", "label": "Evidence pack", "status": "pending"},
        {"id": "investigate", "label": "Investigation pack", "status": "pending"},
        {"id": "triage", "label": "Auto-triage", "status": "pending"},
    ]

    _combo_publish(
        status="running",
        step="scan",
        target=target,
        scanners=wanted,
        user_id=user_id,
        job_id=job_id,
        steps=steps,
    )

    scan_results: list[dict[str, Any]] = []
    skipped: list[dict[str, str]] = []

    for sid in wanted:
        try:
            scanner = get_scanner(sid)
        except KeyError:
            skipped.append({"scanner": sid, "reason": "unknown scanner"})
            continue
        ok_t, t_detail = scanner.validate_target(target)
        if not ok_t:
            skipped.append({"scanner": sid, "reason": t_detail})
            continue
        ok_s, s_reason = scanner.validate_scope(t_detail, scope_list)
        if not ok_s:
            skipped.append({"scanner": sid, "reason": s_reason})
            continue
        avail, avail_detail = scanner.available()
        if not avail:
            skipped.append({"scanner": sid, "reason": avail_detail})
            continue

        scan = create_scan(
            user_id=user_id,
            target=t_detail,
            scanner=sid,
            profile=profile,
            scope=scope_list,
            engagement_id=engagement_id,
            org_id=org_id,
            authorized=True,
        )
        _combo_publish(
            status="running",
            step="scan",
            scanner=sid,
            scan_id=scan["id"],
            target=target,
            job_id=job_id,
            steps=steps,
            scan_detail=f"Starting {sid}",
        )
        # Direct execute — do not enqueue scan_execute (avoids worker deadlock).
        try:
            exec_out = await execute_scan(scan["id"])
        except Exception as exc:  # noqa: BLE001
            exec_out = {"ok": False, "error": str(exc)}
        final = get_scan(scan["id"]) or scan
        _combo_publish(
            status="running",
            step="scan",
            scanner=sid,
            scan_id=scan["id"],
            scan_status=final.get("status"),
            job_id=job_id,
            steps=steps,
            scan_detail=f"{sid} {(final.get('status') or '').lower()}",
        )
        scan_results.append(
            {
                "scan_id": scan["id"],
                "scanner": sid,
                "status": final.get("status"),
                "summary": final.get("summary") if isinstance(final.get("summary"), dict) else {},
                "error": final.get("error") or exec_out.get("error") or "",
                "ok": bool(exec_out.get("ok")) and (final.get("status") == "completed"),
            }
        )

    steps[2]["status"] = "done"
    steps[3]["status"] = "active"
    _combo_publish(
        status="running",
        step="evidence",
        target=target,
        job_id=job_id,
        steps=steps,
        scan_ids=[r["scan_id"] for r in scan_results],
    )

    completed = [r for r in scan_results if r.get("ok")]
    # Prefer nmap evidence when present, else first completed, else first attempted
    primary = next((r for r in completed if r["scanner"] == "nmap"), None)
    if not primary:
        primary = completed[0] if completed else (scan_results[0] if scan_results else None)
    if not primary:
        return {
            "ok": False,
            "error": "All combo scanners failed or were skipped",
            "skipped": skipped,
            "scans": scan_results,
            "steps": steps,
        }

    primary_id = primary["scan_id"]
    steps[3]["status"] = "done"
    steps[4]["status"] = "active"
    _combo_publish(
        status="running",
        step="investigate",
        primary_scan_id=primary_id,
        job_id=job_id,
        steps=steps,
    )

    investigation = investigate_scan(user_id, primary_id, org_id=org_id)

    # Merge findings from all completed scans into the pack summary
    all_findings: list[dict[str, Any]] = []
    seen_ids: set[str] = set()
    for r in completed:
        for f in findings_for_scan(user_id, r["scan_id"]):
            fid = str(f.get("id") or "")
            if fid and fid in seen_ids:
                continue
            if fid:
                seen_ids.add(fid)
            all_findings.append(f)

    high = [
        f
        for f in all_findings
        if (f.get("severity") or "").lower() in {"critical", "high"}
    ]

    steps[4]["status"] = "done"
    steps[5]["status"] = "active" if auto_triage_high else "skipped"
    _combo_publish(
        status="running",
        step="triage",
        primary_scan_id=primary_id,
        findings=len(all_findings),
        job_id=job_id,
        steps=steps,
    )

    triage_out: list[dict[str, Any]] = []
    if auto_triage_high:
        for f in high[:20]:
            vid = f.get("id")
            if not vid:
                continue
            try:
                triage_out.append(triage_vulnerability(user_id, str(vid), owner="SecOps"))
            except Exception as exc:  # noqa: BLE001
                triage_out.append({"ok": False, "vuln_id": vid, "error": str(exc)})
        steps[5]["status"] = "done"
    else:
        steps[5]["status"] = "skipped"

    # Enrich prompt with multi-scanner note
    prompt = investigation.get("prompt") or ""
    extra = (
        f"\n\n--- combo assessment ---\n"
        f"Scanners completed: {', '.join(r['scanner'] for r in completed)}\n"
        f"Scan ids: {', '.join(r['scan_id'] for r in completed)}\n"
        f"Merged findings: {len(all_findings)} (high/critical: {len(high)})\n"
        f"Auto-triaged: {sum(1 for t in triage_out if t.get('ok'))}\n"
        f"Cite only evidence from these scans. Do not invent results.\n"
    )
    prompt = (prompt + extra).strip()

    result = {
        "ok": True,
        "workflow": "combo_assessment",
        "target": target,
        "profile": profile,
        "scope": scope_list,
        "primary_scan_id": primary_id,
        "scan_ids": [r["scan_id"] for r in scan_results],
        "scans": scan_results,
        "skipped": skipped,
        "steps": steps,
        "findings_count": len(all_findings),
        "high_findings": [
            {
                "id": f.get("id"),
                "title": f.get("title"),
                "severity": f.get("severity"),
                "cve": f.get("cve"),
                "asset_name": f.get("asset_name"),
            }
            for f in high[:25]
        ],
        "triage": [
            {
                "ok": t.get("ok"),
                "vuln_id": (t.get("vulnerability") or {}).get("id") or t.get("vuln_id"),
                "risk_id": (t.get("risk") or {}).get("id"),
                "remediation_id": (t.get("remediation") or {}).get("id"),
                "error": t.get("error"),
            }
            for t in triage_out
        ],
        "investigation_id": investigation.get("investigation_id"),
        "prompt": prompt,
        "report_url": f"/api/scans/{primary_id}/report",
        "report_pdf_url": f"/api/scans/{primary_id}/report.pdf",
        "summary": {
            **(investigation.get("summary") or {}),
            "scanners_ok": len(completed),
            "scanners_attempted": len(scan_results),
            "triaged": sum(1 for t in triage_out if t.get("ok")),
            "high_critical": len(high),
        },
    }

    _combo_publish(
        status="completed",
        primary_scan_id=primary_id,
        findings=len(all_findings),
        user_id=user_id,
        job_id=job_id,
        steps=steps,
        scan_ids=result["scan_ids"],
    )
    return result


def enqueue_combo_assessment(payload: dict[str, Any]) -> dict[str, Any]:
    """Queue combo_assessment on the background worker; returns the job row."""
    return enqueue_job("combo_assessment", payload)


@register_job("combo_assessment")
async def handle_combo_assessment(payload: dict[str, Any]) -> dict[str, Any]:
    job_id = payload.pop("_job_id", None)
    return await run_combo_assessment(
        user_id=str(payload.get("user_id") or "local"),
        target=str(payload.get("target") or "").strip(),
        scope=payload.get("scope"),
        authorized=bool(payload.get("authorized")),
        profile=str(payload.get("profile") or "discovery"),
        engagement_id=payload.get("engagement_id"),
        org_id=payload.get("org_id"),
        include_web=bool(payload.get("include_web")),
        auto_triage_high=bool(payload.get("auto_triage_high", True)),
        scanners=payload.get("scanners"),
        job_id=str(job_id) if job_id else None,
    )


# Keep import side-effect registration discoverable
__all__ = [
    "run_combo_assessment",
    "enqueue_combo_assessment",
    "resolve_combo_scanners",
    "default_scope_for_target",
    "handle_combo_assessment",
]
