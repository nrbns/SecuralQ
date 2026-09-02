"""Scan engine executor — queue worker runs scanners; AI does not."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from app.enterprise import ensure_asset_for_target, upsert_vulnerability
from app.scan_engine.models import (
    evidence_root,
    get_scan,
    set_progress,
    update_scan,
)
from app.scanners.base import ScanContext
from app.scanners.registry import ENGINE_ENABLED, get_scanner
from app.services.tool_policy import assert_structured_scope, normalize_scope_json
from app.db import now


async def execute_scan(scan_id: str) -> dict[str, Any]:
    scan = get_scan(scan_id)
    if not scan:
        raise ValueError(f"scan not found: {scan_id}")

    scanner_id = (scan.get("scanner") or "securaiq").lower()
    if scanner_id not in ENGINE_ENABLED:
        update_scan(scan_id, status="failed", error=f"Scanner '{scanner_id}' not engine-enabled yet", completed_at=now())
        raise ValueError(f"Scanner '{scanner_id}' not enabled")

    scanner = get_scanner(scanner_id)
    target = scan["target"]
    scope = normalize_scope_json(scan.get("scope") or [])
    authorized = bool(scan.get("authorized"))
    profile = (scan.get("profile") or "discovery").lower()

    update_scan(scan_id, status="scope_check", started_at=now())
    set_progress(scan_id, "queued", "done")
    set_progress(scan_id, "scope", "active")

    if not authorized:
        update_scan(
            scan_id,
            status="blocked",
            error="Authorization checkbox required — only scan systems you own or are authorized to test",
            completed_at=now(),
        )
        set_progress(scan_id, "scope", "failed")
        return {"ok": False, "blocked": True, "reason": "not_authorized"}

    ok_req, req_reason = assert_structured_scope(
        scanner_id=scanner_id, profile=profile, scope=scope
    )
    if not ok_req:
        update_scan(scan_id, status="blocked", error=req_reason, completed_at=now())
        set_progress(scan_id, "scope", "failed")
        try:
            from app.realtime_bus import publish

            publish(type="scan", id=scan_id, status="blocked", reason=req_reason)
        except Exception:
            pass
        return {"ok": False, "blocked": True, "reason": req_reason}

    ok_t, t_detail = scanner.validate_target(target)
    if not ok_t:
        update_scan(scan_id, status="failed", error=t_detail, completed_at=now())
        return {"ok": False, "error": t_detail}

    ok_s, s_reason = scanner.validate_scope(t_detail, scope)
    if not ok_s:
        update_scan(scan_id, status="blocked", error=s_reason, completed_at=now())
        set_progress(scan_id, "scope", "failed")
        try:
            from app.realtime_bus import publish

            publish(type="scan", id=scan_id, status="blocked", reason=s_reason)
        except Exception:
            pass
        return {"ok": False, "blocked": True, "reason": s_reason}

    set_progress(scan_id, "scope", "done")
    avail, avail_detail = scanner.available()
    if not avail:
        update_scan(scan_id, status="failed", error=avail_detail, completed_at=now())
        return {"ok": False, "error": avail_detail}

    ev_dir = Path(scan.get("evidence_dir") or evidence_root(scan_id))
    ev_dir.mkdir(parents=True, exist_ok=True)
    # Persist scan config + metadata before the scanner runs (raw evidence pack).
    try:
        (ev_dir / "config.json").write_text(
            json.dumps(
                {
                    "scan_id": scan_id,
                    "target": t_detail,
                    "scanner": scanner_id,
                    "profile": scan.get("profile") or "discovery",
                    "scope": scope,
                    "authorized": True,
                    "engagement_id": scan.get("engagement_id"),
                    "org_id": scan.get("org_id"),
                    "user_id": scan.get("user_id"),
                },
                indent=2,
            ),
            encoding="utf-8",
        )
        (ev_dir / "metadata.json").write_text(
            json.dumps(
                {
                    "product": "securaiq",
                    "pipeline": [
                        "queued",
                        "scope_check",
                        "running",
                        "parsing",
                        "normalizing",
                        "risk",
                        "report",
                        "completed",
                    ],
                    "started_at": now(),
                },
                indent=2,
            ),
            encoding="utf-8",
        )
    except Exception:
        pass
    ctx = ScanContext(
        scan_id=scan_id,
        target=t_detail,
        profile=scan.get("profile") or "discovery",
        scope=scope,
        authorized=authorized,
        evidence_dir=ev_dir,
        engagement_id=scan.get("engagement_id"),
        org_id=scan.get("org_id"),
        user_id=scan.get("user_id"),
    )

    update_scan(scan_id, status="running")
    set_progress(scan_id, "discovery", "active")
    set_progress(scan_id, "port_scan", "active")

    raw = await scanner.execute(ctx)

    set_progress(scan_id, "discovery", "done")
    set_progress(scan_id, "port_scan", "done")
    set_progress(scan_id, "service_detect", "done")
    update_scan(scan_id, status="collecting")
    set_progress(scan_id, "collecting", "done")

    update_scan(scan_id, status="parsing")
    set_progress(scan_id, "parsing", "active")
    parsed = scanner.parse(raw, ctx)
    set_progress(scan_id, "parsing", "done")

    update_scan(scan_id, status="normalizing")
    set_progress(scan_id, "normalizing", "active")
    normalized = scanner.normalize(parsed, ctx)
    set_progress(scan_id, "normalizing", "done")
    set_progress(scan_id, "risk", "active")

    user_id = scan["user_id"]
    from app.asset_names import canonical_vuln_asset_name, resolve_target_labels

    labels = resolve_target_labels(t_detail, resolve_ptr=True)
    notes = json.dumps(
        {
            "ip": labels["ip"] or t_detail,
            "host": labels["host"],
            "hostname": labels["hostname"],
            "services": [s.__dict__ for s in normalized.services],
            "technologies": normalized.technologies,
            "scan_id": scan_id,
            "scanner": scanner_id,
            "source": f"scan:{scanner_id}",
        }
    )[:4000]
    asset = ensure_asset_for_target(
        user_id,
        labels["asset_name"],
        notes=notes,
        asset_type=normalized.asset_type or "host",
        engagement_id=scan.get("engagement_id"),
        org_id=scan.get("org_id"),
        resolve_ptr=True,
    )
    if asset and (asset or {}).get("id"):
        try:
            from app.software_inventory import ingest_from_scan_services

            ingest_from_scan_services(
                user_id,
                asset_id=str(asset.get("id") or ""),
                asset_name=labels["asset_name"],
                services=normalized.services or [],
                scanner=scanner_id,
            )
            try:
                from app.software_inventory import publish_software_realtime

                publish_software_realtime(user_id, {"scan_id": scan_id})
            except Exception:
                pass
        except Exception:
            pass
        try:
            from app.realtime_bus import publish

            publish(
                type="asset",
                id=asset.get("id"),
                scan_id=scan_id,
                user_id=user_id,
                action="scan_linked",
            )
        except Exception:
            pass

    try:
        from app.openaudit import ingest_live_device

        ports = []
        for s in normalized.services or []:
            try:
                ports.append(int(getattr(s, "port", 0) or 0))
            except (TypeError, ValueError):
                continue
        ports = [p for p in ports if p]
        ingest_live_device(
            user_id,
            {
                "device_id": f"live:{labels['ip'] or t_detail}",
                "name": labels["asset_name"],
                "hostname": labels["hostname"] or labels["host"],
                "ip": labels["ip"] or (t_detail if "." in str(t_detail) else ""),
                "type": normalized.asset_type or "host",
                "status": "production",
                "os": "",
                "domain": "",
                "description": "ports=" + ",".join(str(p) for p in ports[:24]),
                "raw": {
                    "source": "securaiq_audit",
                    "open_ports": ports[:40],
                    "scan_id": scan_id,
                    "scanner": scanner_id,
                    "technologies": normalized.technologies,
                },
            },
        )
    except Exception:
        pass

    created = 0
    updated = 0
    finding_rows: list[dict[str, Any]] = []
    try:
        from app.realtime_bus import publish

        publish(type="scan", id=scan_id, status="normalizing", step="risk", findings=0)
    except Exception:
        pass
    for f in normalized.findings:
        vuln_asset = canonical_vuln_asset_name(
            f.asset_name or labels["asset_name"],
            asset=asset if isinstance(asset, dict) else None,
        )
        item = {
            "title": f.title,
            "severity": f.severity,
            "asset_name": vuln_asset,
            "asset_id": (asset or {}).get("id"),
            "cve": f.cve,
            "cvss": f.cvss,
            "source": f.source or f"scan:{scanner_id}",
            "engagement_id": scan.get("engagement_id"),
            "org_id": scan.get("org_id"),
            "raw": {
                **(f.raw or {}),
                "evidence": f.evidence,
                "scan_id": scan_id,
                "artifacts": raw.artifact_paths,
                "remediation": getattr(f, "remediation", None) or (f.raw or {}).get("remediation"),
            },
        }
        row = upsert_vulnerability(user_id, item, emit_realtime=True)
        finding_rows.append(row or item)
        if (row or {}).get("_upsert") == "updated":
            updated += 1
        else:
            created += 1
        total = created + updated
        if total == 1 or total % 5 == 0:
            try:
                from app.realtime_bus import publish

                publish(
                    type="scan",
                    id=scan_id,
                    status="normalizing",
                    step="risk",
                    findings=total,
                )
            except Exception:
                pass

    # Deterministic risk from real findings (AI explains this — does not invent it).
    risk_summary = _scan_risk_from_findings(
        user_id=user_id,
        findings=finding_rows,
        asset=asset,
        asset_name=normalized.asset_name or t_detail,
        scan_id=scan_id,
        scanner_id=scanner_id,
        engagement_id=scan.get("engagement_id"),
        org_id=scan.get("org_id"),
        services=normalized.services or [],
    )

    summary = {
        **(normalized.summary or {}),
        "asset_id": (asset or {}).get("id"),
        "findings_created": created,
        "findings_updated": updated,
        "findings": created + updated,
        "exit_code": raw.exit_code,
        "artifacts": list(raw.artifact_paths or []),
        "services": [
            {
                "port": getattr(s, "port", None),
                "protocol": getattr(s, "protocol", "tcp"),
                "service": getattr(s, "service", "") or getattr(s, "name", ""),
                "product": getattr(s, "product", "") or "",
            }
            for s in (normalized.services or [])[:40]
        ],
        "risk": risk_summary,
    }
    if raw.exit_code not in (0, None) and not normalized.services and not normalized.findings:
        err = (raw.stderr or raw.stdout or f"scanner exit {raw.exit_code}")[:2000]
        update_scan(
            scan_id,
            status="failed",
            error=err,
            summary_json=summary,
            completed_at=now(),
        )
        set_progress(scan_id, "risk", "failed")
        return {"ok": False, "error": err, "summary": summary}

    set_progress(scan_id, "risk", "done")
    set_progress(scan_id, "report", "active")
    from app.scan_engine.report import write_scan_report

    report_scan = {**scan, "summary": summary, "status": "completed", "id": scan_id}
    report_path = write_scan_report(ev_dir, report_scan, findings=finding_rows)
    summary["report"] = str(report_path)
    summary["report_url"] = f"/api/scans/{scan_id}/report"
    summary["report_pdf_url"] = f"/api/scans/{scan_id}/report.pdf"
    try:
        from app.commercial_ext import markdown_to_simple_pdf

        pdf_bytes = markdown_to_simple_pdf(
            report_path.read_text(encoding="utf-8"),
            title=f"SecuraIQ VA Report — {t_detail}",
        )
        pdf_path = ev_dir / "report.pdf"
        pdf_path.write_bytes(pdf_bytes)
        summary["report_pdf"] = str(pdf_path)
        if str(pdf_path) not in summary["artifacts"]:
            summary["artifacts"] = [*summary["artifacts"], str(pdf_path)]
    except Exception:
        pass
    if str(report_path) not in summary["artifacts"]:
        summary["artifacts"] = [*summary["artifacts"], str(report_path)]

    set_progress(scan_id, "report", "done")
    try:
        meta_path = ev_dir / "metadata.json"
        meta = {}
        if meta_path.is_file():
            meta = json.loads(meta_path.read_text(encoding="utf-8"))
        meta.update(
            {
                "completed_at": now(),
                "status": "completed",
                "findings": created + updated,
                "risk_score": (risk_summary or {}).get("score"),
                "artifacts": summary.get("artifacts") or [],
            }
        )
        meta_path.write_text(json.dumps(meta, indent=2), encoding="utf-8")
        if str(meta_path) not in summary["artifacts"]:
            summary["artifacts"] = [*summary["artifacts"], str(meta_path)]
        cfg = ev_dir / "config.json"
        if cfg.is_file() and str(cfg) not in summary["artifacts"]:
            summary["artifacts"] = [*summary["artifacts"], str(cfg)]
    except Exception:
        pass
    update_scan(
        scan_id,
        status="completed",
        summary_json=summary,
        completed_at=now(),
        error="",
    )
    # Correlate scan → asset → findings in the knowledge graph (best-effort).
    try:
        from app.knowledge_graph import add_entity_link, rebuild_auto_links

        aid = (asset or {}).get("id")
        if aid:
            add_entity_link(
                user_id,
                src_type="scan",
                src_id=scan_id,
                dst_type="asset",
                dst_id=str(aid),
                relation="discovered",
                notes=f"scanner={scanner_id}",
            )
            for row in finding_rows[:40]:
                vid = (row or {}).get("id")
                if not vid:
                    continue
                add_entity_link(
                    user_id,
                    src_type="asset",
                    src_id=str(aid),
                    dst_type="vuln",
                    dst_id=str(vid),
                    relation="has_finding",
                    notes=f"scan_id={scan_id}",
                )
        rebuild_auto_links(user_id)
    except Exception:
        pass
    try:
        from app.realtime_bus import publish

        publish(type="scan", id=scan_id, status="completed", summary=summary)
        if created:
            publish(
                type="vuln_batch",
                source=f"scan:{scanner_id}",
                count=created,
                scan_id=scan_id,
            )
    except Exception:
        pass
    return {"ok": True, "scan_id": scan_id, "summary": summary}


_SEV_CVSS = {
    "critical": 9.5,
    "high": 7.5,
    "medium": 5.0,
    "low": 3.0,
    "info": 1.0,
}
_SEV_IMPACT = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}


def _scan_risk_from_findings(
    *,
    user_id: str,
    findings: list[dict[str, Any]],
    asset: dict[str, Any] | None,
    asset_name: str,
    scan_id: str,
    scanner_id: str,
    engagement_id: str | None,
    org_id: str | None,
    services: list[Any],
) -> dict[str, Any]:
    """Compute scan-level risk and open register rows for high+ findings."""
    from app.services.risk import compute_risk_score, create_risk, explain_risk_score

    if not findings:
        empty = compute_risk_score(cvss=0.0, exploitability=0.2, exposure=0.3, confidence=0.6)
        empty["explanation"] = explain_risk_score(empty)
        empty["risks_created"] = 0
        return empty

    max_sev = "info"
    order = ("info", "low", "medium", "high", "critical")
    for f in findings:
        sev = (f.get("severity") or "info").lower()
        if sev not in order:
            continue
        if order.index(sev) > order.index(max_sev):
            max_sev = sev

    open_ports = len(services or [])
    exposure = min(1.0, 0.35 + 0.05 * open_ports)
    if max_sev in {"high", "critical"}:
        exposure = max(exposure, 0.7)
    crit = (asset or {}).get("criticality") or "medium"
    score = compute_risk_score(
        cvss=_SEV_CVSS.get(max_sev, 5.0),
        exploitability=0.55 if max_sev in {"high", "critical"} else 0.35,
        exposure=exposure,
        asset_criticality=str(crit),
        confidence=0.75,
    )
    score["max_severity"] = max_sev
    score["explanation"] = explain_risk_score(score)

    risks_created = 0
    for f in findings:
        sev = (f.get("severity") or "").lower()
        if sev not in {"high", "critical"}:
            continue
        try:
            create_risk(
                user_id,
                threat=f"Scan finding ({scanner_id}): {(f.get('title') or 'issue')[:180]}",
                vulnerability=(f.get("cve") or f.get("title") or "")[:240],
                asset_name=asset_name,
                asset_id=(asset or {}).get("id"),
                impact=_SEV_IMPACT.get(sev, 3),
                likelihood=4 if sev == "critical" else 3,
                mitigation=(
                    ((f.get("raw") or {}).get("remediation") if isinstance(f.get("raw"), dict) else None)
                    or "Triage against scan evidence; patch or harden the exposed service."
                )[:2000],
                status="open",
                engagement_id=engagement_id,
                org_id=org_id,
            )
            risks_created += 1
        except Exception:
            continue
    score["risks_created"] = risks_created
    score["scan_id"] = scan_id
    return score


def enqueue_scan_job(scan_id: str) -> dict[str, Any]:
    """Create background job linked to scan record."""
    import app.scan_engine.jobs  # noqa: F401 — ensure handler registered
    from app.jobs import enqueue_job

    job = enqueue_job("scan_execute", {"scan_id": scan_id})
    update_scan(scan_id, job_id=job.get("id"))
    return job
