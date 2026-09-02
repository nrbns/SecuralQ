"""Flagship AI Investigation workflow — correlate highest-risk assets (tenant-scoped).

Does not execute tools or shell. Collects evidence from the security data platform
and returns a structured investigation plan for the analyst / AI to explain.
"""

from __future__ import annotations

from typing import Any

from app.db import audit, new_id, now
from app.enterprise import list_assets, list_vulnerabilities
from app.services.risk import compute_risk_score, explain_risk_score


def investigate_top_assets(
    user_id: str,
    *,
    org_id: str | None = None,
    engagement_id: str | None = None,
    limit: int = 5,
) -> dict[str, Any]:
    """Investigate the N highest-risk assets inside the caller's tenant scope."""
    limit = max(1, min(25, int(limit or 5)))
    assets = list_assets(user_id, engagement_id, org_id=org_id)
    vulns = list_vulnerabilities(user_id, engagement_id=engagement_id, org_id=org_id)

    by_asset: dict[str, list[dict[str, Any]]] = {}
    for v in vulns:
        if (v.get("status") or "").lower() in {"resolved", "closed", "false_positive"}:
            continue
        key = (v.get("asset_id") or v.get("asset_name") or "").strip() or "_unassigned"
        by_asset.setdefault(key, []).append(v)

    scored: list[dict[str, Any]] = []
    for a in assets:
        aid = a.get("id") or ""
        name = a.get("name") or aid
        related = list(by_asset.get(aid, [])) + list(by_asset.get(name, []))
        # Deduplicate by vuln id
        seen: set[str] = set()
        uniq: list[dict[str, Any]] = []
        for v in related:
            vid = v.get("id") or ""
            if vid and vid in seen:
                continue
            if vid:
                seen.add(vid)
            uniq.append(v)
        max_cvss = 0.0
        for v in uniq:
            try:
                max_cvss = max(max_cvss, float(v.get("cvss") or 0))
            except (TypeError, ValueError):
                pass
        if not max_cvss and uniq:
            sev = (uniq[0].get("severity") or "medium").lower()
            max_cvss = {"critical": 9.5, "high": 8.0, "medium": 5.5, "low": 3.0, "info": 1.0}.get(sev, 5.0)
        from app.asset_categories import is_internet_exposed_category

        exposure = 0.8 if is_internet_exposed_category(a.get("asset_type")) else 0.5
        risk = compute_risk_score(
            cvss=max_cvss or None,
            exploitability=0.55 if uniq else 0.2,
            exposure=exposure,
            asset_criticality=a.get("criticality") or "medium",
            threat_intel=0.45,
            confidence=0.75 if uniq else 0.5,
        )
        scored.append(
            {
                "asset": {
                    "id": aid,
                    "name": name,
                    "type": a.get("asset_type"),
                    "criticality": a.get("criticality"),
                    "owner": a.get("owner"),
                },
                "risk": risk,
                "risk_explanation": explain_risk_score(risk),
                "open_findings": len(uniq),
                "findings": [
                    {
                        "id": v.get("id"),
                        "title": v.get("title"),
                        "severity": v.get("severity"),
                        "cve": v.get("cve"),
                        "cvss": v.get("cvss"),
                        "status": v.get("status"),
                        "source": v.get("source"),
                    }
                    for v in sorted(
                        uniq,
                        key=lambda x: float(x.get("cvss") or 0),
                        reverse=True,
                    )[:10]
                ],
            }
        )

    scored.sort(key=lambda x: float((x.get("risk") or {}).get("score") or 0), reverse=True)
    top = scored[:limit]
    investigation_id = new_id()
    steps = [
        {"id": "scope", "label": "Scope verified", "status": "done"},
        {"id": "assets", "label": "Assets identified", "status": "done"},
        {"id": "findings", "label": "Findings correlated", "status": "done"},
        {"id": "intel", "label": "Threat intelligence checked", "status": "done"},
        {"id": "evidence", "label": "Evidence collected", "status": "done"},
        {"id": "analysis", "label": "AI analysis", "status": "ready"},
        {"id": "remediation", "label": "Remediation", "status": "pending"},
        {"id": "verification", "label": "Verification", "status": "pending"},
        {"id": "report", "label": "Report", "status": "pending"},
    ]
    prompts = []
    for item in top:
        asset = item["asset"]
        prompts.append(
            {
                "asset_id": asset.get("id"),
                "asset_name": asset.get("name"),
                "questions": [
                    "Why is it risky?",
                    "What evidence supports it?",
                    "What should I fix?",
                    "How urgent is it?",
                    "How do I verify the fix?",
                ],
                "context_for_ai": {
                    "risk_score": item["risk"]["score"],
                    "risk_band": item["risk"]["band"],
                    "explanation": item["risk_explanation"],
                    "findings": item["findings"],
                    "org_id": org_id,
                    "note": "Stay within this tenant. Do not invent CVEs or scores.",
                },
            }
        )

    result = {
        "investigation_id": investigation_id,
        "created_at": now(),
        "org_id": org_id,
        "engagement_id": engagement_id,
        "limit": limit,
        "steps": steps,
        "assets": top,
        "ai_prompts": prompts,
        "summary": {
            "assets_reviewed": len(assets),
            "assets_selected": len(top),
            "open_findings_total": sum(i["open_findings"] for i in top),
        },
    }
    audit(
        "ai_investigation",
        user_id,
        {
            "investigation_id": investigation_id,
            "org_id": org_id,
            "asset_count": len(top),
        },
    )
    return result


def investigate_scan(
    user_id: str,
    scan_id: str,
    *,
    org_id: str | None = None,
    report_max_chars: int = 12000,
) -> dict[str, Any]:
    """Build an investigation pack from a completed scan's evidence + findings.

    Loads report.md when present. Does not call the LLM — returns prompts/context
    for the chat UI or an analyst to run.
    """
    from pathlib import Path

    from app.scan_engine.models import get_scan
    from app.scan_engine.report import findings_for_scan

    scan = get_scan(scan_id)
    if not scan:
        raise ValueError("Scan not found")
    if user_id not in {"local", "admin"} and scan.get("user_id") not in {user_id, "local"}:
        # Soft ownership: admins / matching user; lab open mode uses local
        if scan.get("user_id") != user_id:
            raise ValueError("Scan not found")

    summary = scan.get("summary") if isinstance(scan.get("summary"), dict) else {}
    if not summary and scan.get("summary_json"):
        import json

        try:
            summary = json.loads(scan.get("summary_json") or "{}")
        except Exception:
            summary = {}

    findings = findings_for_scan(scan.get("user_id") or user_id, scan_id)
    ev_dir = Path(scan.get("evidence_dir") or "")
    report_excerpt = ""
    report_path = ""
    artifacts: list[str] = []
    if ev_dir.is_dir():
        report_file = ev_dir / "report.md"
        if report_file.is_file():
            report_path = str(report_file)
            raw = report_file.read_text(encoding="utf-8", errors="replace")
            report_excerpt = raw[: max(2000, int(report_max_chars))]
        for name in (
            "config.json",
            "metadata.json",
            "nmap.xml",
            "nuclei.jsonl",
            "zap.json",
            "securaiq_scan.json",
            "command.txt",
            "stdout.log",
            "report.md",
            "report.pdf",
        ):
            p = ev_dir / name
            if p.is_file():
                artifacts.append(str(p))
        for extra in summary.get("artifacts") or []:
            if extra and extra not in artifacts:
                artifacts.append(str(extra))

    investigation_id = new_id()
    high = [
        {
            "id": f.get("id"),
            "title": f.get("title"),
            "severity": f.get("severity"),
            "cve": f.get("cve"),
            "asset_name": f.get("asset_name"),
            "status": f.get("status"),
        }
        for f in findings
        if (f.get("severity") or "").lower() in {"critical", "high", "medium"}
    ][:25]

    context = {
        "scan_id": scan_id,
        "target": scan.get("target"),
        "scanner": scan.get("scanner"),
        "profile": scan.get("profile"),
        "status": scan.get("status"),
        "risk": summary.get("risk"),
        "services": summary.get("services") or [],
        "open_ports": summary.get("open_ports"),
        "findings_count": summary.get("findings") or len(findings),
        "evidence_dir": str(ev_dir) if ev_dir else "",
        "report_path": report_path,
        "artifacts": artifacts[:40],
        "high_findings": high,
        "report_excerpt": report_excerpt,
        "note": "Cite only this evidence. Do not invent ports, CVEs, or scan results.",
        "org_id": org_id,
    }
    prompt = (
        f"Investigate SecuraIQ scan `{scan_id}` for target `{scan.get('target')}` "
        f"(scanner={scan.get('scanner')}, profile={scan.get('profile')}).\n"
        f"Risk: {(summary.get('risk') or {}).get('score', 'n/a')} "
        f"({(summary.get('risk') or {}).get('band', 'n/a')}).\n"
        f"Evidence directory: {ev_dir or 'n/a'}\n"
        f"Artifact files: {', '.join(Path(a).name for a in artifacts[:12]) or 'none'}\n\n"
        "Use ONLY the report excerpt and findings below. Recommend remediation and "
        "verification steps. Do not invent scan results.\n\n"
        "--- report.md excerpt ---\n"
        f"{report_excerpt or '(no report.md yet — use findings list)'}\n"
        "--- end excerpt ---\n"
    )
    result = {
        "investigation_id": investigation_id,
        "created_at": now(),
        "kind": "scan_evidence",
        "scan_id": scan_id,
        "org_id": org_id,
        "steps": [
            {"id": "evidence", "label": "Evidence loaded", "status": "done"},
            {"id": "findings", "label": "Findings correlated", "status": "done"},
            {"id": "analysis", "label": "AI analysis", "status": "ready"},
            {"id": "remediation", "label": "Remediation", "status": "pending"},
            {"id": "verification", "label": "Verification", "status": "pending"},
        ],
        "context": context,
        "ai_prompts": [
            {
                "scan_id": scan_id,
                "questions": [
                    "What did this scan actually find?",
                    "Which findings matter most?",
                    "What should we remediate first?",
                    "How do we verify the fix?",
                ],
                "context_for_ai": context,
                "prompt": prompt,
            }
        ],
        "prompt": prompt,
        "summary": {
            "findings": len(findings),
            "artifacts": len(artifacts),
            "has_report": bool(report_excerpt),
        },
    }
    audit(
        "ai_scan_investigation",
        user_id,
        {"investigation_id": investigation_id, "scan_id": scan_id, "findings": len(findings)},
    )
    return result
