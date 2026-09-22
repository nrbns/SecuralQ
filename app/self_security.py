"""Self-security dogfood report — productize Bandit/tooling scans of SecuraIQ itself.

Honesty: this is an in-product snapshot of CI-class tooling (Bandit). Trivy/ZAP
still live in GitHub Actions; this report never invents CVE counts.
"""

from __future__ import annotations

import json
import os
import subprocess
import time
from pathlib import Path
from typing import Any

from app.config import settings
from app.db import get_conn, new_id, now


def ensure_dogfood_schema() -> None:
    c = get_conn()
    c.executescript(
        """
        CREATE TABLE IF NOT EXISTS self_security_dogfood (
            id TEXT PRIMARY KEY,
            generated_at REAL NOT NULL,
            tool TEXT NOT NULL DEFAULT 'bandit',
            summary_json TEXT NOT NULL DEFAULT '{}',
            findings_json TEXT NOT NULL DEFAULT '[]',
            markdown TEXT NOT NULL DEFAULT '',
            ok INTEGER NOT NULL DEFAULT 1
        );
        """
    )
    c.commit()


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def _report_path() -> Path:
    root = Path(settings.data_dir) / "ops"
    root.mkdir(parents=True, exist_ok=True)
    return root / "self_security_dogfood.json"


def run_bandit_scan(*, timeout_sec: int = 120) -> dict[str, Any]:
    """Run Bandit against app/ when available; otherwise return tooling-absent status."""
    app_dir = _repo_root() / "app"
    cmd = [
        os.environ.get("PYTHON", "python"),
        "-m",
        "bandit",
        "-r",
        str(app_dir),
        "-ll",
        "-x",
        str(app_dir / "fine_tune"),
        "-f",
        "json",
    ]
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=max(30, timeout_sec),
            check=False,
        )
    except FileNotFoundError:
        return {
            "ok": False,
            "tool": "bandit",
            "available": False,
            "error": "bandit not installed",
            "findings": [],
            "summary": {},
        }
    except subprocess.TimeoutExpired:
        return {
            "ok": False,
            "tool": "bandit",
            "available": True,
            "error": "bandit timed out",
            "findings": [],
            "summary": {},
        }

    findings: list[dict[str, Any]] = []
    summary: dict[str, Any] = {}
    raw = (proc.stdout or "").strip()
    if raw:
        try:
            data = json.loads(raw)
            metrics = data.get("metrics") or {}
            summary = {
                "high": int((metrics.get("_totals") or {}).get("SEVERITY.HIGH") or 0),
                "medium": int((metrics.get("_totals") or {}).get("SEVERITY.MEDIUM") or 0),
                "low": int((metrics.get("_totals") or {}).get("SEVERITY.LOW") or 0),
                "files_scanned": len((metrics or {}).keys()) - (1 if "_totals" in metrics else 0),
            }
            for r in data.get("results") or []:
                findings.append(
                    {
                        "test_id": r.get("test_id"),
                        "severity": (r.get("issue_severity") or "").upper(),
                        "confidence": (r.get("issue_confidence") or "").upper(),
                        "filename": r.get("filename"),
                        "line": r.get("line_number"),
                        "issue": (r.get("issue_text") or "")[:300],
                    }
                )
        except json.JSONDecodeError:
            summary = {"parse_error": True, "stdout_snip": raw[:400]}

    return {
        "ok": proc.returncode in (0, 1),  # bandit: 1 = findings
        "tool": "bandit",
        "available": True,
        "exit_code": proc.returncode,
        "summary": summary,
        "findings": findings[:200],
        "finding_count": len(findings),
        "stderr_snip": (proc.stderr or "")[:400],
    }


def build_markdown(report: dict[str, Any]) -> str:
    summ = report.get("summary") or {}
    lines = [
        "# SecuraIQ self-security dogfood",
        "",
        f"Generated: `{time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(report.get('generated_at') or time.time()))}`",
        "",
        "## Scope",
        "",
        "- In-product Bandit SAST against `app/`.",
        "- CI also runs Trivy/Semgrep/Gitleaks/Checkov/ZAP (see `.github/workflows/security-scan.yml`).",
        "- This report does **not** invent container CVE counts when Trivy is absent.",
        "",
        "## Bandit summary",
        "",
        f"- Available: `{report.get('available')}`",
        f"- OK: `{report.get('ok')}`",
        f"- High: `{summ.get('high', 'n/a')}` · Medium: `{summ.get('medium', 'n/a')}` · Low: `{summ.get('low', 'n/a')}`",
        f"- Findings captured: `{report.get('finding_count', 0)}`",
        "",
    ]
    findings = report.get("findings") or []
    if findings:
        lines.append("## Top findings (cap 25)")
        lines.append("")
        for f in findings[:25]:
            lines.append(
                f"- `{f.get('severity')}` `{f.get('test_id')}` "
                f"{f.get('filename')}:{f.get('line')} — {f.get('issue')}"
            )
        lines.append("")
    else:
        lines.append("_No findings in snapshot (or Bandit unavailable)._")
        lines.append("")
    lines.append("## Honesty")
    lines.append("")
    lines.append(
        "Lab-production dogfood report. Not a full pentest or FedRAMP evidence package."
    )
    lines.append("")
    return "\n".join(lines)


def generate_dogfood_report(*, run_scan: bool = True) -> dict[str, Any]:
    """Build + persist dogfood snapshot; optionally run Bandit."""
    ensure_dogfood_schema()
    scan = run_bandit_scan() if run_scan else {
        "ok": True,
        "tool": "bandit",
        "available": False,
        "summary": {},
        "findings": [],
        "finding_count": 0,
        "note": "scan skipped",
    }
    ts = now()
    report = {
        **scan,
        "generated_at": ts,
        "ci_workflow": ".github/workflows/security-scan.yml",
        "tools_documented": ["bandit", "trivy", "semgrep", "gitleaks", "checkov", "zap"],
    }
    md = build_markdown(report)
    report["markdown"] = md
    rid = new_id()
    get_conn().execute(
        """
        INSERT INTO self_security_dogfood
        (id, generated_at, tool, summary_json, findings_json, markdown, ok)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (
            rid,
            ts,
            str(report.get("tool") or "bandit"),
            json.dumps(report.get("summary") or {}),
            json.dumps(report.get("findings") or []),
            md,
            1 if report.get("ok") else 0,
        ),
    )
    get_conn().commit()
    path = _report_path()
    path.write_text(json.dumps({k: v for k, v in report.items() if k != "markdown"}, indent=2), encoding="utf-8")
    md_path = Path(settings.data_dir) / "ops" / "SELF-SECURITY-DOGFOOD.md"
    md_path.write_text(md, encoding="utf-8")
    report["id"] = rid
    report["path"] = str(path)
    report["markdown_path"] = str(md_path)
    return report


def latest_dogfood_report() -> dict[str, Any] | None:
    ensure_dogfood_schema()
    row = get_conn().execute(
        "SELECT * FROM self_security_dogfood ORDER BY generated_at DESC LIMIT 1"
    ).fetchone()
    if not row:
        # Fall back to on-disk snapshot
        path = _report_path()
        if path.is_file():
            try:
                return json.loads(path.read_text(encoding="utf-8"))
            except Exception:
                return None
        return None
    return {
        "id": row["id"],
        "generated_at": row["generated_at"],
        "tool": row["tool"],
        "summary": json.loads(row["summary_json"] or "{}"),
        "findings": json.loads(row["findings_json"] or "[]"),
        "markdown": row["markdown"],
        "ok": bool(row["ok"]),
    }
