"""HardeningKitty + CIS Downloads orchestration (authorized Windows labs).

HardeningKitty: https://github.com/scipag/HardeningKitty
CIS Downloads:  https://downloads.cisecurity.org/#/

SecuraIQ supports:
  * detecting / listing HardeningKitty finding lists on disk
  * importing Audit report CSV into vulnerabilities
  * running Audit / Config locally via PowerShell (never HailMary from the API)

HailMary (apply settings) stays out of the HTTP API — use PowerShell on the
owned host after backup, per HardeningKitty docs.
"""

from __future__ import annotations

import asyncio
import csv
import io
import platform
import re
import shutil
from pathlib import Path
from typing import Any

from app.config import settings
from app.db import get_conn, new_id, now

_CIS_DOWNLOADS = "https://downloads.cisecurity.org/#/"
_HK_REPO = "https://github.com/scipag/HardeningKitty"

# Typical HardeningKitty Audit report columns
_REPORT_MARKERS = {"id", "category", "name", "severity", "result", "recommended", "testresult"}


def cis_downloads_url() -> str:
    return _CIS_DOWNLOADS


def repo_url() -> str:
    return _HK_REPO


def module_path() -> Path | None:
    raw = (getattr(settings, "hardeningkitty_module_path", "") or "").strip()
    if raw:
        p = Path(raw).expanduser()
        if p.is_file() and p.suffix.lower() == ".psm1":
            return p.parent
        if p.is_dir():
            return p
    # Common installs
    candidates: list[Path] = []
    for base in (
        Path(r"C:\Program Files\WindowsPowerShell\Modules\HardeningKitty"),
        Path.home() / "Documents" / "WindowsPowerShell" / "Modules" / "HardeningKitty",
        Path.home() / "Documents" / "PowerShell" / "Modules" / "HardeningKitty",
        Path("tools") / "HardeningKitty",
        Path("vendor") / "HardeningKitty",
    ):
        if base.is_dir():
            candidates.append(base)
            # versioned subdirs
            for child in sorted(base.glob("*"), reverse=True):
                if child.is_dir() and (child / "HardeningKitty.psm1").is_file():
                    return child
            if (base / "HardeningKitty.psm1").is_file():
                return base
    return None


def is_installed() -> bool:
    root = module_path()
    return bool(root and (root / "HardeningKitty.psm1").is_file())


def list_finding_lists(limit: int = 80) -> list[dict[str, str]]:
    root = module_path()
    if not root:
        return []
    lists_dir = root / "lists"
    if not lists_dir.is_dir():
        return []
    out: list[dict[str, str]] = []
    for path in sorted(lists_dir.glob("finding_list_*.csv")):
        name = path.name
        kind = "cis" if "cis_" in name.lower() else "baseline"
        out.append(
            {
                "name": name,
                "path": str(path),
                "kind": kind,
                "label": name.replace("finding_list_", "").replace(".csv", "").replace("_", " "),
            }
        )
        if len(out) >= limit:
            break
    return out


def status() -> dict[str, Any]:
    root = module_path()
    lists = list_finding_lists()
    cis_lists = [x for x in lists if x.get("kind") == "cis"]
    return {
        "installed": is_installed(),
        "platform": platform.system(),
        "module_path": str(root) if root else "",
        "finding_lists": len(lists),
        "cis_lists": len(cis_lists),
        "default_list": (getattr(settings, "hardeningkitty_list", "") or "").strip(),
        "powershell": bool(shutil.which("powershell") or shutil.which("pwsh")),
        "cis_downloads": _CIS_DOWNLOADS,
        "repo": _HK_REPO,
        "modes_supported": ["Audit", "Config"],
        "modes_blocked": ["HailMary", "GPO"],
        "hint": (
            "Install HardeningKitty, set HARDENINGKITTY_MODULE_PATH in Settings, "
            "download official CIS Benchmarks from CIS Downloads when needed, "
            "then run Audit or import a report CSV on Vulnerabilities."
        ),
    }


def is_hardeningkitty_report(text: str, filename: str = "") -> bool:
    name = (filename or "").lower()
    if "hardeningkitty" in name or "finding_list_" in name:
        # finding lists are baselines, not reports — still parseable but skip import of baselines as vulns
        if name.startswith("finding_list_") or "/lists/" in name.replace("\\", "/"):
            return False
        if "hardeningkitty" in name or "hardening_kitty" in name:
            return True
    header = (text.splitlines()[0] if text else "").lower()
    cols = {c.strip().strip('"') for c in header.split(",")}
    return _REPORT_MARKERS.issubset(cols) or (
        {"id", "name", "severity", "result", "recommended"}.issubset(cols) and "testresult" in cols
    )


def _sev_map(row: dict[str, str]) -> str:
    test = (row.get("TestResult") or row.get("testresult") or "").strip().lower()
    sev = (row.get("Severity") or row.get("severity") or "").strip().lower()
    finding = (row.get("SeverityFinding") or row.get("severityfinding") or sev).strip().lower()
    if test == "passed" or sev == "passed":
        return "info"
    if finding in {"high", "critical"}:
        return "high" if finding == "high" else "critical"
    if finding == "medium":
        return "medium"
    if finding == "low":
        return "low"
    if sev in {"high", "medium", "low", "critical"}:
        return sev
    return "medium"


def parse_report_csv(
    text: str,
    *,
    engagement_id: str | None = None,
    filename: str = "",
    include_passed: bool = False,
) -> list[dict[str, Any]]:
    """Normalize HardeningKitty Audit CSV rows into SecuraIQ vuln items."""
    reader = csv.DictReader(io.StringIO(text))
    items: list[dict[str, Any]] = []
    for row in reader:
        if not isinstance(row, dict):
            continue
        # normalize keys
        norm = {str(k).strip(): (v if v is not None else "") for k, v in row.items() if k}
        lower = {k.lower(): v for k, v in norm.items()}
        test = (lower.get("testresult") or "").strip().lower()
        sev_label = (lower.get("severity") or "").strip().lower()
        if not include_passed and (test == "passed" or sev_label == "passed"):
            continue
        fid = str(lower.get("id") or "").strip()
        name = str(lower.get("name") or "").strip() or f"HardeningKitty {fid}"
        category = str(lower.get("category") or "").strip()
        result = str(lower.get("result") or "").strip()
        recommended = str(lower.get("recommended") or "").strip()
        severity = _sev_map({**norm, **{k.title(): v for k, v in lower.items()}})
        title = f"[HK {fid}] {name}" if fid else name
        notes = (
            f"hardeningkitty_id={fid}\n"
            f"category={category}\n"
            f"result={result}\n"
            f"recommended={recommended}\n"
            f"test_result={lower.get('testresult') or ''}\n"
            f"source={filename or 'hardeningkitty'}"
        )
        # asset_name must match create_vulnerability(); category is CIS area, not host.
        try:
            import socket

            host_label = socket.gethostname() or "Windows host"
        except Exception:
            host_label = "Windows host"
        items.append(
            {
                "title": title[:400],
                "severity": severity,
                "asset_name": host_label[:200],
                "cve": "",
                "cvss": None,
                "status": "open",
                "owner": "HardeningKitty",
                "notes": notes[:2000],
                "engagement_id": engagement_id,
                "scanner": "hardeningkitty",
                "source": f"hardeningkitty:{filename or 'report'}",
                "raw": {**lower, "category": category, "host": host_label},
            }
        )
    return items


def summarize_report(text: str) -> dict[str, Any]:
    reader = csv.DictReader(io.StringIO(text))
    counts = {"passed": 0, "failed": 0, "high": 0, "medium": 0, "low": 0, "total": 0}
    for row in reader:
        counts["total"] += 1
        lower = {str(k).lower(): (v or "") for k, v in row.items() if k}
        test = str(lower.get("testresult") or "").lower()
        sev = str(lower.get("severity") or "").lower()
        finding = str(lower.get("severityfinding") or sev).lower()
        if test == "passed" or sev == "passed":
            counts["passed"] += 1
        else:
            counts["failed"] += 1
            if finding in counts:
                counts[finding] += 1
    total = max(1, counts["total"])
    # HardeningKitty score formula (approx): (points/max)*5+1
    points = counts["passed"] * 4 + counts["low"] * 2 + counts["medium"]
    max_pts = total * 4
    score = round((points / max_pts) * 5 + 1, 2) if max_pts else 0
    return {"counts": counts, "score_estimate": score}


def ensure_schema() -> None:
    c = get_conn()
    c.execute(
        """
        CREATE TABLE IF NOT EXISTS hardeningkitty_runs (
            id TEXT PRIMARY KEY,
            mode TEXT NOT NULL DEFAULT 'Audit',
            list_name TEXT NOT NULL DEFAULT '',
            report_path TEXT NOT NULL DEFAULT '',
            score REAL,
            passed INTEGER NOT NULL DEFAULT 0,
            failed INTEGER NOT NULL DEFAULT 0,
            imported INTEGER NOT NULL DEFAULT 0,
            status TEXT NOT NULL DEFAULT 'done',
            error TEXT NOT NULL DEFAULT '',
            created_at REAL NOT NULL
        )
        """
    )
    c.commit()


def record_run(meta: dict[str, Any]) -> dict[str, Any]:
    ensure_schema()
    rid = new_id()
    ts = now()
    get_conn().execute(
        """
        INSERT INTO hardeningkitty_runs
        (id, mode, list_name, report_path, score, passed, failed, imported, status, error, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            rid,
            meta.get("mode") or "Audit",
            meta.get("list_name") or "",
            meta.get("report_path") or "",
            meta.get("score"),
            int(meta.get("passed") or 0),
            int(meta.get("failed") or 0),
            int(meta.get("imported") or 0),
            meta.get("status") or "done",
            (meta.get("error") or "")[:500],
            ts,
        ),
    )
    get_conn().commit()
    return {"id": rid, **meta, "created_at": ts}


def recent_runs(limit: int = 10) -> list[dict[str, Any]]:
    ensure_schema()
    rows = get_conn().execute(
        "SELECT * FROM hardeningkitty_runs ORDER BY created_at DESC LIMIT ?",
        (max(1, min(50, int(limit))),),
    ).fetchall()
    return [dict(r) for r in rows]


async def run_audit(
    *,
    mode: str = "Audit",
    finding_list: str | None = None,
    import_findings: bool = True,
    user_id: str = "local",
) -> dict[str, Any]:
    """Run HardeningKitty Audit/Config on this host (Windows + PowerShell)."""
    mode_norm = (mode or "Audit").strip()
    if mode_norm not in {"Audit", "Config"}:
        raise ValueError("Only Audit and Config modes are allowed via SecuraIQ (HailMary/GPO blocked)")
    if platform.system().lower() != "windows":
        raise ValueError("HardeningKitty requires Windows")
    if not is_installed():
        raise ValueError("HardeningKitty module not found — set HARDENINGKITTY_MODULE_PATH")
    root = module_path()
    assert root is not None
    ps = shutil.which("pwsh") or shutil.which("powershell")
    if not ps:
        raise ValueError("PowerShell not found on PATH")

    list_path = (finding_list or getattr(settings, "hardeningkitty_list", "") or "").strip()
    if list_path and not Path(list_path).is_file():
        # allow bare filename from lists/
        candidate = root / "lists" / list_path
        if candidate.is_file():
            list_path = str(candidate)
        else:
            raise ValueError(f"Finding list not found: {list_path}")

    out_dir = Path(settings.data_dir) / "hardeningkitty"
    out_dir.mkdir(parents=True, exist_ok=True)
    stamp = new_id()[:12]
    report = out_dir / f"report_{stamp}.csv"
    log = out_dir / f"log_{stamp}.txt"

    list_arg = f'-FileFindingList "{list_path}"' if list_path else ""
    script = (
        f'Import-Module "{root / "HardeningKitty.psm1"}" -Force; '
        f'Invoke-HardeningKitty -Mode {mode_norm} -Report -Log '
        f'-ReportFile "{report}" -LogFile "{log}" {list_arg}'
    )
    proc = await asyncio.create_subprocess_exec(
        ps,
        "-NoProfile",
        "-ExecutionPolicy",
        "Bypass",
        "-Command",
        script,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    stdout_b, stderr_b = await proc.communicate()
    stdout = (stdout_b or b"").decode("utf-8", errors="replace")
    stderr = (stderr_b or b"").decode("utf-8", errors="replace")
    if proc.returncode not in (0, None) and not report.is_file():
        err = (stderr or stdout or f"exit {proc.returncode}")[:500]
        record_run({"mode": mode_norm, "list_name": list_path, "status": "error", "error": err})
        raise ValueError(f"HardeningKitty failed: {err}")

    summary: dict[str, Any] = {"counts": {}, "score_estimate": None}
    imported = 0
    if report.is_file():
        text = report.read_text(encoding="utf-8", errors="replace")
        summary = summarize_report(text)
        if import_findings and mode_norm == "Audit":
            from app.enterprise import create_vulnerability

            items = parse_report_csv(text, filename=report.name)
            for it in items[:500]:
                create_vulnerability(user_id, it)
                imported += 1
    score_m = re.search(r"HardeningKitty score is:\s*([0-9.]+)", stdout, re.I)
    score = float(score_m.group(1)) if score_m else summary.get("score_estimate")
    counts = summary.get("counts") or {}
    meta = {
        "mode": mode_norm,
        "list_name": list_path or "(default)",
        "report_path": str(report) if report.is_file() else "",
        "score": score,
        "passed": int(counts.get("passed") or 0),
        "failed": int(counts.get("failed") or 0),
        "imported": imported,
        "status": "done",
        "stdout_tail": stdout[-800:],
    }
    record_run(meta)
    return meta
