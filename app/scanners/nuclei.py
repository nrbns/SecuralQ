"""Nuclei scanner adapter — template-based web / vuln checks (second engine scanner).

Requires `nuclei` on PATH. Writes JSONL evidence; normalizes to SecuraIQ findings.
Only runs against authorized, in-scope targets (scope enforced by scan engine).
"""

from __future__ import annotations

import asyncio
import json
import re
import shutil
from typing import Any
from urllib.parse import urlparse

from app.scanners.base import (
    NormalizedFinding,
    NormalizedScan,
    NormalizedService,
    RawScanResult,
    ScanContext,
    Scanner,
)
from app.scanners.constants import HOST_OR_IP
from app.services.tool_policy import target_in_scope

_CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)

# Profile → nuclei CLI args (after binary + -u URL)
_PROFILE_ARGS: dict[str, list[str]] = {
    "discovery": [
        "-tags",
        "tech,tech-detect,exposure,misconfig",
        "-severity",
        "info,low,medium,high,critical",
    ],
    "web": [
        "-severity",
        "critical,high,medium",
        "-tags",
        "cve,xss,sqli,ssrf,misconfig,exposure,rce",
    ],
    "vulnerability": [
        "-severity",
        "critical,high,medium,low",
    ],
    "full": [
        "-severity",
        "critical,high,medium,low,info",
    ],
}

_TIMEOUT = {
    "discovery": 120.0,
    "web": 180.0,
    "vulnerability": 300.0,
    "full": 420.0,
}


def _hostname_from_target(target: str) -> str:
    t = (target or "").strip()
    if not t:
        return ""
    if "://" in t:
        try:
            return (urlparse(t).hostname or "").lower().rstrip(".")
        except Exception:
            return ""
    return re.sub(r"^https?://", "", t, flags=re.I).split("/")[0].split(":")[0].lower().rstrip(".")


def to_nuclei_url(target: str) -> str:
    """Normalize host/IP/URL into a URL Nuclei can scan."""
    t = (target or "").strip()
    if not t:
        return ""
    if re.match(r"^https?://", t, re.I):
        return t.rstrip("/")
    host = t.split("/")[0]
    # Prefer https for hostnames; http for bare RFC1918 IPs is fine either way
    return f"https://{host}"


def parse_nuclei_jsonl(text: str) -> list[dict[str, Any]]:
    """Parse Nuclei -jsonl / -json-export lines into intermediate finding dicts."""
    findings: list[dict[str, Any]] = []
    for line in (text or "").splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            row = json.loads(line)
        except Exception:
            continue
        if not isinstance(row, dict):
            continue
        info = row.get("info") if isinstance(row.get("info"), dict) else {}
        sev = str(info.get("severity") or row.get("severity") or "medium").lower()
        title = (
            info.get("name")
            or row.get("template-id")
            or row.get("template_id")
            or "Nuclei finding"
        )
        cve = ""
        classification = info.get("classification")
        if isinstance(classification, dict):
            cves = classification.get("cve-id") or classification.get("cve_id") or []
            if isinstance(cves, list) and cves:
                cve = str(cves[0]).upper()
            elif isinstance(cves, str) and cves.upper().startswith("CVE-"):
                cve = cves.upper()
        if not cve:
            for m in _CVE_RE.finditer(json.dumps(row)[:2000]):
                cve = m.group(0).upper()
                break
        matched = row.get("matched-at") or row.get("host") or row.get("ip") or ""
        findings.append(
            {
                "title": str(title)[:300],
                "severity": sev if sev in {"critical", "high", "medium", "low", "info"} else "medium",
                "cve": cve[:40],
                "asset_name": str(matched)[:200],
                "template_id": str(row.get("template-id") or row.get("template_id") or ""),
                "raw": row,
            }
        )
    return findings[:120]


class NucleiScanner(Scanner):
    id = "nuclei"
    name = "Nuclei"
    profiles = ("discovery", "web", "vulnerability", "full")

    def available(self) -> tuple[bool, str]:
        path = shutil.which("nuclei")
        if path:
            return True, path
        return False, "nuclei not found on PATH — install ProjectDiscovery Nuclei for web vuln templates"

    def validate_target(self, target: str) -> tuple[bool, str]:
        t = (target or "").strip()
        if not t:
            return False, "target required"
        if any(c in t for c in ";&|`$()<>"):
            return False, "invalid target characters"
        host = _hostname_from_target(t)
        if not host or not HOST_OR_IP.match(host):
            return False, "target must be hostname, IPv4, or http(s) URL"
        return True, to_nuclei_url(t)

    def validate_scope(self, target: str, scope: list[str]) -> tuple[bool, str]:
        host = _hostname_from_target(target)
        ok, reason = target_in_scope(target=host or target, ip=None, scope=scope)
        if ok:
            return True, reason
        return False, f"target out of engagement scope ({reason})"

    def build_command(self, ctx: ScanContext) -> list[str]:
        ok, detail = self.available()
        if not ok:
            raise RuntimeError(detail)
        binary = detail
        ok_t, url = self.validate_target(ctx.target)
        if not ok_t:
            raise ValueError(url)
        profile = (ctx.profile or "web").lower()
        if profile not in _PROFILE_ARGS:
            profile = "web"
        out_path = ctx.evidence_dir / "nuclei.jsonl"
        args = [
            binary,
            "-u",
            url,
            "-jsonl",
            "-silent",
            "-no-color",
            "-timeout",
            "8",
            "-rate-limit",
            "50",
            "-o",
            str(out_path),
            *_PROFILE_ARGS[profile],
        ]
        return args

    async def execute(self, ctx: ScanContext) -> RawScanResult:
        ctx.evidence_dir.mkdir(parents=True, exist_ok=True)
        argv = self.build_command(ctx)
        profile = (ctx.profile or "web").lower()
        timeout = _TIMEOUT.get(profile, 180.0)
        out_path = ctx.evidence_dir / "nuclei.jsonl"

        proc = await asyncio.create_subprocess_exec(
            *argv,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout_b, stderr_b = await asyncio.wait_for(proc.communicate(), timeout=timeout)
            code = int(proc.returncode or 0)
        except asyncio.TimeoutError:
            try:
                proc.kill()
            except Exception:
                pass
            stdout_b, stderr_b = b"", b"nuclei timed out"
            code = -1

        stdout = (stdout_b or b"").decode("utf-8", errors="replace")
        stderr = (stderr_b or b"").decode("utf-8", errors="replace")
        # Nuclei often writes only to -o; also capture stdout if present
        if stdout.strip() and (not out_path.exists() or out_path.stat().st_size == 0):
            out_path.write_text(stdout, encoding="utf-8")
        elif stdout.strip() and out_path.exists():
            # Append any stdout lines not already in file (some versions dual-write)
            existing = out_path.read_text(encoding="utf-8", errors="replace")
            if stdout.strip() not in existing:
                out_path.write_text(existing + ("\n" if existing and not existing.endswith("\n") else "") + stdout, encoding="utf-8")

        (ctx.evidence_dir / "stdout.log").write_text(stdout, encoding="utf-8")
        (ctx.evidence_dir / "stderr.log").write_text(stderr, encoding="utf-8")
        (ctx.evidence_dir / "command.txt").write_text(" ".join(argv), encoding="utf-8")

        artifacts = [
            str(ctx.evidence_dir / "command.txt"),
            str(ctx.evidence_dir / "stdout.log"),
            str(ctx.evidence_dir / "stderr.log"),
        ]
        if out_path.exists():
            artifacts.insert(0, str(out_path))

        return RawScanResult(
            exit_code=code,
            stdout=stdout,
            stderr=stderr,
            artifact_paths=artifacts,
            meta={"argv": argv, "timeout": timeout, "url": argv[2] if len(argv) > 2 else ""},
        )

    def parse(self, raw: RawScanResult, ctx: ScanContext) -> list[dict[str, Any]]:
        out_path = ctx.evidence_dir / "nuclei.jsonl"
        text = ""
        if out_path.exists():
            text = out_path.read_text(encoding="utf-8", errors="replace")
        if not text.strip():
            text = raw.stdout or ""
        return parse_nuclei_jsonl(text)

    def normalize(self, parsed: Any, ctx: ScanContext) -> NormalizedScan:
        rows = parsed if isinstance(parsed, list) else []
        ok_t, url = self.validate_target(ctx.target)
        host = _hostname_from_target(url if ok_t else ctx.target) or (ctx.target or "unknown")

        findings: list[NormalizedFinding] = []
        services: list[NormalizedService] = []
        seen_ports: set[int] = set()

        for row in rows:
            if not isinstance(row, dict):
                continue
            asset = row.get("asset_name") or host
            # Prefer hostname for asset inventory
            asset_host = _hostname_from_target(str(asset)) or host
            findings.append(
                NormalizedFinding(
                    title=str(row.get("title") or "Nuclei finding")[:300],
                    severity=str(row.get("severity") or "medium"),
                    asset_name=asset_host[:200],
                    cve=(row.get("cve") or None) or None,
                    source=f"nuclei:{row.get('template_id') or 'scan'}",
                    evidence=str(asset)[:500],
                    raw=row.get("raw") if isinstance(row.get("raw"), dict) else row,
                )
            )
            # Infer http(s) service from matched URL
            matched = str(asset)
            if matched.startswith("https://") and 443 not in seen_ports:
                seen_ports.add(443)
                services.append(NormalizedService(port=443, protocol="tcp", state="open", service="https"))
            elif matched.startswith("http://") and 80 not in seen_ports:
                seen_ports.add(80)
                services.append(NormalizedService(port=80, protocol="tcp", state="open", service="http"))

        if findings and not any(f.severity == "info" and "Open ports" in f.title for f in findings):
            # Inventory note when templates hit
            findings.insert(
                0,
                NormalizedFinding(
                    title=f"Nuclei reported {len(rows)} template match(es) on {host}",
                    severity="info",
                    asset_name=host,
                    source="nuclei:summary",
                    evidence=f"profile={ctx.profile} url={url if ok_t else ctx.target}",
                    raw={"count": len(rows)},
                ),
            )

        return NormalizedScan(
            asset_name=host,
            asset_type="url" if "://" in (ctx.target or "") else "host",
            services=services,
            findings=findings,
            technologies=[],
            summary={
                "open_ports": len(services),
                "findings": len(findings),
                "template_matches": len(rows),
                "scanner": "nuclei",
                "profile": ctx.profile,
                "url": url if ok_t else ctx.target,
            },
        )
