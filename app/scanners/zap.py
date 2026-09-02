"""SecuraIQ Web Scanner — built-in DAST (no install required).

Primary engine: pure-Python HTTP assessment (``app.scanners.web_builtin``).
Optional enhancement when ``ZAP_PREFER_API=true`` and a ZAP daemon is reachable.
"""

from __future__ import annotations

import asyncio
import json
import re
import shutil
from typing import Any

from app.scanners.base import (
    NormalizedFinding,
    NormalizedScan,
    NormalizedService,
    RawScanResult,
    ScanContext,
    Scanner,
)
from app.scanners.constants import HOST_OR_IP, internal_target_reason
from app.scanners.nuclei import _hostname_from_target, to_nuclei_url
from app.services.tool_policy import target_in_scope

_TIMEOUT = {
    "discovery": 90.0,
    "web": 180.0,
    "vulnerability": 240.0,
    "full": 360.0,
}


def _sev_from_zap_risk(riskcode: str | int | None, riskdesc: str = "") -> str:
    try:
        code = int(riskcode) if riskcode is not None and str(riskcode).strip() != "" else -1
    except (TypeError, ValueError):
        code = -1
    if code >= 3 or "high" in (riskdesc or "").lower():
        return "high"
    if code == 2 or "medium" in (riskdesc or "").lower():
        return "medium"
    if code == 1 or "low" in (riskdesc or "").lower():
        return "low"
    return "info"


def parse_zap_json(data: dict[str, Any]) -> list[dict[str, Any]]:
    """Parse ZAP / SecuraIQ web JSON report (site[].alerts[]) into intermediate rows."""
    items: list[dict[str, Any]] = []
    for site in data.get("site") or []:
        if not isinstance(site, dict):
            continue
        host = site.get("@name") or site.get("name") or site.get("@host") or "web-app"
        for alert in site.get("alerts") or []:
            if not isinstance(alert, dict):
                continue
            name = alert.get("name") or alert.get("alert") or "Web finding"
            plugin = alert.get("pluginid") or alert.get("pluginId") or ""
            items.append(
                {
                    "title": str(name)[:300],
                    "severity": _sev_from_zap_risk(alert.get("riskcode"), str(alert.get("riskdesc") or "")),
                    "asset_name": str(host)[:200],
                    "plugin": str(plugin),
                    "raw": {
                        k: v
                        for k, v in alert.items()
                        if k != "instances"
                    }
                    | {"instances_count": len(alert.get("instances") or [])},
                }
            )
    return items[:150]


def parse_zap_baseline_text(text: str, *, asset: str) -> list[dict[str, Any]]:
    """Best-effort parse of zap-baseline.py console lines (WARN-/FAIL- style)."""
    items: list[dict[str, Any]] = []
    for line in (text or "").splitlines():
        line = line.strip()
        m = re.match(r"^(WARN|FAIL|INFO)-(\w+)\s+(.*)$", line, re.I)
        if not m:
            continue
        level, code, rest = m.group(1).upper(), m.group(2), m.group(3).strip()
        sev = {"FAIL": "high", "WARN": "medium", "INFO": "info"}.get(level, "info")
        items.append(
            {
                "title": (rest or code)[:300],
                "severity": sev,
                "asset_name": asset[:200],
                "plugin": code,
                "raw": {"line": line, "level": level},
            }
        )
    return items[:80]


def _resolve_zap_binary() -> tuple[str | None, str]:
    baseline = shutil.which("zap-baseline.py") or shutil.which("zap-baseline")
    if baseline:
        return baseline, "baseline"
    for name in ("zap.sh", "zap", "zaproxy"):
        path = shutil.which(name)
        if path:
            return path, "zap"
    return None, ""


async def _probe_zap_api_sync() -> tuple[bool, str]:
    try:
        from app.scanners.zap_api import probe_zap_api

        return await probe_zap_api()
    except Exception as exc:
        return False, str(exc)


class ZapScanner(Scanner):
    id = "zap"
    name = "SecuraIQ Web Scanner"
    profiles = ("discovery", "web", "vulnerability", "full")

    def available(self) -> tuple[bool, str]:
        return True, "built-in SecuraIQ Web Scanner — no ZAP daemon or install required"

    def validate_target(self, target: str) -> tuple[bool, str]:
        t = (target or "").strip()
        if not t:
            return False, "target required"
        if any(c in t for c in ";&|`$()<>"):
            return False, "invalid target characters"
        host = _hostname_from_target(t)
        if not host or not HOST_OR_IP.match(host):
            return False, "target must be hostname, IPv4, or http(s) URL"
        # The Web Scanner is scoped to public-facing web apps — internal
        # hosts (loopback, RFC1918/private IPs, link-local, .local/.internal
        # names) belong to the network/VAPT scanner instead, and allowing
        # them here would let this tool be pointed at internal services
        # (SSRF) rather than the public web it's meant to assess.
        blocked = internal_target_reason(host)
        if blocked:
            return (
                False,
                f"Web Scanner targets public web apps only ({blocked}). "
                "Use a network/VAPT scan for internal hosts.",
            )
        return True, to_nuclei_url(t)

    def validate_scope(self, target: str, scope: list[str]) -> tuple[bool, str]:
        host = _hostname_from_target(target)
        ok, reason = target_in_scope(target=host or target, ip=None, scope=scope)
        if ok:
            return True, reason
        return False, f"target out of engagement scope ({reason})"

    def build_command(self, ctx: ScanContext) -> list[str]:
        ok_t, url = self.validate_target(ctx.target)
        if not ok_t:
            raise ValueError(url)
        profile = (ctx.profile or "web").lower()
        return [
            "securaiq-web-scanner",
            "--target",
            url,
            "--profile",
            profile,
            "--builtin",
        ]

    async def execute(self, ctx: ScanContext) -> RawScanResult:
        ctx.evidence_dir.mkdir(parents=True, exist_ok=True)
        ok_t, url = self.validate_target(ctx.target)
        if not ok_t:
            raise ValueError(url)
        profile = (ctx.profile or "web").lower()
        timeout = _TIMEOUT.get(profile, 180.0)

        from app.config import settings
        from app.scanners.web_builtin import run_builtin_web_scan

        out = await run_builtin_web_scan(
            target_url=url,
            profile=profile,
            evidence_dir=ctx.evidence_dir,
            scan_id=ctx.scan_id,
            timeout_sec=timeout,
        )
        mode = "securaiq_web_builtin"
        cmd = f"SecuraIQ Web Scanner (built-in) profile={profile} target={url}"

        # Optional deep scan when external ZAP daemon is configured and reachable.
        if bool(getattr(settings, "zap_prefer_api", False)):
            api_ok, api_detail = await _probe_zap_api_sync()
            if api_ok:
                from app.scanners.zap_api import resolve_zap_api_settings, run_zap_api_assessment

                base, key = resolve_zap_api_settings()
                try:
                    ext = await run_zap_api_assessment(
                        target_url=url,
                        profile=profile,
                        evidence_dir=ctx.evidence_dir,
                        base_url=base,
                        api_key=key,
                        timeout_sec=timeout,
                        scan_id=ctx.scan_id,
                    )
                    mode = "securaiq_web_builtin+zap_api"
                    cmd = f"{cmd} + ZAP REST {base}"
                    out = {**out, "zap_api": ext, "zap_api_detail": api_detail}
                except Exception as exc:
                    (ctx.evidence_dir / "zap_api.stderr").write_text(str(exc), encoding="utf-8")

        (ctx.evidence_dir / "command.txt").write_text(cmd, encoding="utf-8")
        (ctx.evidence_dir / "stdout.log").write_text(json.dumps(out, indent=2), encoding="utf-8")
        (ctx.evidence_dir / "stderr.log").write_text("", encoding="utf-8")
        artifacts = list(out.get("artifacts") or [])
        artifacts.extend(
            [
                str(ctx.evidence_dir / "command.txt"),
                str(ctx.evidence_dir / "stdout.log"),
                str(ctx.evidence_dir / "stderr.log"),
            ]
        )
        return RawScanResult(
            exit_code=0,
            stdout=(ctx.evidence_dir / "stdout.log").read_text(encoding="utf-8"),
            stderr="",
            artifact_paths=artifacts,
            meta={"mode": mode, "timeout": timeout, "builtin": True},
        )

    def parse(self, raw: RawScanResult, ctx: ScanContext) -> list[dict[str, Any]]:
        json_path = ctx.evidence_dir / "zap.json"
        if json_path.exists() and json_path.stat().st_size > 0:
            try:
                data = json.loads(json_path.read_text(encoding="utf-8", errors="replace"))
                if isinstance(data, dict):
                    return parse_zap_json(data)
            except Exception:
                pass
        text = (raw.stdout or "").strip()
        if text.startswith("{"):
            try:
                data = json.loads(text)
                if isinstance(data, dict) and ("site" in data or "@version" in data):
                    return parse_zap_json(data)
            except Exception:
                pass
        ok_t, url = self.validate_target(ctx.target)
        host = _hostname_from_target(url if ok_t else ctx.target) or ctx.target
        return parse_zap_baseline_text(raw.stdout or "", asset=str(host))

    def normalize(self, parsed: Any, ctx: ScanContext) -> NormalizedScan:
        rows = parsed if isinstance(parsed, list) else []
        ok_t, url = self.validate_target(ctx.target)
        host = _hostname_from_target(url if ok_t else ctx.target) or (ctx.target or "unknown")

        findings: list[NormalizedFinding] = []
        for row in rows:
            if not isinstance(row, dict):
                continue
            asset = _hostname_from_target(str(row.get("asset_name") or "")) or host
            findings.append(
                NormalizedFinding(
                    title=str(row.get("title") or "Web finding")[:300],
                    severity=str(row.get("severity") or "info"),
                    asset_name=asset[:200],
                    source=f"securaiq_web:{row.get('plugin') or 'scan'}",
                    evidence=str(row.get("asset_name") or url if ok_t else ctx.target)[:500],
                    raw=row.get("raw") if isinstance(row.get("raw"), dict) else row,
                )
            )

        if findings:
            findings.insert(
                0,
                NormalizedFinding(
                    title=f"SecuraIQ Web Scanner found {len(rows)} issue(s) on {host}",
                    severity="info",
                    asset_name=host,
                    source="securaiq_web:summary",
                    evidence=f"profile={ctx.profile}",
                    raw={"count": len(rows)},
                ),
            )

        services: list[NormalizedService] = []
        if ok_t and url.startswith("https://"):
            services.append(NormalizedService(port=443, protocol="tcp", state="open", service="https"))
        elif ok_t:
            services.append(NormalizedService(port=80, protocol="tcp", state="open", service="http"))

        return NormalizedScan(
            asset_name=host,
            asset_type="url",
            services=services,
            findings=findings,
            technologies=[],
            summary={
                "open_ports": len(services),
                "findings": len(findings),
                "alerts": len(rows),
                "scanner": "securaiq_web",
                "profile": ctx.profile,
                "url": url if ok_t else ctx.target,
            },
        )
