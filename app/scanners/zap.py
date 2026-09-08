"""SecuraIQ Web Scanner — built-in DAST (no install required).

Primary engine: pure-Python HTTP assessment (``app.scanners.web_builtin``).
Optional enhancement when ``ZAP_PREFER_API=true`` and a ZAP daemon is reachable.
"""

from __future__ import annotations

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


def _web_scan_url(target: str) -> str:
    """Normalize host/IP/CIDR/URL into an http(s) URL for the built-in web scanner.

    Private/lab IPs prefer http (labs rarely terminate TLS on the gateway).
    CIDR like ``192.168.0.1/24`` is reduced to the host portion for web DAST
    (subnet sweeps belong to Discovery / network scanners).
    """
    import ipaddress

    t = (target or "").strip()
    if not t:
        return ""
    if re.match(r"^https?://", t, re.I):
        return t.rstrip("/")
    # Strip CIDR suffix for web single-host scan
    host_part = t.split("/")[0].strip()
    bare = _hostname_from_target(host_part) or host_part.split(":")[0]
    port = ""
    if ":" in host_part and not host_part.startswith("["):
        # host:port (not IPv6)
        bits = host_part.rsplit(":", 1)
        if len(bits) == 2 and bits[1].isdigit():
            bare, port = bits[0], bits[1]
    try:
        ip = ipaddress.ip_address(bare)
        scheme = "http" if (ip.is_private or ip.is_loopback) else "https"
    except ValueError:
        scheme = "https"
    if port:
        return f"{scheme}://{bare}:{port}"
    return f"{scheme}://{bare}"


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


def _report_engine_tag(version: str) -> str:
    """Map report @version to honest engine id (never claim ZAP for builtin)."""
    ver = (version or "").strip().upper()
    if "SECURAIQ" in ver:
        return "securaiq_web"
    if "ZAP-API" in ver or ver.startswith("ZAP"):
        return "zap_api"
    # Classic OWASP ZAP JSON exports use numeric versions like "2.14.0".
    if ver and ver[0].isdigit():
        return "zap_api"
    return "securaiq_web"


def parse_zap_json(data: dict[str, Any]) -> list[dict[str, Any]]:
    """Parse ZAP / SecuraIQ web JSON report (site[].alerts[]) into intermediate rows."""
    items: list[dict[str, Any]] = []
    report_src = str(data.get("@version") or "")
    # Honest source tag: builtin report vs optional ZAP API / classic ZAP export.
    default_engine = _report_engine_tag(report_src)
    for site in data.get("site") or []:
        if not isinstance(site, dict):
            continue
        host = site.get("@name") or site.get("name") or site.get("@host") or "web-app"
        for alert in site.get("alerts") or []:
            if not isinstance(alert, dict):
                continue
            name = alert.get("name") or alert.get("alert") or "Web finding"
            plugin = alert.get("pluginid") or alert.get("pluginId") or ""
            instances = alert.get("instances") or []
            uri = ""
            if isinstance(instances, list) and instances:
                first = instances[0] if isinstance(instances[0], dict) else {}
                uri = str(first.get("uri") or first.get("url") or "")[:500]
            evidence_url = uri or str(host)
            engine = str(alert.get("engine") or default_engine)
            items.append(
                {
                    "title": str(name)[:300],
                    "severity": _sev_from_zap_risk(alert.get("riskcode"), str(alert.get("riskdesc") or "")),
                    "asset_name": str(host)[:200],
                    "plugin": str(plugin),
                    "evidence": evidence_url,
                    "engine": engine,
                    "raw": {
                        k: v
                        for k, v in alert.items()
                        if k != "instances"
                    }
                    | {
                        "instances_count": len(instances) if isinstance(instances, list) else 0,
                        "uri": uri,
                        "engine": engine,
                    },
                }
            )
    return items[:150]


def _alert_dedupe_key(alert: dict[str, Any]) -> str:
    name = str(alert.get("name") or alert.get("alert") or "").strip().lower()
    plugin = str(alert.get("pluginid") or alert.get("pluginId") or "").strip()
    instances = alert.get("instances") or []
    uri = ""
    if isinstance(instances, list) and instances and isinstance(instances[0], dict):
        uri = str(instances[0].get("uri") or instances[0].get("url") or "")
    return f"{plugin}|{name}|{uri}"


def merge_web_alert_reports(*reports: dict[str, Any] | None) -> dict[str, Any]:
    """Merge SecuraIQ builtin + optional ZAP API alert reports without inventing rows."""
    merged_alerts: list[dict[str, Any]] = []
    seen: set[str] = set()
    site_name = ""
    versions: list[str] = []
    for report in reports:
        if not isinstance(report, dict):
            continue
        ver = str(report.get("@version") or "").strip()
        if ver:
            versions.append(ver)
        for site in report.get("site") or []:
            if not isinstance(site, dict):
                continue
            if not site_name:
                site_name = str(site.get("@name") or site.get("name") or "")
            engine = _report_engine_tag(ver)
            for alert in site.get("alerts") or []:
                if not isinstance(alert, dict):
                    continue
                row = dict(alert)
                row.setdefault("engine", engine)
                key = _alert_dedupe_key(row)
                if key in seen:
                    continue
                seen.add(key)
                merged_alerts.append(row)
    version = "+".join(dict.fromkeys(versions)) if versions else "SecuraIQ-WebScanner"
    return {
        "@version": version,
        "site": [{"@name": site_name or "web-app", "alerts": merged_alerts}],
    }


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
        # Web DAST needs a single host/URL — accept CIDR by using the host part.
        host = _hostname_from_target(t.split("/")[0] if "/" in t and "://" not in t else t)
        if not host:
            host = _hostname_from_target(t)
        if not host or not HOST_OR_IP.match(host):
            return False, "target must be hostname, IPv4, or http(s) URL"
        # Web path is public/web URLs only — never RFC1918, loopback, or
        # link-local/cloud-metadata. Use Network/Discovery (nmap/combo) for LAN.
        blocked = internal_target_reason(host, allow_lab_private=False)
        if blocked:
            return (
                False,
                f"Web Scanner blocked ({blocked}). "
                "Use a public http(s) URL only. For private/LAN hosts use Network "
                "(Discovery) scan — not Web.",
            )
        return True, _web_scan_url(t)

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

        builtin_report: dict[str, Any] | None = None
        zap_path = ctx.evidence_dir / "zap.json"
        if zap_path.exists():
            try:
                loaded = json.loads(zap_path.read_text(encoding="utf-8"))
                if isinstance(loaded, dict):
                    builtin_report = loaded
            except Exception:
                builtin_report = None

        # Optional deep scan ONLY when ZAP_PREFER_API=true and daemon is up.
        # Otherwise findings stay SecuraIQ Web Scanner — never labeled as ZAP.
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
                    api_report: dict[str, Any] | None = None
                    api_json = ctx.evidence_dir / "zap_api_report.json"
                    if api_json.exists():
                        try:
                            loaded_api = json.loads(api_json.read_text(encoding="utf-8"))
                            if isinstance(loaded_api, dict):
                                api_report = loaded_api
                        except Exception:
                            api_report = None
                    merged = merge_web_alert_reports(builtin_report, api_report)
                    zap_path.write_text(json.dumps(merged, indent=2), encoding="utf-8")
                    out["alerts"] = len((merged.get("site") or [{}])[0].get("alerts") or [])
                except Exception as exc:
                    (ctx.evidence_dir / "zap_api.stderr").write_text(str(exc), encoding="utf-8")
                    # Keep builtin zap.json intact on ZAP failure.
            else:
                (ctx.evidence_dir / "zap_api.skipped").write_text(
                    f"ZAP_PREFER_API set but daemon unreachable: {api_detail}\n"
                    "Using SecuraIQ Web Scanner (built-in) only.\n",
                    encoding="utf-8",
                )

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
            meta={"mode": mode, "timeout": timeout, "builtin": True, "scanner": "securaiq_web"},
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
            engine = str(row.get("engine") or "securaiq_web")
            plugin = row.get("plugin") or "scan"
            source_prefix = "zap_api" if engine == "zap_api" else "securaiq_web"
            evidence = str(row.get("evidence") or row.get("asset_name") or (url if ok_t else ctx.target))[:500]
            findings.append(
                NormalizedFinding(
                    title=str(row.get("title") or "Web finding")[:300],
                    severity=str(row.get("severity") or "info"),
                    asset_name=asset[:200],
                    source=f"{source_prefix}:{plugin}",
                    evidence=evidence,
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
