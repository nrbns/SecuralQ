"""Nmap scanner adapter — primary SecuraIQ discovery engine.

Produces XML evidence (-oX), parses ports/services, normalizes to assets + findings.
Does not invent CVEs; open ports become inventory + risk-flagged findings for known risky services.
"""

from __future__ import annotations

import asyncio
import re
import shutil
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any

from app.scanners.base import (
    NormalizedFinding,
    NormalizedScan,
    NormalizedService,
    RawScanResult,
    ScanContext,
    Scanner,
)
from app.exposure import WINDOWS_LAN_PORTS, network_scope, severity_for_risky_port
from app.scanners.constants import HOST_OR_IP as _HOST_OR_IP
from app.scanners.constants import RISKY_PORTS as _RISKY
from app.services.tool_policy import target_in_scope

_PROFILE_ARGS: dict[str, list[str]] = {
    "discovery": ["-Pn", "-sT", "--top-ports", "100", "-T4", "--open"],
    "web": ["-Pn", "-sT", "-sV", "-p", "80,443,8080,8443,8000,3000", "-T4", "--open"],
    "vulnerability": ["-Pn", "-sT", "-sV", "-sC", "--top-ports", "200", "-T4", "--open"],
    "full": ["-Pn", "-sT", "-sV", "-sC", "--top-ports", "1000", "-T4", "--open"],
}


class NmapScanner(Scanner):
    id = "nmap"
    name = "Nmap"
    profiles = ("discovery", "web", "vulnerability", "full")

    def available(self) -> tuple[bool, str]:
        path = shutil.which("nmap")
        if not path:
            # Windows installer often lands here even when PATH is stale in the service process.
            for candidate in (
                r"C:\Program Files (x86)\Nmap\nmap.exe",
                r"C:\Program Files\Nmap\nmap.exe",
                "/usr/bin/nmap",
                "/usr/local/bin/nmap",
            ):
                if Path(candidate).is_file():
                    path = candidate
                    break
        if not path:
            return False, "nmap not found on PATH — install Nmap to run live scans"
        # Probe startup: missing Npcap on Windows yields STATUS_DLL_NOT_FOUND (0xC0000135).
        try:
            import subprocess

            probe = subprocess.run(
                [path, "--version"],
                capture_output=True,
                timeout=10,
                text=True,
                errors="replace",
            )
            code = int(probe.returncode or 0)
            if code in (0xC0000135, 3221225781, -1073741515):
                return (
                    False,
                    "nmap installed but cannot start — install Npcap (https://npcap.com) then restart SecuraIQ",
                )
            if code != 0 and not (probe.stdout or "").strip():
                return False, f"nmap probe failed (exit {code}) — check Npcap / permissions"
        except Exception as exc:
            return False, f"nmap probe failed: {exc}"
        return True, path

    def validate_target(self, target: str) -> tuple[bool, str]:
        t = (target or "").strip()
        if not t:
            return False, "target required"
        if t.startswith("-") or any(c in t for c in ";&|`$()<>"):
            return False, "invalid target characters"
        # Strip URL scheme if pasted
        t2 = re.sub(r"^https?://", "", t, flags=re.I).split("/")[0].split(":")[0]
        if not _HOST_OR_IP.match(t2):
            return False, "target must be hostname or IPv4"
        return True, t2

    def validate_scope(self, target: str, scope: list[str]) -> tuple[bool, str]:
        ok, reason = target_in_scope(target=target, ip=None, scope=scope)
        if ok:
            return True, reason
        return False, f"target out of engagement scope ({reason})"

    def build_command(self, ctx: ScanContext) -> list[str]:
        ok, detail = self.available()
        if not ok:
            raise RuntimeError(detail)
        binary = detail
        ok_t, target = self.validate_target(ctx.target)
        if not ok_t:
            raise ValueError(target)
        profile = (ctx.profile or "discovery").lower()
        if profile not in _PROFILE_ARGS:
            profile = "discovery"
        xml_path = ctx.evidence_dir / "nmap.xml"
        args = [binary, *_PROFILE_ARGS[profile], "-oX", str(xml_path), target]
        # Soft host timeout scaled by profile
        timeout_map = {"discovery": "60s", "web": "90s", "vulnerability": "180s", "full": "300s"}
        args.extend(["--host-timeout", timeout_map.get(profile, "60s")])
        return args

    async def execute(self, ctx: ScanContext) -> RawScanResult:
        ctx.evidence_dir.mkdir(parents=True, exist_ok=True)
        argv = self.build_command(ctx)
        timeout = {"discovery": 90.0, "web": 120.0, "vulnerability": 240.0, "full": 420.0}.get(
            (ctx.profile or "discovery").lower(), 90.0
        )
        proc = await asyncio.create_subprocess_exec(
            *argv,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout_b, stderr_b = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        except asyncio.TimeoutError:
            try:
                proc.kill()
            except Exception:
                pass
            stdout_b, stderr_b = b"", b"nmap timed out"
            code = -1
        else:
            code = int(proc.returncode or 0)

        stdout = (stdout_b or b"").decode("utf-8", errors="replace")
        stderr = (stderr_b or b"").decode("utf-8", errors="replace")
        if code in (0xC0000135, 3221225781, -1073741515):
            stderr = (
                (stderr + "\n" if stderr else "")
                + "nmap failed to start (STATUS_DLL_NOT_FOUND). Install Npcap from https://npcap.com "
                "and restart SecuraIQ."
            ).strip()
        (ctx.evidence_dir / "stdout.log").write_text(stdout, encoding="utf-8")
        (ctx.evidence_dir / "stderr.log").write_text(stderr, encoding="utf-8")
        (ctx.evidence_dir / "command.txt").write_text(" ".join(argv), encoding="utf-8")

        artifacts = []
        xml_path = ctx.evidence_dir / "nmap.xml"
        if xml_path.exists():
            artifacts.append(str(xml_path))
        artifacts.extend(
            [
                str(ctx.evidence_dir / "stdout.log"),
                str(ctx.evidence_dir / "stderr.log"),
                str(ctx.evidence_dir / "command.txt"),
            ]
        )
        return RawScanResult(
            exit_code=code,
            stdout=stdout,
            stderr=stderr,
            artifact_paths=artifacts,
            meta={"argv": argv, "timeout": timeout},
        )

    def parse(self, raw: RawScanResult, ctx: ScanContext) -> dict[str, Any]:
        xml_path = ctx.evidence_dir / "nmap.xml"
        if xml_path.exists() and xml_path.stat().st_size > 0:
            return parse_nmap_xml(xml_path.read_text(encoding="utf-8", errors="replace"))
        # Fallback: parse text table from stdout
        return parse_nmap_text(raw.stdout or "")

    def normalize(self, parsed: Any, ctx: ScanContext) -> NormalizedScan:
        data = parsed if isinstance(parsed, dict) else {}
        ok_t, target = self.validate_target(ctx.target)
        asset_name = target if ok_t else (ctx.target or "unknown").strip()
        host = (data.get("hostname") or data.get("address") or asset_name).strip() or asset_name

        services: list[NormalizedService] = []
        for p in data.get("ports") or []:
            if not isinstance(p, dict):
                continue
            try:
                port = int(p.get("port") or 0)
            except (TypeError, ValueError):
                continue
            if port <= 0:
                continue
            services.append(
                NormalizedService(
                    port=port,
                    protocol=str(p.get("protocol") or "tcp"),
                    state=str(p.get("state") or "open"),
                    service=str(p.get("service") or ""),
                    product=str(p.get("product") or ""),
                    version=str(p.get("version") or ""),
                )
            )

        technologies: list[str] = []
        for s in services:
            label = " ".join(x for x in (s.product, s.version, s.service) if x).strip()
            if label and label not in technologies:
                technologies.append(label)

        findings: list[NormalizedFinding] = []
        # Inventory finding summarizing open ports
        if services:
            port_list = ", ".join(f"{s.port}/{s.protocol} {s.service or s.state}".strip() for s in services[:40])
            findings.append(
                NormalizedFinding(
                    title=f"Open ports discovered on {host}",
                    severity="info",
                    asset_name=host,
                    source="nmap:discovery",
                    evidence=port_list,
                    raw={"ports": [s.__dict__ for s in services]},
                )
            )
        for s in services:
            if s.state != "open":
                continue
            risky = _RISKY.get(s.port)
            if not risky:
                continue
            _svc, _default_sev, msg = risky
            scope = network_scope(host)
            sev = severity_for_risky_port(s.port, scope)
            if scope == "private" and s.port in WINDOWS_LAN_PORTS:
                title = f"Windows LAN service on port {s.port}/tcp (private/lab)"
            else:
                title = f"{msg} ({s.port}/{s.protocol}"
                if s.service:
                    title += f" {s.service}"
                title += ")"
            findings.append(
                NormalizedFinding(
                    title=title[:300],
                    severity=sev,
                    asset_name=host,
                    source=f"nmap:port-{s.port}",
                    evidence=f"{s.port}/{s.protocol} open {s.service} {s.product} {s.version}".strip(),
                    raw={
                        "port": s.port,
                        "service": s.service,
                        "product": s.product,
                        "version": s.version,
                        "scope": scope,
                    },
                )
            )

        return NormalizedScan(
            asset_name=host,
            asset_type="host",
            services=services,
            findings=findings,
            technologies=technologies,
            summary={
                "open_ports": len([s for s in services if s.state == "open"]),
                "findings": len(findings),
                "technologies": len(technologies),
                "scanner": "nmap",
                "profile": ctx.profile,
            },
        )


def parse_nmap_xml(xml_text: str) -> dict[str, Any]:
    """Parse Nmap XML (-oX) into a simple dict. Safe on truncated/partial XML."""
    out: dict[str, Any] = {"ports": [], "address": "", "hostname": ""}
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return out
    host = root.find("host")
    if host is None:
        # Sometimes multiple hosts; take first with ports
        for h in root.findall("host"):
            if h.find("ports") is not None:
                host = h
                break
    if host is None:
        return out
    addr = host.find("address")
    if addr is not None:
        out["address"] = addr.get("addr") or ""
    hostnames = host.find("hostnames")
    if hostnames is not None:
        hn = hostnames.find("hostname")
        if hn is not None:
            out["hostname"] = hn.get("name") or ""
    ports_el = host.find("ports")
    if ports_el is None:
        return out
    for port_el in ports_el.findall("port"):
        state_el = port_el.find("state")
        state = (state_el.get("state") if state_el is not None else "") or ""
        if state and state != "open":
            continue
        svc_el = port_el.find("service")
        try:
            portnum = int(port_el.get("portid") or 0)
        except ValueError:
            continue
        out["ports"].append(
            {
                "port": portnum,
                "protocol": port_el.get("protocol") or "tcp",
                "state": state or "open",
                "service": (svc_el.get("name") if svc_el is not None else "") or "",
                "product": (svc_el.get("product") if svc_el is not None else "") or "",
                "version": (svc_el.get("version") if svc_el is not None else "") or "",
            }
        )
    return out


def parse_nmap_text(text: str) -> dict[str, Any]:
    """Fallback parser for classic nmap text tables."""
    ports: list[dict[str, Any]] = []
    for line in (text or "").splitlines():
        m = re.match(
            r"^(\d+)/(tcp|udp)\s+(open|filtered|closed)\s+(\S+)(?:\s+(.*))?$",
            line.strip(),
            re.I,
        )
        if not m:
            continue
        if m.group(3).lower() != "open":
            continue
        rest = (m.group(5) or "").strip()
        product = rest
        version = ""
        ports.append(
            {
                "port": int(m.group(1)),
                "protocol": m.group(2).lower(),
                "state": "open",
                "service": m.group(4),
                "product": product,
                "version": version,
            }
        )
    return {"ports": ports, "address": "", "hostname": ""}


def parse_nmap_xml_file(path: Path | str) -> dict[str, Any]:
    return parse_nmap_xml(Path(path).read_text(encoding="utf-8", errors="replace"))
