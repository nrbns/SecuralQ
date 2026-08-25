"""Security tool catalog: SecuraIQ builtins + third-party PATH/API tools."""

from __future__ import annotations

import shutil
from dataclasses import dataclass
from typing import Literal


Kind = Literal["builtin", "external"]
# securaiq = our native scanners; third_party = PATH binaries or vendor/public APIs
Origin = Literal["securaiq", "third_party"]


@dataclass(frozen=True)
class ToolSpec:
    id: str
    name: str
    kind: Kind
    description: str
    binaries: tuple[str, ...] = ()  # PATH names for external tools
    needs_target: bool = True
    heavy: bool = False  # opt-in / instruct-only by default
    category: str = "recon"
    origin: Origin = "securaiq"
    provider: str = ""  # e.g. Nmap, Microsoft Defender, NVD


TOOL_CATALOG: dict[str, ToolSpec] = {
    # --- Integrated VA (one tool: securaiq + nmap + nuclei + web scanner → evidence → AI → triage) ---
    "combo_assessment": ToolSpec(
        "combo_assessment",
        "Integrated VA",
        "builtin",
        "One workflow: authorize → SecuraIQ + Nmap + Nuclei + SecuraIQ Web Scanner → evidence → "
        "investigation pack → optional auto-triage. Replaces running scanners separately.",
        category="vuln",
        origin="securaiq",
        provider="SecuraIQ",
        heavy=True,
    ),
    # --- SecuraIQ tools (always available; no third-party install) ---
    "ports": ToolSpec(
        "ports", "Port probe", "builtin",
        "Fast TCP probe of common ports",
        category="recon",
        origin="securaiq",
        provider="SecuraIQ",
    ),
    "http": ToolSpec(
        "http", "HTTP fingerprint", "builtin",
        "Fetch headers, status, title, security headers",
        category="web",
        origin="securaiq",
        provider="SecuraIQ",
    ),
    "tls": ToolSpec(
        "tls", "TLS cert", "builtin",
        "TLS version + certificate summary",
        category="web",
        origin="securaiq",
        provider="SecuraIQ",
    ),
    "dns": ToolSpec(
        "dns", "DNS lookup", "builtin",
        "A/AAAA resolve + reverse PTR",
        category="recon",
        origin="securaiq",
        provider="SecuraIQ",
    ),
    "whois": ToolSpec(
        "whois", "RDAP / WHOIS", "builtin",
        "RDAP query (fallback to whois binary if present)",
        binaries=("whois",),
        category="recon",
        origin="securaiq",
        provider="SecuraIQ",
    ),
    "robots": ToolSpec(
        "robots", "robots.txt / sitemap", "builtin",
        "Fetch robots.txt and sitemap.xml hints",
        category="web",
        origin="securaiq",
        provider="SecuraIQ",
    ),
    "tech": ToolSpec(
        "tech", "Tech fingerprint", "builtin",
        "Lightweight stack hints from headers/body",
        category="web",
        origin="securaiq",
        provider="SecuraIQ",
    ),
    "headers_security": ToolSpec(
        "headers_security", "Security headers check", "builtin",
        "Score common HTTP security headers",
        category="web",
        origin="securaiq",
        provider="SecuraIQ",
    ),
    "email_auth": ToolSpec(
        "email_auth", "Email auth (SPF/DMARC)", "builtin",
        "DNS TXT lookup for SPF and DMARC (awareness / blue team)",
        needs_target=True,
        category="awareness",
        origin="securaiq",
        provider="SecuraIQ",
    ),
    "phishing_url": ToolSpec(
        "phishing_url", "Phishing URL review", "builtin",
        "Heuristic review of URLs in the message for awareness training",
        needs_target=False,
        category="awareness",
        origin="securaiq",
        provider="SecuraIQ",
    ),
    "suite_guide": ToolSpec(
        "suite_guide", "Burp / Acunetix / Greenbone guide", "builtin",
        "How to run Burp Suite, Acunetix, Greenbone/OpenVAS, ZAP in authorized labs",
        needs_target=False,
        category="intel",
        origin="securaiq",
        provider="SecuraIQ",
    ),
    "hardening_baseline": ToolSpec(
        "hardening_baseline", "Hardening & patch-exposure baseline", "builtin",
        "CIS-style scored checklist: TLS config, security headers, email auth, "
        "and risky exposed services — plus missing-patch counts from any "
        "connected XDR/EDR (Sophos/CrowdStrike/SentinelOne/Defender)",
        category="hardening",
        origin="securaiq",
        provider="SecuraIQ",
    ),
    "netvuln_scan": ToolSpec(
        "netvuln_scan", "Network vulnerability scan", "builtin",
        "Real vulnerability scan with zero installs: port probe + service banner "
        "grab, TLS/cert weaknesses, missing security headers, risky exposed "
        "services, and banner-based known-CVE matching for common services.",
        category="vuln",
        origin="securaiq",
        provider="SecuraIQ",
    ),
    "securaiq": ToolSpec(
        "securaiq", "SecuraIQ Scan Engine", "builtin",
        "Primary built-in scan engine (no install): discovery → ports → services → "
        "normalized findings → evidence + report. Queued as job kind scan_execute "
        "(Prefect when PREFECT_ENABLED, else local worker). Authorized / owned targets only.",
        category="vuln",
        origin="securaiq",
        provider="SecuraIQ",
        heavy=True,
    ),
    "openvas": ToolSpec(
        "openvas", "SecuraIQ Network Scanner", "builtin",
        "Install-free network vulnerability assessment (OpenVAS-class checks): "
        "full port probe, service banners, TLS weaknesses, security headers, "
        "risky services, and version→CVE matching. No Greenbone/GVM install required. "
        "Authorized / owned targets only.",
        category="vuln",
        origin="securaiq",
        provider="SecuraIQ",
    ),
    "code_scan": ToolSpec(
        "code_scan", "Code security scan (SAST)", "builtin",
        "Static scan of a local codebase folder: hardcoded secrets/keys, "
        "dangerous code patterns (eval/exec, shell=True, unsafe deserialization, "
        "XSS-prone DOM writes, string-built SQL), and known-vulnerable "
        "dependency versions via OSV.dev — no semgrep/bandit/trivy install "
        "required. Set Target to a local folder path and check Auth to confirm "
        "you own/are authorized to scan it.",
        needs_target=False,  # path comes from `target`, validated inside the tool
        heavy=True,
        category="sast",
        origin="securaiq",
        provider="SecuraIQ",
    ),
    "securaiq_code": ToolSpec(
        "securaiq_code", "SecuraIQ Code", "builtin",
        "SecuraIQ Code quality & SAST: sync issues from your connected code engine "
        "(SonarQube/SonarCloud-compatible API) into Vulnerabilities, or scan a local "
        "folder when Target is a path. Configure under Settings → SecuraIQ Code.",
        needs_target=False,
        heavy=True,
        category="sast",
        origin="securaiq",
        provider="SecuraIQ",
    ),
    "codeql": ToolSpec(
        "codeql", "CodeQL", "external",
        "GitHub CodeQL SAST. A single generic CLI invocation can't safely "
        "analyze an arbitrary repo — CodeQL needs a per-language database "
        "build step, so this tool reports whether the CLI is present and "
        "gives the exact commands to run it, rather than faking a scan. Real, "
        "automated CodeQL coverage of SecuraIQ's own codebase runs on every "
        "push via the `codeql` job in .github/workflows/security-scan.yml "
        "(github/codeql-action) — check the repo's Security tab for results.",
        binaries=("codeql",),
        needs_target=False,
        heavy=True,
        category="sast",
        origin="third_party",
        provider="GitHub CodeQL",
    ),
    "semgrep": ToolSpec(
        "semgrep", "Semgrep (SAST)", "external",
        "Real Semgrep static analysis (`semgrep --config=auto`) against a local "
        "codebase folder — pip-installable, so this runs the genuine scanner "
        "when present on PATH rather than approximating it. Set Target to a "
        "local folder path and check Auth. If semgrep isn't installed, install "
        "with `pip install semgrep`; `code_scan` covers the same path with no "
        "install required in the meantime.",
        binaries=("semgrep",),
        needs_target=False,  # path comes from `target`, same as code_scan
        heavy=True,
        category="sast",
        origin="third_party",
        provider="Semgrep",
    ),
    # --- Third-party APIs / vendor modules ---
    "cve_lookup": ToolSpec(
        "cve_lookup", "CVE lookup (NVD)", "builtin",
        "Pull NVD detail for CVE IDs mentioned in the message",
        needs_target=False,
        category="intel",
        origin="third_party",
        provider="NVD",
    ),
    "defender_hunt": ToolSpec(
        "defender_hunt", "Defender advanced hunting", "builtin",
        "Run KQL advanced hunting against Microsoft Defender XDR "
        "(Graph runHuntingQuery / legacy MTP API — authorized tenant only)",
        needs_target=False,
        heavy=True,
        category="intel",
        origin="third_party",
        provider="Microsoft Defender",
    ),
    "siem_sync": ToolSpec(
        "siem_sync", "SecuraIQ SIEM sync", "builtin",
        "Pull Wazuh manager agents + alerts into Assets, XDR feed, and SOC console. "
        "Configure WAZUH_* under Settings → SecuraIQ SIEM, then run sync from Tools or chat.",
        needs_target=False,
        category="siem",
        origin="securaiq",
        provider="SecuraIQ SIEM",
    ),
    "xdr_sync": ToolSpec(
        "xdr_sync", "XDR / EDR sync", "builtin",
        "Sync detections from configured vendors (Sophos, CrowdStrike, SentinelOne, "
        "Microsoft Defender) into the unified XDR feed and optional incidents.",
        needs_target=False,
        category="siem",
        origin="third_party",
        provider="Multi-vendor XDR",
    ),
    "thehive_sync": ToolSpec(
        "thehive_sync", "TheHive case sync", "builtin",
        "Pull TheHive cases into SecuraIQ Incidents. Configure THEHIVE_* under Settings.",
        needs_target=False,
        category="ir",
        origin="third_party",
        provider="TheHive",
    ),
    "inventory_sync": ToolSpec(
        "inventory_sync", "Network inventory sync", "builtin",
        "Refresh local /24 LAN inventory (Open-AudIT-style) into Assets — same as "
        "Refresh LAN / Sync inventory in the Tools hub.",
        needs_target=False,
        category="inventory",
        origin="securaiq",
        provider="SecuraIQ",
    ),
    "hardeningkitty": ToolSpec(
        "hardeningkitty", "HardeningKitty (Windows)", "external",
        "Import CIS/baseline Audit reports or run local Audit via PowerShell module "
        "(authorized Windows hosts). HailMary apply is not exposed via SecuraIQ API.",
        binaries=(),
        needs_target=False,
        category="hardening",
        origin="third_party",
        provider="HardeningKitty",
    ),
    # --- Third-party PATH binaries ---
    "nmap": ToolSpec(
        "nmap", "Nmap", "external",
        "Nmap via SecuraIQ scan engine (job scan_execute / Prefect when enabled); "
        "falls back to PATH nmap or builtin port probe if the binary is missing.",
        binaries=("nmap",),
        category="recon",
        origin="third_party",
        provider="Nmap",
        heavy=True,
    ),
    "nikto": ToolSpec(
        "nikto", "Nikto", "external",
        "Web server vulnerability scan",
        binaries=("nikto", "nikto.pl"),
        heavy=True,
        category="web",
        origin="third_party",
        provider="Nikto",
    ),
    "nuclei": ToolSpec(
        "nuclei", "Nuclei", "external",
        "Nuclei via SecuraIQ scan engine (job scan_execute / Prefect when enabled); "
        "falls back to PATH nuclei or builtin netvuln_scan if missing.",
        binaries=("nuclei",),
        heavy=True,
        category="vuln",
        origin="third_party",
        provider="ProjectDiscovery",
    ),
    "zap": ToolSpec(
        "zap", "SecuraIQ Web Scanner", "builtin",
        "Install-free web vulnerability assessment (built-in DAST): security headers, "
        "cookies, sensitive paths, CORS, TLS, reflection probes, and technology "
        "disclosure. No ZAP daemon or external binary required. "
        "Set ZAP_PREFER_API=true only if you want optional ZAP daemon deep-scan on top. "
        "Authorized / owned targets only.",
        heavy=True,
        category="web",
        origin="securaiq",
        provider="SecuraIQ",
    ),
    "sqlmap": ToolSpec(
        "sqlmap", "sqlmap", "external",
        "SQL injection test (lab targets only)",
        binaries=("sqlmap", "sqlmap.py"),
        heavy=True,
        category="web",
        origin="third_party",
        provider="sqlmap",
    ),
    "wpscan": ToolSpec(
        "wpscan", "WPScan", "external",
        "WordPress vulnerability scan",
        binaries=("wpscan",),
        heavy=True,
        category="web",
        origin="third_party",
        provider="WPScan",
    ),
    "masscan": ToolSpec(
        "masscan", "Masscan", "external",
        "Fast port sweep (rate-limited, lab host only)",
        binaries=("masscan",),
        heavy=True,
        category="recon",
        origin="third_party",
        provider="Masscan",
    ),
    "rustscan": ToolSpec(
        "rustscan", "RustScan", "external",
        "Fast port discovery then nmap scripts",
        binaries=("rustscan",),
        category="recon",
        origin="third_party",
        provider="RustScan",
    ),
    "whatweb": ToolSpec(
        "whatweb", "WhatWeb", "external",
        "Web technology fingerprinting",
        binaries=("whatweb",),
        category="web",
        origin="third_party",
        provider="WhatWeb",
    ),
    "dig": ToolSpec(
        "dig", "dig", "external",
        "DNS dig ANY/A/MX/TXT (when available)",
        binaries=("dig",),
        category="recon",
        origin="third_party",
        provider="BIND dig",
    ),
    "curl": ToolSpec(
        "curl", "curl", "external",
        "HTTP request with response headers",
        binaries=("curl",),
        category="web",
        origin="third_party",
        provider="curl",
    ),
    "sslscan": ToolSpec(
        "sslscan", "sslscan", "external",
        "SSL/TLS cipher and protocol scan",
        binaries=("sslscan",),
        category="web",
        origin="third_party",
        provider="sslscan",
    ),
    "sslyze": ToolSpec(
        "sslyze", "SSLyze", "external",
        "Python SSL/TLS analyzer",
        binaries=("sslyze",),
        heavy=True,
        category="web",
        origin="third_party",
        provider="SSLyze",
    ),
    "gobuster": ToolSpec(
        "gobuster", "Gobuster", "external",
        "Directory brute (small built-in wordlist)",
        binaries=("gobuster",),
        heavy=True,
        category="web",
        origin="third_party",
        provider="Gobuster",
    ),
    "ffuf": ToolSpec(
        "ffuf", "ffuf", "external",
        "Web fuzzer (small wordlist, rate-limited)",
        binaries=("ffuf",),
        heavy=True,
        category="web",
        origin="third_party",
        provider="ffuf",
    ),
    "traceroute": ToolSpec(
        "traceroute", "Traceroute", "external",
        "Path trace (tracert on Windows)",
        binaries=("traceroute", "tracert"),
        category="recon",
        origin="third_party",
        provider="OS traceroute",
    ),
    "ping": ToolSpec(
        "ping", "Ping", "external",
        "ICMP reachability check",
        binaries=("ping",),
        category="recon",
        origin="third_party",
        provider="OS ping",
    ),
    "openssl": ToolSpec(
        "openssl", "OpenSSL s_client", "external",
        "TLS handshake peek",
        binaries=("openssl",),
        category="web",
        origin="third_party",
        provider="OpenSSL",
    ),
    "wafw00f": ToolSpec(
        "wafw00f", "wafw00f", "external",
        "WAF detection",
        binaries=("wafw00f",),
        category="web",
        origin="third_party",
        provider="wafw00f",
    ),
}


# Default auto set — lightweight SecuraIQ builtins only (fast).
AUTO_LIGHT_TOOLS = (
    "dns",
    "ports",
    "http",
    "headers_security",
)

# Awareness / phishing mode — no port scanning; DNS + lure review only
AWARENESS_AUTO_TOOLS = (
    "phishing_url",
    "email_auth",
    "suite_guide",
)

ORIGIN_ORDER = ("securaiq", "third_party")
ORIGIN_LABELS = {
    "securaiq": "SecuraIQ tools",
    "third_party": "Third-party tools & APIs",
}

# When PATH binary missing, run this builtin so PT workflows still produce real results.
EXTERNAL_FALLBACKS: dict[str, str] = {
    "nmap": "ports",
    "masscan": "ports",
    "rustscan": "ports",
    "nikto": "headers_security",
    "nuclei": "netvuln_scan",
    "zap": "headers_security",
    "whatweb": "tech",
    "dig": "dns",
    "sslscan": "tls",
    "sslyze": "tls",
    "gobuster": "robots",
    "ffuf": "robots",
    "wafw00f": "headers_security",
    "sqlmap": "http",
    "wpscan": "http",
    "openssl": "tls",
}

# Always-on PT pack — single integrated VA tool (replaces multi-scanner PT pack)
PT_PACK_TOOLS: tuple[str, ...] = (
    "combo_assessment",
)

# SOC / inventory connectors — runnable from Tools hub and chat (no scan target)
SOC_PACK_TOOLS: tuple[str, ...] = (
    "siem_sync",
    "xdr_sync",
    "inventory_sync",
)

# Tools that queue the scan engine (scan_execute → Prefect when ready)
ENGINE_TOOLS: dict[str, str] = {
    "combo_assessment": "combo_assessment",
    "combo": "combo_assessment",
    "integrated_va": "combo_assessment",
    "securaiq": "securaiq",
    "nmap": "nmap",
    "nuclei": "nuclei",
    "zap": "zap",
}


def resolve_binary(spec: ToolSpec) -> str | None:
    if spec.kind == "builtin":
        return None
    for name in spec.binaries:
        path = shutil.which(name)
        if path:
            return path
    return None


def is_available(tool_id: str) -> bool:
    spec = TOOL_CATALOG.get(tool_id)
    if not spec:
        return False
    # Credential / module-gated tools (even if kind=builtin) — must check before
    # the generic builtin "always True" path or the UI lies about availability.
    if tool_id == "defender_hunt":
        try:
            from app.connectors.defender import is_configured

            return is_configured()
        except Exception:
            return False
    if tool_id == "siem_sync":
        try:
            from app.connectors import wazuh as wz

            return wz.is_configured()
        except Exception:
            return False
    if tool_id == "xdr_sync":
        try:
            from app.xdr import status as xdr_st

            return any(v.get("configured") for v in xdr_st().values())
        except Exception:
            return False
    if tool_id == "thehive_sync":
        try:
            from app.connectors import thehive as th

            return th.is_configured()
        except Exception:
            return False
    if tool_id == "inventory_sync":
        return True
    if tool_id == "hardeningkitty":
        try:
            from app.hardeningkitty import is_installed

            return is_installed()
        except Exception:
            return False
    if spec.kind == "builtin":
        return True
    return resolve_binary(spec) is not None


def list_tools_status() -> dict:
    import time

    cache = getattr(list_tools_status, "_cache", None)
    now = time.monotonic()
    if cache and (now - cache["ts"]) < 45:
        return cache["payload"]
    tools = []
    available = 0
    by_origin_avail = {"securaiq": 0, "third_party": 0}
    by_origin_total = {"securaiq": 0, "third_party": 0}
    for tid, spec in TOOL_CATALOG.items():
        avail = is_available(tid)
        origin = spec.origin if spec.origin in by_origin_total else "third_party"
        by_origin_total[origin] = by_origin_total.get(origin, 0) + 1
        if avail:
            available += 1
            by_origin_avail[origin] = by_origin_avail.get(origin, 0) + 1
        tools.append(
            {
                "id": tid,
                "name": spec.name,
                "kind": spec.kind,
                "origin": origin,
                "provider": spec.provider or ("SecuraIQ" if origin == "securaiq" else tid),
                "description": spec.description,
                "available": avail,
                "heavy": spec.heavy,
                "needs_target": spec.needs_target,
                "category": spec.category,
                "binary": resolve_binary(spec) if spec.kind == "external" else "builtin",
                "fallback": EXTERNAL_FALLBACKS.get(tid) if not avail and tid in EXTERNAL_FALLBACKS else None,
                "engine": ENGINE_TOOLS.get(tid),
            }
        )
    payload = {
        "tools": tools,
        "count": len(tools),
        "available_count": available,
        "securaiq_count": by_origin_total["securaiq"],
        "securaiq_available": by_origin_avail["securaiq"],
        "third_party_count": by_origin_total["third_party"],
        "third_party_available": by_origin_avail["third_party"],
        "origins": [
            {
                "id": oid,
                "label": ORIGIN_LABELS[oid],
                "count": by_origin_total[oid],
                "available": by_origin_avail[oid],
            }
            for oid in ORIGIN_ORDER
        ],
        "auto_light": list(AUTO_LIGHT_TOOLS),
        "auto_awareness": list(AWARENESS_AUTO_TOOLS),
        "pt_pack": list(PT_PACK_TOOLS),
        "soc_pack": list(SOC_PACK_TOOLS),
        "engine_tools": dict(ENGINE_TOOLS),
    }
    list_tools_status._cache = {"ts": now, "payload": payload}
    return payload
