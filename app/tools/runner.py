"""Select and run authorized security tools; format results for the AI."""

from __future__ import annotations

import asyncio
import hashlib
import json
import re
import shutil
import socket
import ssl
from pathlib import Path
from typing import Any

import httpx

from app.config import settings
from app.net_assess import extract_targets, resolve_and_authorize
from app.tools.registry import (
    AUTO_LIGHT_TOOLS,
    AWARENESS_AUTO_TOOLS,
    ENGINE_TOOLS,
    EXTERNAL_FALLBACKS,
    PT_PACK_TOOLS,
    TOOL_CATALOG,
    is_available,
    resolve_binary,
)

_CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)
_URL_RE = re.compile(r"https?://[^\s<>\"']+", re.I)
_DOMAIN_RE = re.compile(r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b", re.I)
_AWARENESS_HINT_RE = re.compile(
    r"\b(phish(?:ing)?|awareness|lure|gophish|knowbe4|spf|dkim|dmarc|"
    r"email\s*auth|simulation|vishing|smishing|red\s*flags?|spear.?phish)\b",
    re.IGNORECASE,
)
_TOOL_WORD_RE = re.compile(
    r"\b(nmap|nikto|nuclei|whatweb|gobuster|ffuf|sslscan|sslyze|dig|whois|curl|"
    r"traceroute|tracert|ping|openssl|wafw00f|ports?|dns|tls|http|robots|tech|"
    r"cve_lookup|headers?(?:\s+security)?|zap|zaproxy|sqlmap|wpscan|masscan|"
    r"rustscan|openvas|greenbone|gvm|securaiq(?:_scan|_code|_engine|_siem)?|sonarqube|sonar|burp|acunetix|email_auth|phishing_url|suite_guide|"
    r"spf|dmarc|dkim|phish(?:ing)?|awareness|hardening(?:_baseline)?|patch(?:es|ing|"
    r"\s+compliance)?|xdr|edr|defender(?:_hunt)?|advanced\s*hunting|kql|semgrep|codeql|code_scan|"
    r"wazuh|siem(?:_sync)?|thehive(?:_sync)?|crowdstrike|sophos|sentinelone|inventory(?:_sync)?|openaudit)\b",
    re.IGNORECASE,
)
_RUN_HINT_RE = re.compile(
    r"\b(run|use|execute|launch|scan\s+with|probe\s+with|tools?\s*:|review|check)\b",
    re.IGNORECASE,
)

_COMMON_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445,
    1433, 1521, 2049, 3000, 3306, 3389, 5432, 5900, 5985, 6379,
    8009, 8080, 8180, 8443, 9200, 27017,
]

# Fast default probe set — includes Metasploitable2 / Juice Shop lab services
_LIGHT_PORTS = [
    21, 22, 23, 25, 80, 111, 135, 139, 443, 445, 3000, 3306, 3389,
    5432, 5900, 6379, 8080, 8443, 9200, 27017,
]

_DIR_WORDS = [
    "admin", "login", "api", "robots.txt", "sitemap.xml", ".git", ".env",
    "backup", "wp-admin", "wp-login.php", "phpmyadmin", "console", "swagger",
    "actuator", "server-status", "uploads", "static", "assets", "config",
]


def _publish_tool_pulse(
    *,
    kind: str,
    status: str,
    user_id: str = "local",
    target: str = "",
    findings: int | None = None,
    tools: list[str] | None = None,
    message: str = "",
) -> None:
    try:
        from app.realtime_bus import publish

        payload: dict[str, Any] = {
            "type": "tool",
            "kind": kind,
            "tool": kind,
            "status": status,
            "user_id": user_id or "local",
        }
        if target:
            payload["target"] = str(target)[:120]
        if findings is not None:
            payload["findings"] = int(findings)
        if tools:
            payload["tools"] = tools[:8]
        if message:
            payload["message"] = message
        publish(**payload)
    except Exception:
        pass


def parse_tool_request(
    message: str,
    *,
    explicit: list[str] | None = None,
    auto: bool = False,
    include_heavy: bool = False,
    mode: str | None = None,
) -> list[str]:
    """Decide which tools to run from UI list, message instructions, or auto set."""
    selected: list[str] = []
    mode_l = (mode or "").lower()
    awareness_mode = mode_l in {"awareness", "ciso", "tabletop"}

    if explicit:
        _explicit_alias = {
            "wazuh": "siem_sync",
            "siem": "siem_sync",
            "xdr": "xdr_sync",
            "thehive": "thehive_sync",
            "inventory": "inventory_sync",
            "openaudit": "inventory_sync",
        }
        for t in explicit:
            tid = (t or "").strip().lower().replace(" ", "_")
            if tid in _explicit_alias:
                tid = _explicit_alias[tid]
            if tid == "tracert":
                tid = "traceroute"
            if tid in ("header", "headers", "headers_security"):
                tid = "headers_security"
            if tid in ("port", "ports"):
                tid = "ports"
            if tid in TOOL_CATALOG:
                selected.append(tid)

    # Instruction parsing: "run nmap and nikto"
    instructed = bool(_RUN_HINT_RE.search(message or "")) or bool(explicit)
    mentioned: list[str] = []
    for m in _TOOL_WORD_RE.finditer(message or ""):
        raw = m.group(1).lower()
        alias = {
            "port": "ports",
            "ports": "ports",
            "tracert": "traceroute",
            "header": "headers_security",
            "headers": "headers_security",
            "headers security": "headers_security",
            "zaproxy": "zap",
            "greenbone": "openvas",
            "gvm": "openvas",
            "openvas": "openvas",
            "network_scanner": "openvas",
            "securaiq_network": "openvas",
            "web_scanner": "zap",
            "securaiq_web": "zap",
            "dast": "zap",
            "securaiq": "securaiq",
            "securaiq_scan": "securaiq",
            "securaiq_engine": "securaiq",
            "combo": "combo_assessment",
            "integrated_va": "combo_assessment",
            "integrated": "combo_assessment",
            "va_combo": "combo_assessment",
            "full_scan": "combo_assessment",
            "pentest": "combo_assessment",
            "assessment": "combo_assessment",
            "sonarqube": "securaiq_code",
            "sonar": "securaiq_code",
            "sonarcloud": "securaiq_code",
            "code_quality": "securaiq_code",
            "securaiq_code": "securaiq_code",
            "burp": "suite_guide",
            "acunetix": "suite_guide",
            "spf": "email_auth",
            "dmarc": "email_auth",
            "dkim": "email_auth",
            "phish": "phishing_url",
            "phishing": "phishing_url",
            "awareness": "phishing_url",
            "hardening": "hardening_baseline",
            "hardening_baseline": "hardening_baseline",
            "patch": "hardening_baseline",
            "patches": "hardening_baseline",
            "patching": "hardening_baseline",
            "patch compliance": "hardening_baseline",
            "xdr": "hardening_baseline",
            "edr": "hardening_baseline",
            "defender": "defender_hunt",
            "defender_hunt": "defender_hunt",
            "advanced hunting": "defender_hunt",
            "kql": "defender_hunt",
            "wazuh": "siem_sync",
            "siem": "siem_sync",
            "securaiq_siem": "siem_sync",
            "siem_sync": "siem_sync",
            "xdr_sync": "xdr_sync",
            "crowdstrike": "xdr_sync",
            "sophos": "xdr_sync",
            "sentinelone": "xdr_sync",
            "thehive": "thehive_sync",
            "thehive_sync": "thehive_sync",
            "inventory": "inventory_sync",
            "inventory_sync": "inventory_sync",
            "openaudit": "inventory_sync",
            "lan": "inventory_sync",
        }.get(raw, raw.replace(" ", "_"))
        if alias in TOOL_CATALOG:
            mentioned.append(alias)
        elif raw == "cve_lookup" or raw.startswith("cve"):
            mentioned.append("cve_lookup")

    if instructed and mentioned:
        selected.extend(mentioned)
    elif mentioned and not auto:
        # Soft instruct: tool names alone still count when tools module is on
        selected.extend(mentioned)

    if auto and not selected:
        preset = AWARENESS_AUTO_TOOLS if awareness_mode else AUTO_LIGHT_TOOLS
        for tid in preset:
            spec = TOOL_CATALOG[tid]
            if spec.heavy and not include_heavy:
                continue
            selected.append(tid)

    # Power awareness tools across every mode when the message clearly asks
    if _URL_RE.search(message or "") and "phishing_url" not in selected:
        selected.insert(0, "phishing_url")
    if _AWARENESS_HINT_RE.search(message or ""):
        if "phishing_url" not in selected:
            selected.append("phishing_url")
        if "email_auth" not in selected and (
            _DOMAIN_RE.search(message or "") or awareness_mode
        ):
            selected.append("email_auth")

    # Always attach cve_lookup if CVEs present
    if _CVE_RE.search(message or "") and "cve_lookup" not in selected:
        selected.append("cve_lookup")

    # Heavy tools only when instructed / explicit / include_heavy
    out: list[str] = []
    seen: set[str] = set()
    explicit_l = {x.strip().lower() for x in (explicit or [])}
    for tid in selected:
        if tid in seen:
            continue
        spec = TOOL_CATALOG.get(tid)
        if not spec:
            continue
        if spec.heavy and not (include_heavy or tid in mentioned or tid in explicit_l):
            continue
        seen.add(tid)
        out.append(tid)
    return out[:12]


async def _run_cmd(argv: list[str], timeout: float = 25.0) -> dict[str, Any]:
    try:
        proc = await asyncio.create_subprocess_exec(
            *argv,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        except asyncio.TimeoutError:
            proc.kill()
            await proc.communicate()
            return {"ok": False, "error": f"timed out after {timeout:.0f}s", "output": ""}
        text = (stdout or b"").decode("utf-8", errors="replace")
        err = (stderr or b"").decode("utf-8", errors="replace")
        return {
            "ok": proc.returncode == 0 or bool(text.strip()),
            "output": (text or err)[-4500:],
            "stderr": err[-800:] if err and not text.strip() else "",
            "returncode": proc.returncode,
        }
    except FileNotFoundError:
        return {"ok": False, "error": "binary not found", "output": ""}
    except Exception as exc:
        return {"ok": False, "error": str(exc), "output": ""}


async def _probe_port(ip: str, port: int, timeout: float = 0.22) -> bool:
    try:
        _r, w = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout=timeout)
        w.close()
        try:
            await w.wait_closed()
        except Exception:
            pass
        return True
    except Exception:
        return False


_BANNER_GRAB_PORTS = (21, 22, 23, 25)


async def _grab_banner(ip: str, port: int, timeout: float = 1.3) -> str:
    """Read whatever the service says first on connect (FTP/SSH/Telnet/SMTP
    all greet in cleartext) — no install, just a raw socket read."""
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout=timeout)
    except Exception:
        return ""
    try:
        data = await asyncio.wait_for(reader.read(256), timeout=timeout)
        try:
            return data.decode("utf-8").strip()
        except UnicodeDecodeError:
            return data.decode("latin-1", errors="replace").strip()
    except Exception:
        return ""
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass


async def _tool_ports(ip: str, *, light: bool = True) -> dict[str, Any]:
    ports = _LIGHT_PORTS if light else _COMMON_PORTS
    flags = await asyncio.gather(*[_probe_port(ip, p) for p in ports])
    open_ports = [p for p, ok in zip(ports, flags) if ok]
    label = "light probe" if light else "full probe"
    return {
        "ok": True,
        "open_ports": open_ports,
        "output": f"Open ({label}): {open_ports or 'none'} · checked {len(ports)} ports",
    }


async def _tool_dns(target: str, ip: str) -> dict[str, Any]:
    lines = [f"target={target}", f"ip={ip}"]
    try:
        infos = socket.getaddrinfo(target, None)
        addrs = sorted({i[4][0] for i in infos})
        lines.append(f"addresses={addrs}")
    except Exception as exc:
        lines.append(f"resolve_error={exc}")
    try:
        ptr, _, _ = socket.gethostbyaddr(ip)
        lines.append(f"ptr={ptr}")
    except Exception:
        lines.append("ptr=none")
    return {"ok": True, "output": "\n".join(lines)}


async def _http_get(url: str) -> tuple[httpx.Response | None, str]:
    timeout = httpx.Timeout(connect=1.0, read=4.0, write=2.0, pool=2.0)
    try:
        async with httpx.AsyncClient(timeout=timeout, follow_redirects=True, verify=False) as client:
            r = await client.get(url, headers={"User-Agent": "SecuraIQ-Tools/1.0"})
            return r, ""
    except Exception as exc:
        return None, str(exc)


def _guess_base_urls(ip: str, open_ports: list[int] | None = None) -> list[str]:
    ports = open_ports or []
    urls: list[str] = []
    if 443 in ports or not ports:
        urls.append(f"https://{ip}/")
    if 8443 in ports:
        urls.append(f"https://{ip}:8443/")
    if 80 in ports or not ports:
        urls.append(f"http://{ip}/")
    if 8080 in ports:
        urls.append(f"http://{ip}:8080/")
    # de-dupe
    seen: set[str] = set()
    out = []
    for u in urls:
        if u not in seen:
            seen.add(u)
            out.append(u)
    return out[:3]


async def _tool_http(ip: str, open_ports: list[int] | None = None) -> dict[str, Any]:
    lines = []
    for url in _guess_base_urls(ip, open_ports):
        r, err = await _http_get(url)
        if err or r is None:
            lines.append(f"{url} error={err}")
            continue
        title = ""
        m = re.search(r"<title[^>]*>(.*?)</title>", r.text[:12000], re.I | re.S)
        if m:
            title = re.sub(r"\s+", " ", m.group(1)).strip()[:120]
        interesting = {
            k: r.headers.get(k)
            for k in (
                "server", "x-powered-by", "x-frame-options", "content-security-policy",
                "strict-transport-security", "x-content-type-options", "set-cookie",
            )
            if r.headers.get(k)
        }
        lines.append(f"{url} status={r.status_code} title={title!r} headers={interesting}")
    return {"ok": bool(lines), "output": "\n".join(lines) or "no HTTP response"}


async def _tool_headers_security(ip: str, open_ports: list[int] | None = None) -> dict[str, Any]:
    checks = [
        "strict-transport-security",
        "content-security-policy",
        "x-frame-options",
        "x-content-type-options",
        "referrer-policy",
        "permissions-policy",
    ]
    lines = []
    for url in _guess_base_urls(ip, open_ports)[:2]:
        r, err = await _http_get(url)
        if r is None:
            lines.append(f"{url}: {err}")
            continue
        present = [h for h in checks if r.headers.get(h)]
        missing = [h for h in checks if h not in present]
        lines.append(f"{url}: present={present}; missing={missing}")
    return {"ok": True, "output": "\n".join(lines) or "no HTTP"}


async def _tool_tls(ip: str, open_ports: list[int] | None = None) -> dict[str, Any]:
    port = 443 if not open_ports or 443 in open_ports else (8443 if 8443 in (open_ports or []) else 443)

    def _sync() -> dict[str, str]:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((ip, port), timeout=1.5) as sock:
            with ctx.wrap_socket(sock, server_hostname=ip) as ssock:
                cert = ssock.getpeercert()
                ver = ssock.version() or ""
                if not cert:
                    return {"tls": ver, "note": "no peer cert details"}
                sub = dict(x[0] for x in cert.get("subject", ()))
                iss = dict(x[0] for x in cert.get("issuer", ()))
                return {
                    "tls": ver,
                    "cn": sub.get("commonName", ""),
                    "issuer": iss.get("commonName", ""),
                    "notAfter": cert.get("notAfter", ""),
                    "port": str(port),
                }

    try:
        data = await asyncio.to_thread(_sync)
        return {"ok": True, "output": json.dumps(data)}
    except Exception as exc:
        return {"ok": False, "error": str(exc), "output": ""}


async def _tool_robots(ip: str, open_ports: list[int] | None = None) -> dict[str, Any]:
    lines = []
    for base in _guess_base_urls(ip, open_ports)[:2]:
        for path in ("robots.txt", "sitemap.xml"):
            url = base.rstrip("/") + "/" + path
            r, err = await _http_get(url)
            if r is None:
                lines.append(f"{url}: {err}")
            else:
                body = r.text[:800].replace("\n", " | ")
                lines.append(f"{url} [{r.status_code}]: {body}")
    return {"ok": True, "output": "\n".join(lines)}


async def _tool_tech(ip: str, open_ports: list[int] | None = None) -> dict[str, Any]:
    hints: list[str] = []
    for url in _guess_base_urls(ip, open_ports)[:2]:
        r, err = await _http_get(url)
        if r is None:
            hints.append(f"{url}: {err}")
            continue
        body = r.text[:20000].lower()
        hdr = {k.lower(): v for k, v in r.headers.items()}
        if "wordpress" in body or "wp-content" in body:
            hints.append("WordPress signals")
        if "drupal" in body:
            hints.append("Drupal signals")
        if "joomla" in body:
            hints.append("Joomla signals")
        if "react" in body or "next" in hdr.get("x-powered-by", "").lower():
            hints.append("JS framework signals")
        if "nginx" in hdr.get("server", "").lower():
            hints.append(f"Nginx: {hdr.get('server')}")
        if "apache" in hdr.get("server", "").lower():
            hints.append(f"Apache: {hdr.get('server')}")
        if "iis" in hdr.get("server", "").lower():
            hints.append(f"IIS: {hdr.get('server')}")
        if "php" in hdr.get("x-powered-by", "").lower():
            hints.append(hdr.get("x-powered-by", "PHP"))
        cookie = hdr.get("set-cookie", "")
        if "asp.net" in cookie.lower() or "asp.net" in body:
            hints.append("ASP.NET signals")
        hints.append(f"{url} server={hdr.get('server', '?')}")
    return {"ok": True, "output": "; ".join(dict.fromkeys(hints)) or "no tech hints"}


async def _tool_whois(target: str, ip: str) -> dict[str, Any]:
    # Prefer RDAP (builtin), then whois binary
    timeout = httpx.Timeout(connect=2.0, read=6.0, write=2.0, pool=2.0)
    try:
        async with httpx.AsyncClient(timeout=timeout, follow_redirects=True) as client:
            r = await client.get(f"https://rdap.org/ip/{ip}")
            if r.status_code == 200:
                data = r.json()
                name = data.get("name") or data.get("handle")
                country = data.get("country")
                return {
                    "ok": True,
                    "output": json.dumps(
                        {"source": "rdap", "name": name, "country": country, "ip": ip},
                        default=str,
                    )[:2000],
                }
    except Exception:
        pass
    binary = resolve_binary(TOOL_CATALOG["whois"])
    if binary:
        # whois may need hostname; try ip
        return await _run_cmd([binary, ip], timeout=12)
    return {"ok": False, "error": "RDAP failed and whois binary missing", "output": ""}


_KQL_FENCE_RE = re.compile(r"```(?:kql|kusto)?\s*([\s\S]*?)```", re.I)


async def _tool_defender_hunt(message: str) -> dict[str, Any]:
    """Run Defender XDR advanced hunting (authorized tenant — Graph or legacy MTP)."""
    from app.connectors import defender as defender_conn

    if not defender_conn.is_configured():
        return {
            "ok": False,
            "error": "Defender not configured",
            "output": (
                "Set DEFENDER_TENANT_ID / DEFENDER_CLIENT_ID / DEFENDER_CLIENT_SECRET and "
                "grant ThreatHunting.Read.All (Graph) or AdvancedHunting.Read.All (MTP)."
            ),
        }

    query = ""
    m = _KQL_FENCE_RE.search(message or "")
    if m:
        query = (m.group(1) or "").strip()
    if not query:
        qm = re.search(r"(?is)\bquery\s*[:=]\s*(.+)$", message or "")
        if qm:
            query = qm.group(1).strip().strip("`")
    if not query:
        query = defender_conn.DEFAULT_LIVE_QUERY

    result = await defender_conn.run_advanced_hunting(query, limit=25)
    if not result.get("ok"):
        return {
            "ok": False,
            "error": result.get("error") or "hunting_failed",
            "output": json.dumps(
                {
                    "hint": result.get("hint"),
                    "graph_error": result.get("graph_error"),
                    "legacy_error": result.get("legacy_error"),
                },
                indent=2,
            )[:2000],
        }

    rows = result.get("results") or []
    preview = json.dumps(rows[:8], indent=2, default=str)[:3500]
    lines = [
        f"backend={result.get('backend')} rows={result.get('result_count')}/{result.get('result_total')}",
        preview or "(no rows)",
        "Remediation: triage hosts/accounts in results, open an incident for confirmed threats, "
        "and tune detections — hunting is read-only.",
    ]
    return {
        "ok": True,
        "output": "\n".join(lines),
        "backend": result.get("backend"),
        "result_count": result.get("result_count"),
    }


async def _tool_siem_sync(user_id: str = "local") -> dict[str, Any]:
    from app.connectors import wazuh as wz
    from app.jobs import enqueue_job

    if not wz.is_configured():
        return {
            "ok": False,
            "error": "SecuraIQ SIEM not configured",
            "output": (
                "Set WAZUH_BASE_URL, WAZUH_USER, and WAZUH_PASSWORD under "
                "Settings → SecuraIQ SIEM, then run `siem sync` again."
            ),
        }
    job = enqueue_job("wazuh_sync", {"user_id": user_id}, engine="auto")
    jid = (job or {}).get("id") or "?"
    return {
        "ok": True,
        "output": (
            f"SecuraIQ SIEM sync queued · job `{jid}` · pulls Wazuh agents into Assets "
            f"and alerts into the SOC/XDR feed. Open SOC workspace to watch progress."
        ),
        "job_id": jid,
    }


async def _tool_xdr_sync(user_id: str = "local") -> dict[str, Any]:
    from app.jobs import enqueue_job
    from app.xdr import status as xdr_st

    vendors = xdr_st()
    configured = [v for v, meta in vendors.items() if meta.get("configured")]
    if not configured:
        return {
            "ok": False,
            "error": "No XDR vendors configured",
            "output": (
                "Configure at least one vendor under Settings → XDR "
                "(Sophos, CrowdStrike, SentinelOne, or Microsoft Defender), then run `xdr sync`."
            ),
        }
    job = enqueue_job("xdr_sync", {"user_id": user_id}, engine="auto")
    jid = (job or {}).get("id") or "?"
    return {
        "ok": True,
        "output": (
            f"XDR sync queued · job `{jid}` · vendors: {', '.join(configured)}. "
            "Detections land in SOC → XDR / EDR and may open incidents for critical/high alerts."
        ),
        "job_id": jid,
        "vendors": configured,
    }


async def _tool_thehive_sync(user_id: str = "local") -> dict[str, Any]:
    from app.connectors import thehive as th
    from app.jobs import enqueue_job

    if not th.is_configured():
        return {
            "ok": False,
            "error": "TheHive not configured",
            "output": "Set THEHIVE_URL and THEHIVE_API_KEY under Settings → TheHive.",
        }
    job = enqueue_job("thehive_sync", {"user_id": user_id}, engine="auto")
    jid = (job or {}).get("id") or "?"
    return {
        "ok": True,
        "output": f"TheHive case sync queued · job `{jid}` · cases appear under Incidents.",
        "job_id": jid,
    }


async def _tool_inventory_sync(user_id: str = "local") -> dict[str, Any]:
    from app.lan_sync import refresh_lan_assets

    result = refresh_lan_assets(user_id, queue_scan=False)
    inv_job = (result or {}).get("inventory_job") or {}
    jid = inv_job.get("id") or "?"
    subnet = (result or {}).get("subnet") or "local /24"
    n = 1 + len((result or {}).get("neighbors") or [])
    return {
        "ok": True,
        "output": (
            f"Network inventory refresh queued · {n} host(s) on `{subnet}` · job `{jid}`. "
            "Hosts stream into Assets → Open Audit as they are probed."
        ),
        "job_id": jid,
        "subnet": subnet,
    }


async def _tool_cve_lookup(message: str) -> dict[str, Any]:
    cves = list(dict.fromkeys(_CVE_RE.findall(message or "")))[:3]
    if not cves:
        return {"ok": False, "error": "No CVE IDs in message", "output": ""}
    lines = []
    timeout = httpx.Timeout(connect=2.0, read=8.0, write=2.0, pool=2.0)
    async with httpx.AsyncClient(timeout=timeout, follow_redirects=True) as client:
        for cve in cves:
            try:
                r = await client.get(
                    "https://services.nvd.nist.gov/rest/json/cves/2.0",
                    params={"cveId": cve.upper()},
                    headers={"User-Agent": "SecuraIQ-Tools/1.0"},
                )
                if r.status_code != 200:
                    lines.append(f"{cve}: HTTP {r.status_code}")
                    continue
                vulns = (r.json().get("vulnerabilities") or [])
                if not vulns:
                    lines.append(f"{cve}: not found")
                    continue
                cve_obj = vulns[0].get("cve") or {}
                desc = next(
                    (d.get("value") for d in (cve_obj.get("descriptions") or []) if d.get("lang") == "en"),
                    "",
                )
                metrics = cve_obj.get("metrics") or {}
                score = ""
                for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                    arr = metrics.get(key) or []
                    if arr:
                        score = str((arr[0].get("cvssData") or {}).get("baseScore", ""))
                        break
                lines.append(f"{cve.upper()} CVSS={score} — {(desc or '')[:500]}")
            except Exception as exc:
                lines.append(f"{cve}: {exc}")
    return {"ok": True, "output": "\n".join(lines)}


async def _tool_email_auth(target: str) -> dict[str, Any]:
    domain = target.strip().lower()
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", domain):
        return {
            "ok": False,
            "error": "email_auth needs a domain (e.g. example.com), not an IP",
            "output": "",
        }
    domain = domain.removeprefix("http://").removeprefix("https://").split("/")[0]
    lines = [f"domain={domain}"]
    dig = resolve_binary(TOOL_CATALOG["dig"]) if "dig" in TOOL_CATALOG else None
    for name, qname in (("SPF", domain), ("DMARC", f"_dmarc.{domain}")):
        if dig:
            res = await _run_cmd([dig, "+short", "TXT", qname], timeout=8)
            lines.append(f"{name} TXT: {(res.get('output') or res.get('error') or 'none').strip()[:500]}")
        else:
            nslookup = shutil.which("nslookup")
            if nslookup:
                res = await _run_cmd([nslookup, "-type=TXT", qname], timeout=10)
                lines.append(f"{name}:\n{(res.get('output') or '')[:600]}")
            else:
                lines.append(f"{name}: install dig/nslookup for TXT lookups (`nslookup -type=TXT {qname}`)")
    lines.append("Awareness: SPF fail + DMARC p=quarantine/reject reduces spoofed phishing.")
    return {"ok": True, "output": "\n".join(lines)}


async def _tool_phishing_url(message: str) -> dict[str, Any]:
    urls = _URL_RE.findall(message or "")[:5]
    if not urls:
        # try bare domains as example
        return {
            "ok": True,
            "output": (
                "No URL found. Paste a sample lure URL for awareness review.\n"
                "Teach users: hover links, check domain brand mismatch, unexpected MFA prompts, "
                "urgency/fear language, lookalike domains (rn→m), and report-don't-click."
            ),
        }
    findings = []
    for url in urls:
        flags = []
        host = re.sub(r"^https?://", "", url, flags=re.I).split("/")[0].lower()
        if re.search(r"\d{1,3}(\.\d{1,3}){3}", host):
            flags.append("raw-IP host (common in phish)")
        if "@" in url:
            flags.append("credential-in-URL / @ trick")
        if host.count(".") >= 3:
            flags.append("deep subdomain (lookalike risk)")
        for brand in ("microsoft", "google", "apple", "paypal", "okta", "login", "secure", "account"):
            if brand in host and not host.endswith(f"{brand}.com") and brand not in host.split(".")[0:1]:
                flags.append(f"brand keyword in host ({brand})")
        if any(x in url.lower() for x in ("%2f", "..", "redirect", "url=")):
            flags.append("redirect / encoding pattern")
        findings.append(f"{url}\n  host={host}\n  flags={flags or ['none — still verify via SOC process']}")
    findings.append(
        "Training note: label simulations clearly in real programs; measure report-rate not shame."
    )
    return {"ok": True, "output": "\n".join(findings)}


async def _tool_suite_guide() -> dict[str, Any]:
    from app.scanners.registry import get_scanner

    zap_avail, zap_detail = get_scanner("zap").available()
    nuclei = resolve_binary(TOOL_CATALOG["nuclei"]) if "nuclei" in TOOL_CATALOG else None
    zap_line = f"READY: {zap_detail}" if zap_avail else "built-in (always available)"
    text = f"""Authorized lab / engagement tool playbooks

## Burp Suite (PortSwigger)
- Community/Pro GUI: proxy 127.0.0.1:8080, intercept, repeater, intruder (lab apps).
- Scope only in-scope hosts. Export sitemap → report.
- SecuraIQ twin: **SecuraIQ Web Scanner** (built-in DAST) — {zap_line}.
- **Results import is real, not just a guide**: Scanner tab → right-click → "Report selected issues" →
  XML → upload via Import (`POST /api/vulnerabilities/import`) if you prefer file import over Live scan.
  Findings land as real, severity-scored
  vulnerability rows (High/Medium/Low/Information mapped correctly), same pipeline as Trivy/Semgrep/ZAP.

## Acunetix (licensed DAST)
- Point at lab/staging URL with credentials in scope.
- API: set ACUNETIX_URL + API key in env if you automate; otherwise use UI scans.
- FOSS stand-ins: ZAP baseline + Nuclei {'READY' if nuclei else '(install nuclei)'}.

## SecuraIQ Network Scanner (built-in OpenVAS-class)
- Run tool `openvas` from Live scan — install-free network vuln assessment.
- Ports, banners, TLS, headers, risky services, version→CVE matching. Auth + owned targets only.
- Findings persist into Assets / Vulnerabilities automatically.

## SecuraIQ Code (built-in SAST)
- Tool `securaiq_code`: sync connected code engine issues, or set Target to a local folder for code_scan.
- Configure engine URL/token under Settings → SecuraIQ Code.

## Quick authorized commands
```bash
# SecuraIQ Live scan: Auth + openvas on owned host
# SecuraIQ Web Scanner (built-in — New Scan → zap, or POST /api/scans with scanner=zap)
# Nuclei
nuclei -u http://192.168.56.101/ -severity critical,high
# Nmap service
nmap -sV -sC 192.168.56.101
```

Always: written scope, rate limits, detection notes, remediation owners.
"""
    return {"ok": True, "output": text}


from app.exposure import (
    HIGH_RISK_PORTS as _HIGH_RISK_PORTS,
    RISKY_PORT_NOTES as _RISKY_PORTS,
    extract_port as _extract_port,
    network_scope as _target_network_scope,
    port_dedupe_key,
    risky_port_finding as _risky_port_finding,
)

_HEADER_CHECKS = (
    "strict-transport-security",
    "content-security-policy",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy",
)


async def _tool_hardening_baseline(host: str, ip: str, open_ports: list[int] | None) -> dict[str, Any]:
    """Composite CIS-style hardening/patch-exposure baseline.

    Combines signals SecuraIQ can verify directly against any authorized
    target (TLS config, HTTP security headers, SPF/DMARC, exposed risky
    services) with patch-compliance data already ingested from any connected
    XDR/EDR vendor for this host, if that host has been seen there.
    """
    findings: list[str] = []
    passed = 0
    checked = 0

    # 1) TLS
    checked += 1
    tls_result = await _tool_tls(ip, open_ports)
    if tls_result.get("ok"):
        try:
            tls_data = json.loads(tls_result.get("output") or "{}")
        except Exception:
            tls_data = {}
        ver = tls_data.get("tls", "")
        if ver in ("TLSv1.2", "TLSv1.3"):
            passed += 1
            findings.append(f"[PASS] TLS version {ver}")
        elif ver:
            findings.append(f"[FAIL] Outdated TLS version {ver} — upgrade to TLS 1.2+")
        else:
            findings.append("[SKIP] TLS: no cert data returned")
    else:
        findings.append(f"[SKIP] TLS check failed: {tls_result.get('error', 'no HTTPS service')}")

    # 2) HTTP security headers
    urls = _guess_base_urls(ip, open_ports)[:1]
    if urls:
        r, err = await _http_get(urls[0])
        if r is not None:
            for h in _HEADER_CHECKS:
                checked += 1
                if r.headers.get(h):
                    passed += 1
                    findings.append(f"[PASS] Header present: {h}")
                else:
                    findings.append(f"[FAIL] Header missing: {h}")
        else:
            findings.append(f"[SKIP] Headers check: {err}")

    # 3) Email auth (SPF/DMARC) — only meaningful for a domain, not a bare IP
    if host and not re.match(r"^\d{1,3}(\.\d{1,3}){3}$", host):
        checked += 1
        auth_result = await _tool_email_auth(host)
        out = (auth_result.get("output") or "").lower()
        if "spf" in out and "none" not in out.split("spf")[1][:40].lower():
            passed += 1
            findings.append("[PASS] SPF record present")
        else:
            findings.append("[FAIL] SPF record missing or unresolved")
        checked += 1
        if "dmarc" in out and "none" not in out.split("dmarc")[1][:60].lower():
            passed += 1
            findings.append("[PASS] DMARC record present")
        else:
            findings.append("[FAIL] DMARC record missing or unresolved")

    # 4) Risky exposed services — probe if the caller did not already run ports
    ports = list(open_ports or [])
    if not ports:
        probe = await _tool_ports(ip, light=True)
        ports = list(probe.get("open_ports") or [])
        findings.append(f"[INFO] Auto port probe: {probe.get('output') or 'none'}")
    exposed_risky = [p for p in ports if p in _RISKY_PORTS]
    checked += 1
    scope = _target_network_scope(host, ip)
    if not exposed_risky:
        passed += 1
        findings.append("[PASS] No high-risk services in the scanned port set")
    else:
        from app.exposure import WINDOWS_LAN_PORTS

        for p in exposed_risky:
            if scope == "loopback":
                findings.append(
                    f"[FAIL] Local listener port {p}/tcp (loopback — not network-exposed) — {_RISKY_PORTS[p]}"
                )
            elif scope == "private" and p in WINDOWS_LAN_PORTS:
                # Do not fail the hardening score for expected Windows LAN listeners
                findings.append(
                    f"[INFO] Windows LAN service on port {p}/tcp (private/lab) — {_RISKY_PORTS[p]}"
                )
            elif scope == "private":
                findings.append(
                    f"[FAIL] LAN-reachable port {p}/tcp — {_RISKY_PORTS[p]}"
                )
            else:
                findings.append(f"[FAIL] Exposed risky port {p}/tcp — {_RISKY_PORTS[p]}")
        if scope == "private" and all(p in WINDOWS_LAN_PORTS for p in exposed_risky):
            passed += 1  # only lab-common Windows ports → control passes with INFO notes

    # 5) Patch compliance — pulled from whatever XDR/EDR vendors are connected
    try:
        from app.xdr import patch_compliance_summary, status as xdr_status

        vendors = xdr_status()
        active = [v for v, s in vendors.items() if s.get("configured")]
        if not active:
            findings.append(
                "[INFO] Patch compliance: no XDR/EDR vendor configured — connect Sophos, "
                "CrowdStrike, SentinelOne, or Microsoft Defender in Settings to get real "
                "missing-patch data instead of this remote heuristic baseline."
            )
        else:
            summary = patch_compliance_summary()
            host_gaps = (summary.get("by_host") or {}).get(host) or (summary.get("by_host") or {}).get(ip)
            if host_gaps:
                findings.append(f"[FAIL] Missing patches for this host (from XDR): {host_gaps}")
            else:
                findings.append(
                    f"[INFO] Patch compliance: no missing-patch data for {host or ip} yet "
                    f"({summary.get('hosts_with_gaps', 0)} other host(s) have gaps) — "
                    "run POST /api/xdr/sync or wait for the scheduled sync."
                )
    except Exception:
        findings.append("[INFO] Patch compliance: XDR module unavailable")

    score = round((passed / checked) * 100) if checked else 0
    grade = "A" if score >= 90 else "B" if score >= 75 else "C" if score >= 60 else "D" if score >= 40 else "F"
    header = f"Hardening baseline for {host or ip}: score={score}/100 (grade {grade}), {passed}/{checked} controls passed"
    return {"ok": True, "output": header + "\n" + "\n".join(findings), "score": score, "grade": grade}


# Real, published CVEs matched heuristically against service banners / server
# headers — a lightweight stand-in for nmap --script vuln / nuclei when those
# aren't installed. Conservative on purpose: only clear-text version strings,
# never a guess.
_VERSION_VULN_RULES: list[tuple[re.Pattern, str, str, str]] = [
    (re.compile(r"vsftpd 2\.3\.4", re.I), "vsftpd 2.3.4", "CVE-2011-2523",
     "Known backdoored build — a ':)' in the USER field opens a root shell on port 6200. Upgrade immediately."),
    (re.compile(r"ProFTPD 1\.3\.3", re.I), "ProFTPD 1.3.3", "CVE-2010-4221",
     "mod_copy/telnet IAC buffer overflow — remote code execution. Upgrade."),
    (re.compile(r"OpenSSH[_-]?(1\.|2\.|3\.|4\.|5\.|6\.|7\.[0-4])", re.I), "OpenSSH < 7.5", "see NVD for this build",
     "End-of-support-window OpenSSH build with multiple published CVEs — upgrade to a current maintained release."),
    (re.compile(r"Apache/2\.2\.", re.I), "Apache httpd 2.2.x", "EOL",
     "Apache httpd 2.2.x reached end-of-life in 2017 — no security patches ship for it. Upgrade to 2.4.x current."),
    (re.compile(r"Apache/2\.4\.(?:[0-9]|1[0-9]|2[0-5])\b", re.I), "Apache httpd 2.4.0-2.4.25", "CVE-2017-9798",
     "Optionsbleed (memory disclosure via OPTIONS) affects this build range — upgrade to 2.4.27+."),
    (re.compile(r"nginx/(0\.|1\.[0-9]\.|1\.1[0-2]\.)", re.I), "nginx < 1.13", "see NVD for this build",
     "Old nginx build — multiple published CVEs since this release line. Upgrade to a current stable release."),
    (re.compile(r"Microsoft-IIS/6\.0", re.I), "IIS 6.0", "CVE-2017-7269",
     "IIS 6.0 WebDAV buffer overflow, actively exploited historically — decommission or upgrade."),
    (re.compile(r"Microsoft-IIS/7\.", re.I), "IIS 7.x", "EOL",
     "IIS 7.x ships with Windows Server 2008, out of extended support — upgrade the OS/IIS."),
]


async def _tool_netvuln_scan(host: str, ip: str, open_ports: list[int] | None) -> dict[str, Any]:
    """Composite, install-free vulnerability scan: banner grab + version-CVE
    matching + TLS weaknesses + missing security headers + risky exposed
    services. Powers SecuraIQ Network Scanner (openvas) and netvuln_scan."""
    findings: list[str] = []
    matches: list[dict[str, str]] = []

    ports = list(open_ports or [])
    if not ports:
        probe = await _tool_ports(ip, light=False)
        ports = list(probe.get("open_ports") or [])
        findings.append(f"[INFO] Port probe: {probe.get('output') or 'none'}")

    # 1) Raw banners on classic cleartext ports (FTP/SSH/Telnet/SMTP)
    for p in ports:
        if p not in _BANNER_GRAB_PORTS:
            continue
        banner = await _grab_banner(ip, p)
        if not banner:
            continue
        clean = banner.splitlines()[0][:200]
        findings.append(f"[INFO] Banner {p}/tcp: {clean}")
        for pattern, product, cve, note in _VERSION_VULN_RULES:
            if pattern.search(banner):
                findings.append(f"[FAIL] {product} on port {p}/tcp ({cve}) — {note}")
                matches.append({"port": str(p), "product": product, "cve": cve, "note": note})

    # 2) Web server header fingerprint (reuse the same HTTP fetch other tools use)
    if any(p in ports for p in (80, 443, 8080, 8443)) or not ports:
        http_result = await _tool_http(ip, ports)
        for sh in re.findall(r"server=([^\s,}]+)", http_result.get("output") or ""):
            for pattern, product, cve, note in _VERSION_VULN_RULES:
                if pattern.search(sh):
                    findings.append(f"[FAIL] {product} ({cve}) — {note}")
                    matches.append({"port": "http", "product": product, "cve": cve, "note": note})

        # 3) TLS weaknesses
        if 443 in ports or 8443 in ports or not ports:
            tls_result = await _tool_tls(ip, ports)
            if tls_result.get("ok"):
                try:
                    tls_data = json.loads(tls_result.get("output") or "{}")
                except Exception:
                    tls_data = {}
                ver = tls_data.get("tls", "")
                if ver and ver not in ("TLSv1.2", "TLSv1.3"):
                    findings.append(f"[FAIL] Outdated TLS version negotiated: {ver} — disable and require TLS 1.2+")
                elif ver:
                    findings.append(f"[PASS] TLS version {ver}")

        # 4) Missing security headers
        hdr_result = await _tool_headers_security(ip, ports)
        m = re.search(r"missing=\[(.*?)\]", hdr_result.get("output") or "")
        if m and m.group(1).strip():
            findings.append(f"[FAIL] Missing HTTP security headers: {m.group(1)}")

    # 5) Risky exposed services (same table hardening_baseline uses)
    scope = _target_network_scope(host, ip)
    from app.exposure import WINDOWS_LAN_PORTS

    for p in ports:
        if p in _RISKY_PORTS:
            if scope == "loopback":
                findings.append(
                    f"[FAIL] Local listener on port {p}/tcp (loopback — not network-exposed) — {_RISKY_PORTS[p]}"
                )
            elif scope == "private" and p in WINDOWS_LAN_PORTS:
                findings.append(
                    f"[INFO] Windows LAN service on port {p}/tcp (private/lab) — {_RISKY_PORTS[p]}"
                )
            elif scope == "private":
                findings.append(
                    f"[FAIL] LAN-reachable service on port {p}/tcp — {_RISKY_PORTS[p]}"
                )
            else:
                findings.append(f"[FAIL] Exposed risky service on port {p}/tcp — {_RISKY_PORTS[p]}")

    fail_count = sum(1 for f in findings if f.startswith("[FAIL]"))
    header = (
        f"Network vulnerability scan for {host or ip}: {len(ports)} open port(s), "
        f"{fail_count} finding(s) ({len(matches)} version-matched CVE-class issue(s))"
    )
    body = "\n".join(findings) if findings else "(no issues found in the checks run)"
    return {
        "ok": True,
        "output": header + "\n" + body,
        "open_ports": ports,
        "cve_matches": matches,
    }


async def _tool_openvas(host: str, ip: str, open_ports: list[int] | None) -> dict[str, Any]:
    """SecuraIQ Network Scanner — built-in OpenVAS-class assessment (no GVM install)."""
    result = await _tool_netvuln_scan(host, ip, open_ports)
    out = result.get("output") or ""
    branded = (
        f"SecuraIQ Network Scanner (OpenVAS-class · built-in) · target {host or ip}\n"
        f"{out}"
    )
    result = dict(result)
    result["output"] = branded
    result["scanner"] = "securaiq_network"
    return result


async def _tool_zap(
    host: str,
    ip: str,
    open_ports: list[int] | None,
    *,
    authorized: bool,
    user_id: str,
    engagement_id: str | None,
    light: bool,
) -> dict[str, Any]:
    """SecuraIQ Web Scanner — built-in DAST via scan engine."""
    eng_target = (host or ip or "").strip()
    if not eng_target:
        return {"ok": False, "error": "no target", "output": ""}
    if not eng_target.startswith(("http://", "https://")):
        urls = _guess_base_urls(ip or host, open_ports)
        eng_target = urls[0] if urls else f"http://{eng_target}/"
    profile = "discovery" if light else "vulnerability"
    result = await _tool_engine_scan(
        "zap",
        eng_target,
        authorized=authorized,
        user_id=user_id,
        engagement_id=engagement_id,
        profile=profile,
        wait_sec=180.0 if light else 240.0,
    )
    out = result.get("output") or ""
    branded = dict(result)
    branded["output"] = f"SecuraIQ Web Scanner (built-in) · target {eng_target}\n{out}"
    branded["scanner"] = "securaiq_web"
    return branded


async def _tool_combo_assessment(
    target: str,
    *,
    authorized: bool,
    user_id: str,
    engagement_id: str | None = None,
    profile: str = "discovery",
    org_id: str | None = None,
) -> dict[str, Any]:
    """Single integrated VA tool — all scanners + evidence + investigate + triage."""
    from app.combo_assessment import default_scope_for_target, run_combo_assessment

    target = (target or "").strip()
    if not target:
        return {"ok": False, "error": "target required", "output": ""}
    if not authorized:
        return {
            "ok": False,
            "error": "Auth required",
            "output": "Check Auth — only assess systems you own or are authorized to test.",
        }
    prof = (profile or "discovery").lower()
    include_web = prof in {"web", "vulnerability", "full"}
    pack = await run_combo_assessment(
        user_id=user_id or "local",
        target=target,
        scope=default_scope_for_target(target),
        authorized=True,
        profile=prof,
        engagement_id=engagement_id,
        org_id=org_id,
        include_web=include_web,
        auto_triage_high=True,
    )
    if not pack.get("ok"):
        err = pack.get("error") or "combo assessment failed"
        return {
            "ok": False,
            "error": err,
            "output": err,
            "blocked": pack.get("blocked"),
        }
    summary = pack.get("summary") or {}
    scanners = ", ".join(
        s.get("scanner") or "?"
        for s in (pack.get("scans") or [])
        if s.get("ok")
    ) or "securaiq"
    lines = [
        "Integrated VA (combo_assessment) — one tool, full pipeline",
        f"target={target} · profile={prof}",
        f"scanners_ok={summary.get('scanners_ok', 0)} ({scanners})",
        f"findings={pack.get('findings_count', 0)} · high/crit={summary.get('high_critical', 0)}",
        f"triaged={summary.get('triaged', 0)}",
        f"primary_scan={pack.get('primary_scan_id')}",
        f"report={pack.get('report_url')}",
        "",
        "Evidence-backed AI prompt (use Ask AI or paste into chat):",
        (pack.get("prompt") or "")[:12000],
    ]
    return {
        "ok": True,
        "output": "\n".join(lines),
        "combo": pack,
        "scan_id": pack.get("primary_scan_id"),
        "scan_ids": pack.get("scan_ids"),
        "findings": pack.get("findings_count"),
        "prompt": pack.get("prompt"),
        "workflow": "combo_assessment",
    }


async def _tool_engine_scan(
    scanner_id: str,
    target: str,
    *,
    authorized: bool,
    user_id: str,
    engagement_id: str | None = None,
    profile: str = "discovery",
    wait_sec: float = 180.0,
) -> dict[str, Any]:
    """Queue scan_execute (Prefect when enabled) and wait for a short window."""
    from app.jobs import get_job
    from app.scan_engine.executor import enqueue_scan_job
    from app.scan_engine.models import create_scan, get_scan
    from app.scanners.registry import get_scanner

    scanner_id = (scanner_id or "securaiq").lower().strip()
    target = (target or "").strip()
    if not target:
        return {"ok": False, "error": "target required", "output": ""}
    if not authorized:
        return {
            "ok": False,
            "error": "Auth required",
            "output": "Check Auth — only scan systems you own or are authorized to assess.",
        }

    try:
        scanner = get_scanner(scanner_id)
    except Exception as exc:
        return {"ok": False, "error": str(exc), "output": ""}

    avail, avail_detail = scanner.available()
    if not avail:
        return {
            "ok": False,
            "error": "scanner_unavailable",
            "output": avail_detail or f"{scanner_id} not available",
            "scanner_unavailable": True,
        }

    scan = create_scan(
        user_id=user_id or "local",
        target=target,
        scanner=scanner_id,
        profile=profile or "discovery",
        engagement_id=engagement_id,
        authorized=True,
    )
    scan_id = scan["id"]
    job = enqueue_scan_job(scan_id)
    job_id = (job or {}).get("id")
    engine = ((job or {}).get("payload") or {}).get("_engine") or "local"

    deadline = asyncio.get_running_loop().time() + max(30.0, wait_sec)
    final = get_scan(scan_id) or scan
    while asyncio.get_running_loop().time() < deadline:
        final = get_scan(scan_id) or final
        status = (final.get("status") or "").lower()
        if status in {"completed", "failed", "blocked"}:
            break
        if job_id:
            j = get_job(job_id)
            if j and (j.get("status") or "").lower() in {"completed", "failed"}:
                final = get_scan(scan_id) or final
                if (final.get("status") or "").lower() in {"completed", "failed", "blocked"}:
                    break
        await asyncio.sleep(0.75)

    status = (final.get("status") or "unknown").lower()
    summary = final.get("summary") or {}
    if isinstance(summary, str):
        try:
            summary = json.loads(summary)
        except Exception:
            summary = {}
    findings_n = summary.get("findings_count") or summary.get("vulns") or 0
    services_n = summary.get("services_count") or summary.get("services") or 0
    err = final.get("error") or ""
    report_md = f"/api/scans/{scan_id}/report"
    report_pdf = f"/api/scans/{scan_id}/report.pdf"
    lines = [
        f"SecuraIQ scan engine · scanner={scanner_id} · profile={profile}",
        f"scan_id={scan_id} · job={job_id or '-'} · orchestration={engine}",
        f"status={status}",
    ]
    if services_n or findings_n:
        lines.append(f"services={services_n} · findings={findings_n}")
    if err:
        lines.append(f"error={err}")
    if status == "completed":
        lines.append(f"report: {report_md}")
        lines.append(f"pdf: {report_pdf}")
    elif status not in {"failed", "blocked"}:
        lines.append("still running — open Reports / scan status for the finished report")

    ok = status == "completed"
    return {
        "ok": ok,
        "output": "\n".join(lines),
        "scan_id": scan_id,
        "job_id": job_id,
        "engine": engine,
        "scanner": scanner_id,
        "status": status,
        "summary": summary,
        "report_url": report_md if ok else None,
        "report_pdf_url": report_pdf if ok else None,
        "error": err or (None if ok else status),
    }

async def _tool_securaiq_code(
    *,
    target: str,
    message: str,
    authorized: bool,
    user_id: str,
    on_progress=None,
) -> dict[str, Any]:
    """SecuraIQ Code: local folder SAST and/or sync connected code-quality engine."""
    path_candidate = (target or "").strip()
    looks_like_path = bool(
        path_candidate
        and (
            "/" in path_candidate
            or "\\" in path_candidate
            or path_candidate.endswith((".py", ".js", ".ts", ".go", ".java"))
            or Path(path_candidate).exists()
        )
    )
    lines: list[str] = ["SecuraIQ Code"]

    try:
        from app.connectors import sonarqube as sonar_conn
        from app.sonarqube import sync as sonar_sync
        from app.sonarqube import status as sonar_status
    except Exception as exc:
        sonar_conn = None  # type: ignore[assignment]
        sonar_sync = None  # type: ignore[assignment]
        sonar_status = None  # type: ignore[assignment]
        lines.append(f"Engine connector unavailable: {exc}")

    if looks_like_path:
        local = await _tool_code_scan(
            path_candidate, authorized=authorized, on_progress=on_progress
        )
        local_ok = bool(local.get("ok"))
        lines.append(local.get("output") or local.get("error") or "local scan finished")
        payload: dict[str, Any] = {
            "ok": local_ok,
            "output": "\n".join(lines),
            "scanner": "securaiq_code",
            "mode": "local_sast",
            "secret_findings": local.get("secret_findings") or [],
            "pattern_findings": local.get("pattern_findings") or [],
            "dependency_findings": local.get("dependency_findings") or [],
            "target_path": local.get("target_path") or path_candidate,
            "files_scanned": local.get("files_scanned"),
        }
        if local.get("error"):
            payload["error"] = local["error"]
        if sonar_conn and sonar_sync and sonar_conn.is_configured() and authorized:
            result = await sonar_sync(user_id or "local")
            synced = int(result.get("imported") or 0)
            lines.append(f"Engine sync: imported={synced}")
            payload["output"] = "\n".join(lines)
            payload["imported"] = synced
            payload["mode"] = "local_sast+engine_sync"
        return payload

    if sonar_conn and sonar_sync and sonar_conn.is_configured():
        if not authorized:
            lines.append(
                "Code engine is configured but Auth is off — check Auth to sync authorized projects."
            )
            return {
                "ok": False,
                "error": "auth_required",
                "output": "\n".join(lines),
                "scanner": "securaiq_code",
            }
        result = await sonar_sync(user_id or "local")
        synced = int(result.get("imported") or 0)
        st = sonar_status() if sonar_status else {}
        lines.append(
            f"Engine sync: imported={synced} · project={st.get('project_key') or 'all'} · "
            f"url={st.get('base_url') or 'configured'}"
        )
        if result.get("error"):
            lines.append(f"Sync note: {result['error']}")
        return {
            "ok": bool(result.get("ok", True)),
            "output": "\n".join(lines),
            "imported": synced,
            "scanner": "securaiq_code",
            "mode": "engine_sync",
        }

    lines.append(
        "No local folder in Target and no code engine configured.\n"
        "• Set Target to an owned local project path and Auth, or\n"
        "• Settings → SecuraIQ Code: set engine base URL + token, then run this tool or Sync."
    )
    return {
        "ok": False,
        "error": "not_configured",
        "output": "\n".join(lines),
        "scanner": "securaiq_code",
    }


async def _run_external(tool_id: str, target: str, ip: str, open_ports: list[int] | None) -> dict[str, Any]:
    spec = TOOL_CATALOG[tool_id]
    binary = resolve_binary(spec)
    if not binary:
        return {"ok": False, "error": f"{tool_id} not installed (PATH)", "output": ""}

    # Prefer hostname for HTTP(S) so TLS SNI / virtual hosts work (Cloudflare etc.).
    http_peer = target.strip() if target and not re.match(r"^\d{1,3}(?:\.\d{1,3}){3}$", target.strip()) else ip
    urls = _guess_base_urls(http_peer, open_ports) or [f"http://{http_peer}/"]
    base_http = urls[0]

    if tool_id == "nmap":
        return await _run_cmd(
            [binary, "-Pn", "-sT", "--top-ports", "40", "-T4", "--open", "--host-timeout", "18s", ip],
            timeout=28,
        )
    if tool_id == "nikto":
        return await _run_cmd([binary, "-h", base_http, "-maxtime", "20s"], timeout=30)
    if tool_id == "nuclei":
        # JSONL so findings can be persisted into the vulnerability register
        return await _run_cmd(
            [
                binary,
                "-u",
                base_http,
                "-severity",
                "critical,high,medium",
                "-silent",
                "-jsonl",
                "-timeout",
                "5",
                "-rate-limit",
                "50",
            ],
            timeout=35,
        )
    if tool_id == "whatweb":
        return await _run_cmd([binary, "-a", "1", base_http], timeout=20)
    if tool_id == "dig":
        return await _run_cmd([binary, "+short", "A", target], timeout=10)
    if tool_id == "curl":
        return await _run_cmd([binary, "-sI", "-L", "--max-time", "8", base_http], timeout=12)
    if tool_id == "sslscan":
        hostport = f"{ip}:443" if not open_ports or 443 in open_ports else f"{ip}:8443"
        return await _run_cmd([binary, "--no-colour", hostport], timeout=25)
    if tool_id == "sslyze":
        return await _run_cmd([binary, f"{ip}:443"], timeout=30)
    if tool_id == "gobuster":
        wordlist = _ensure_mini_wordlist()
        return await _run_cmd(
            [binary, "dir", "-u", base_http, "-w", str(wordlist), "-q", "-t", "20", "--timeout", "5s"],
            timeout=30,
        )
    if tool_id == "ffuf":
        wordlist = _ensure_mini_wordlist()
        return await _run_cmd(
            [binary, "-u", base_http.rstrip("/") + "/FUZZ", "-w", str(wordlist), "-mc", "200,204,301,302,403", "-t", "10", "-timeout", "5"],
            timeout=30,
        )
    if tool_id == "traceroute":
        # Windows tracert vs unix traceroute
        if binary.lower().endswith("tracert.exe") or binary.lower().endswith("tracert"):
            return await _run_cmd([binary, "-d", "-h", "8", ip], timeout=25)
        return await _run_cmd([binary, "-n", "-m", "8", ip], timeout=25)
    if tool_id == "ping":
        # Windows: -n count; Unix: -c count
        import sys
        if sys.platform.startswith("win"):
            return await _run_cmd([binary, "-n", "2", "-w", "1000", ip], timeout=8)
        return await _run_cmd([binary, "-c", "2", "-W", "1", ip], timeout=8)
    if tool_id == "openssl":
        # echo | openssl s_client -connect
        try:
            proc = await asyncio.create_subprocess_exec(
                binary, "s_client", "-connect", f"{ip}:443", "-servername", target,
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,
            )
            try:
                stdout, _ = await asyncio.wait_for(proc.communicate(input=b"Q\n"), timeout=12)
            except asyncio.TimeoutError:
                proc.kill()
                await proc.communicate()
                return {"ok": False, "error": "timed out", "output": ""}
            text = (stdout or b"").decode("utf-8", errors="replace")
            # keep certificate / protocol lines
            keep = [ln for ln in text.splitlines() if any(k in ln for k in ("Protocol", "Cipher", "subject=", "issuer=", "Verify"))]
            return {"ok": True, "output": "\n".join(keep)[:3000] or text[:2000]}
        except Exception as exc:
            return {"ok": False, "error": str(exc), "output": ""}
    if tool_id == "wafw00f":
        return await _run_cmd([binary, base_http], timeout=20)
    if tool_id == "sqlmap":
        return await _run_cmd(
            [binary, "-u", base_http, "--batch", "--level=1", "--risk=1", "--timeout=8", "--smart"],
            timeout=40,
        )
    if tool_id == "wpscan":
        return await _run_cmd([binary, "--url", base_http, "--no-update", "-e", "vp,vt"], timeout=40)
    if tool_id == "masscan":
        return await _run_cmd(
            [binary, ip, "-p1-1024,3306,3389,8080,8443", "--rate", "500", "--wait", "0"],
            timeout=25,
        )
    if tool_id == "rustscan":
        return await _run_cmd([binary, "-a", ip, "--ulimit", "5000", "-g"], timeout=25)

    return {"ok": False, "error": f"no runner for {tool_id}", "output": ""}


def _ensure_mini_wordlist() -> Path:
    path = Path(settings.chroma_persist_dir).resolve().parent / "wordlists" / "securaiq-mini.txt"
    path.parent.mkdir(parents=True, exist_ok=True)
    if not path.exists():
        path.write_text("\n".join(_DIR_WORDS) + "\n", encoding="utf-8")
    return path


# --- Code security scan (SAST) — pure Python, no semgrep/bandit/trivy install ---

_CODE_SCAN_MAX_FILES = 4000
_CODE_SCAN_MAX_FILE_BYTES = 1_500_000
_CODE_SCAN_SKIP_DIRS = {
    "node_modules", ".git", ".venv", "venv", "__pycache__", "dist", "build",
    ".next", ".pytest_cache", "site-packages", ".tox", "target", "bin", "obj",
    ".idea", ".vscode", "coverage", ".mypy_cache",
}
_CODE_SCAN_EXTS = {
    ".py", ".js", ".jsx", ".ts", ".tsx", ".java", ".go", ".rb", ".php", ".cs",
    ".cpp", ".c", ".h", ".env", ".yml", ".yaml", ".json", ".sh", ".ps1", ".tf",
}

# Detect the presence of a likely secret — never surface the matched value
# itself, only its location (matches the gitleaks adapter's own rule: strip
# the secret material out of anything persisted or returned).
_SECRET_RULES: list[tuple[str, re.Pattern]] = [
    ("aws_access_key_id", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("aws_secret_access_key", re.compile(r"(?i)aws.{0,20}(secret|access).{0,20}[:=]\s*['\"][0-9a-zA-Z/+]{40}['\"]")),
    ("private_key_block", re.compile(r"-----BEGIN (RSA|EC|DSA|OPENSSH|PGP) PRIVATE KEY-----")),
    ("slack_token", re.compile(r"xox[baprs]-[0-9A-Za-z-]{10,}")),
    ("github_token", re.compile(r"gh[pousr]_[0-9A-Za-z]{20,}")),
    ("stripe_secret_key", re.compile(r"sk_(live|test)_[0-9A-Za-z]{16,}")),
    ("generic_api_key", re.compile(r"(?i)\b(api[_-]?key|apikey)\b\s*[:=]\s*['\"][0-9a-zA-Z\-_]{16,}['\"]")),
    ("generic_secret_or_password", re.compile(r"(?i)\b(secret|password|passwd|pwd)\b\s*[:=]\s*['\"][^'\"\s]{8,}['\"]")),
    ("jwt_like_token", re.compile(r"eyJ[0-9A-Za-z_-]{10,}\.[0-9A-Za-z_-]{10,}\.[0-9A-Za-z_-]{10,}")),
]

_DANGEROUS_RULES: list[tuple[str, re.Pattern, frozenset[str], str, str]] = [
    ("py_eval_exec", re.compile(r"\b(eval|exec)\s*\("), frozenset({".py"}), "high",
     "eval()/exec() — arbitrary code execution if input is not fully trusted"),
    ("py_subprocess_shell_true", re.compile(r"subprocess\.\w+\([^)]*shell\s*=\s*True"), frozenset({".py"}), "high",
     "subprocess(..., shell=True) — command injection risk if any argument is user-influenced"),
    ("py_os_system", re.compile(r"\bos\.system\s*\("), frozenset({".py"}), "high",
     "os.system() — command injection risk; prefer subprocess with a list and shell=False"),
    ("py_pickle_load", re.compile(r"pickle\.loads?\("), frozenset({".py"}), "high",
     "pickle.load/loads — insecure deserialization; never unpickle untrusted data"),
    ("py_yaml_unsafe_load", re.compile(r"yaml\.load\((?![^)]*Loader\s*=\s*yaml\.SafeLoader)"), frozenset({".py"}), "medium",
     "yaml.load() without SafeLoader — insecure deserialization risk"),
    ("py_sql_fstring_execute", re.compile(r"(?i)\.execute\s*\(\s*f['\"]"), frozenset({".py"}), "high",
     "SQL query built with an f-string — likely SQL injection; use parameterized queries"),
    ("py_sql_percent_format", re.compile(r"(?i)\.execute\s*\(\s*['\"][^'\"]*%[sd]"), frozenset({".py"}), "high",
     "SQL query with % formatting — likely SQL injection; use parameterized queries"),
    ("py_path_traversal_join", re.compile(r"open\s*\(\s*os\.path\.join\([^)]*request"), frozenset({".py"}), "medium",
     "Path built from request input — path traversal risk; validate and resolve under a root"),
    ("js_eval", re.compile(r"\beval\s*\("), frozenset({".js", ".jsx", ".ts", ".tsx"}), "high",
     "eval() — arbitrary code execution if input is not fully trusted"),
    ("js_new_function", re.compile(r"\bnew\s+Function\s*\("), frozenset({".js", ".jsx", ".ts", ".tsx"}), "high",
     "new Function() — dynamic code execution risk if input is not fully trusted"),
    ("js_inner_html", re.compile(r"\.innerHTML\s*="), frozenset({".js", ".jsx", ".ts", ".tsx"}), "medium",
     "Direct innerHTML assignment — XSS risk if the value is not sanitized"),
    ("js_document_write", re.compile(r"document\.write\s*\("), frozenset({".js", ".jsx", ".ts", ".tsx"}), "medium",
     "document.write() — XSS risk if the argument includes untrusted data"),
    ("js_sql_string_concat", re.compile(r"(?i)(SELECT|INSERT|UPDATE|DELETE).{0,40}(\+|`\$\{)"),
     frozenset({".js", ".jsx", ".ts", ".tsx"}), "high",
     "SQL string concatenation / template — likely SQL injection; use parameterized queries"),
    ("react_dangerously_set_inner_html", re.compile(r"dangerouslySetInnerHTML"), frozenset({".jsx", ".tsx"}), "medium",
     "dangerouslySetInnerHTML — XSS risk if content is not sanitized"),
    ("hardcoded_http_url", re.compile(r"http://(?!localhost|127\.0\.0\.1|0\.0\.0\.0)[A-Za-z0-9]"),
     frozenset({".py", ".js", ".ts", ".jsx", ".tsx", ".java", ".go", ".rb", ".php", ".cs"}), "low",
     "Hardcoded plaintext HTTP URL — prefer HTTPS"),
]


def _redact(line: str, span: tuple[int, int]) -> str:
    """Never surface the actual secret value — only its location and shape."""
    start, end = span
    return (line[:start] + "\u00abredacted\u00bb" + line[end:]).strip()[:160]


async def _osv_dependency_check(root: Path, files: list[Path]) -> list[dict[str, Any]]:
    """Query OSV.dev (free, no API key) for known-vulnerable pinned dependency
    versions in requirements.txt / package.json. Best-effort — a network
    failure just skips this section, it does not fail the whole scan."""
    queries: list[dict[str, Any]] = []
    meta: list[tuple[str, str, str]] = []

    req_re = re.compile(r"^\s*([A-Za-z0-9_.\-]+)\s*==\s*([A-Za-z0-9_.\-]+)\s*$")
    for f in files:
        if len(queries) >= 80:
            break
        if f.name == "requirements.txt":
            try:
                for line in f.read_text(encoding="utf-8", errors="ignore").splitlines():
                    line = line.split("#", 1)[0].strip()
                    m = req_re.match(line)
                    if m:
                        name, ver = m.group(1), m.group(2)
                        meta.append((name, ver, "PyPI"))
                        queries.append({"package": {"name": name, "ecosystem": "PyPI"}, "version": ver})
            except Exception:
                continue
        elif f.name == "package.json":
            try:
                data = json.loads(f.read_text(encoding="utf-8", errors="ignore"))
            except Exception:
                continue
            deps: dict[str, Any] = {}
            deps.update(data.get("dependencies") or {})
            deps.update(data.get("devDependencies") or {})
            for name, spec in deps.items():
                ver = re.sub(r"^[\^~>=<\s]+", "", str(spec)).strip()
                if not re.match(r"^\d+\.\d+\.\d+", ver):
                    continue
                meta.append((name, ver, "npm"))
                queries.append({"package": {"name": name, "ecosystem": "npm"}, "version": ver})

    if not queries:
        return []
    queries = queries[:80]
    meta = meta[:80]

    try:
        timeout = httpx.Timeout(connect=3.0, read=10.0, write=3.0, pool=3.0)
        async with httpx.AsyncClient(timeout=timeout) as client:
            r = await client.post(
                "https://api.osv.dev/v1/querybatch",
                json={"queries": queries},
                headers={"User-Agent": "SecuraIQ-Tools/1.0"},
            )
            if r.status_code != 200:
                return []
            results = (r.json() or {}).get("results") or []
    except Exception:
        return []

    out: list[dict[str, Any]] = []
    for (name, ver, eco), res in zip(meta, results):
        vulns = (res or {}).get("vulns") or []
        if not vulns:
            continue
        out.append({
            "name": name,
            "version": ver,
            "ecosystem": eco,
            "count": len(vulns),
            "sample_id": vulns[0].get("id", "?"),
        })
    return out[:40]


async def _tool_code_scan(
    target_path: str,
    *,
    authorized: bool,
    on_progress=None,
) -> dict[str, Any]:
    """Static scan of a local codebase path: hardcoded secrets, dangerous
    code patterns, and known-vulnerable dependency versions. Pure Python —
    no semgrep/bandit/trivy install required."""
    if not target_path or not target_path.strip():
        return {
            "ok": False,
            "error": "No codebase path given",
            "output": (
                "Set Target to a local folder path (e.g. C:\\path\\to\\project or "
                "/home/user/project) and check Auth to confirm you own or are "
                "authorized to scan it, then run code_scan again."
            ),
        }
    # Mirrors the network-tool consent model (authorized_target) — code_scan
    # reads files off disk, so it needs the same explicit authorization,
    # especially since LAN mode has no auth by default.
    if not authorized:
        return {
            "ok": False,
            "error": "Not authorized",
            "output": (
                "code_scan reads source files on disk — check **Auth** "
                "(authorized_target) to confirm you own or are authorized to "
                "scan this path before it runs."
            ),
        }

    root = Path(target_path.strip()).expanduser()
    try:
        root = root.resolve(strict=False)
    except Exception:
        return {"ok": False, "error": "Invalid path", "output": f"Could not resolve path: {target_path}"}
    if not root.exists():
        return {"ok": False, "error": "Path not found", "output": f"No such file or directory: {root}"}

    files: list[Path] = []
    if root.is_file():
        files = [root]
    else:
        for p in root.rglob("*"):
            if len(files) >= _CODE_SCAN_MAX_FILES:
                break
            if not p.is_file():
                continue
            if any(part in _CODE_SCAN_SKIP_DIRS for part in p.parts):
                continue
            if p.suffix.lower() not in _CODE_SCAN_EXTS and p.name not in ("requirements.txt", "package.json"):
                continue
            try:
                if p.stat().st_size > _CODE_SCAN_MAX_FILE_BYTES:
                    continue
            except OSError:
                continue
            files.append(p)

    secret_findings: list[dict[str, Any]] = []
    pattern_findings: list[dict[str, Any]] = []
    scanned = 0
    budget_hit = False
    total_files = len(files)

    async def _emit_progress(rel: str = "") -> None:
        if not on_progress:
            return
        info = {
            "scanned": scanned,
            "total": total_files,
            "findings": len(secret_findings) + len(pattern_findings),
            "file": rel,
            "target_path": str(root),
        }
        try:
            maybe = on_progress(info)
            if asyncio.iscoroutine(maybe):
                await maybe
        except Exception:
            pass
        try:
            from app.realtime_bus import publish

            publish(type="tool_progress", tool="code_scan", **info)
        except Exception:
            pass
        await asyncio.sleep(0)

    await _emit_progress()
    for f in files:
        if budget_hit:
            break
        try:
            text = f.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue
        scanned += 1
        rel = str(f.relative_to(root)) if root.is_dir() else f.name
        ext = f.suffix.lower()
        for lineno, line in enumerate(text.splitlines(), start=1):
            for rule_id, pattern in _SECRET_RULES:
                m = pattern.search(line)
                if m:
                    secret_findings.append(
                        {"rule": rule_id, "file": rel, "line": lineno, "context": _redact(line, m.span())}
                    )
            for rule_id, pattern, exts, sev, note in _DANGEROUS_RULES:
                if ext not in exts:
                    continue
                if pattern.search(line):
                    pattern_findings.append(
                        {
                            "rule": rule_id, "file": rel, "line": lineno, "severity": sev,
                            "note": note, "context": line.strip()[:160],
                        }
                    )
            if len(secret_findings) + len(pattern_findings) >= 300:
                budget_hit = True
                break
        if scanned == 1 or scanned % 40 == 0 or scanned == total_files or budget_hit:
            await _emit_progress(rel)

    dep_findings = await _osv_dependency_check(root, files)

    findings_lines: list[str] = []
    for s in secret_findings[:60]:
        findings_lines.append(f"[FAIL] Possible {s['rule']} in {s['file']}:{s['line']} — {s['context']}")
    for p in pattern_findings[:80]:
        findings_lines.append(f"[FAIL] {p['rule']} ({p['severity']}) in {p['file']}:{p['line']} — {p['note']}")
    for d in dep_findings[:40]:
        plural = "y" if d["count"] == 1 else "ies"
        findings_lines.append(
            f"[FAIL] Vulnerable dependency {d['name']}@{d['version']} ({d['ecosystem']}) — "
            f"{d['count']} known advisor{plural}, e.g. {d['sample_id']}"
        )

    header = (
        f"Code security scan of {root}: {scanned} file(s) scanned, "
        f"{len(secret_findings)} possible secret(s), {len(pattern_findings)} risky pattern(s), "
        f"{len(dep_findings)} vulnerable dependenc{'y' if len(dep_findings) == 1 else 'ies'}"
    )
    body = "\n".join(findings_lines) if findings_lines else "(clean — no issues found in the checks run)"
    return {
        "ok": True,
        "output": header + "\n" + body,
        "secret_findings": secret_findings,
        "pattern_findings": pattern_findings,
        "dependency_findings": dep_findings,
        "target_path": str(root),
        "files_scanned": scanned,
    }


async def _tool_semgrep(
    target_path: str,
    *,
    authorized: bool,
    on_progress=None,
) -> dict[str, Any]:
    """Real Semgrep SAST run against a local codebase path. Semgrep is
    pip-installable (unlike nmap/nuclei/etc.), so this genuinely invokes the
    `semgrep` binary via subprocess when present on PATH — it does not fake
    or approximate results. When semgrep isn't installed, this returns clear
    install guidance instead of a stub result; `code_scan` covers the same
    codebase with zero-install checks (secrets, dangerous patterns,
    vulnerable dependencies) in the meantime."""
    if not target_path or not target_path.strip():
        return {
            "ok": False,
            "error": "No codebase path given",
            "output": (
                "Set Target to a local folder path (e.g. C:\\path\\to\\project or "
                "/home/user/project) and check Auth to confirm you own or are "
                "authorized to scan it, then run semgrep again."
            ),
        }
    if not authorized:
        return {
            "ok": False,
            "error": "Not authorized",
            "output": (
                "semgrep reads source files on disk — check **Auth** "
                "(authorized_target) to confirm you own or are authorized to "
                "scan this path before it runs."
            ),
        }

    root = Path(target_path.strip()).expanduser()
    try:
        root = root.resolve(strict=False)
    except Exception:
        return {"ok": False, "error": "Invalid path", "output": f"Could not resolve path: {target_path}"}
    if not root.exists():
        return {"ok": False, "error": "Path not found", "output": f"No such file or directory: {root}"}

    binary = shutil.which("semgrep")
    if not binary:
        return {
            "ok": False,
            "error": "semgrep not installed (PATH)",
            "output": (
                "Semgrep isn't on PATH. Install it with `pip install semgrep` "
                "(or `pipx install semgrep`) then run this tool again — SecuraIQ "
                "will invoke the real `semgrep --config=auto` scanner. In the "
                "meantime, `code_scan` covers hardcoded secrets, dangerous "
                "patterns, and known-vulnerable dependencies for this same "
                "path with no install required."
            ),
        }

    async def _emit(scanned: int, total: int, findings: int) -> None:
        if not on_progress:
            return
        try:
            maybe = on_progress(
                {"scanned": scanned, "total": total, "findings": findings, "target_path": str(root)}
            )
            if asyncio.iscoroutine(maybe):
                await maybe
        except Exception:
            pass

    await _emit(0, 0, 0)
    try:
        proc = await asyncio.create_subprocess_exec(
            binary,
            "--config=auto",
            "--json",
            "--timeout",
            "60",
            "--max-target-bytes",
            "2000000",
            str(root),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=150)
        except asyncio.TimeoutError:
            proc.kill()
            await proc.communicate()
            return {"ok": False, "error": "semgrep timed out", "output": ""}
    except Exception as exc:
        return {"ok": False, "error": str(exc), "output": ""}

    raw_text = (stdout or b"").decode("utf-8", errors="replace")
    # Found via live testing: semgrep can exit non-zero with EMPTY stdout (e.g.
    # its rule-registry fetch is blocked by a proxy/firewall) while still
    # writing a real error to stderr. Treating empty stdout as "{}" silently
    # reported that as a clean 0-finding scan — a false "it worked" instead
    # of the real failure. Empty/malformed output is always an error now,
    # never a default-to-clean result.
    if not raw_text.strip():
        err_tail = (stderr or b"").decode("utf-8", errors="replace").strip()
        return {
            "ok": False,
            "error": f"semgrep produced no output (exit code {proc.returncode})",
            "output": err_tail[-1500:] if err_tail else "semgrep exited with no output and no error detail.",
        }
    try:
        data = json.loads(raw_text)
    except Exception:
        err_tail = (stderr or b"").decode("utf-8", errors="replace")[-800:]
        return {
            "ok": False,
            "error": "Could not parse semgrep output",
            "output": err_tail or raw_text[-800:] or "semgrep produced no output",
        }
    if not isinstance(data, dict) or "results" not in data:
        return {
            "ok": False,
            "error": "Unexpected semgrep output shape",
            "output": raw_text[:800],
        }

    results = data.get("results") or []
    scan_errors = data.get("errors") or []
    scanned_paths = (data.get("paths") or {}).get("scanned") or []

    findings_lines: list[str] = []
    for r in results[:80]:
        extra = r.get("extra") or {}
        sev = extra.get("severity") or "WARNING"
        msg = extra.get("message") or r.get("check_id") or "finding"
        line_no = (r.get("start") or {}).get("line")
        findings_lines.append(
            f"[{sev}] {r.get('check_id')} in {r.get('path')}:{line_no} — {msg}"[:300]
        )

    header = (
        f"Semgrep scan of {root}: {len(scanned_paths)} file(s) scanned, "
        f"{len(results)} finding(s)"
    )
    if scan_errors:
        header += f", {len(scan_errors)} rule error(s)"
    body = "\n".join(findings_lines) if findings_lines else "(clean — no issues found by the ruleset run)"

    await _emit(len(scanned_paths), len(scanned_paths), len(results))

    return {
        "ok": True,
        "output": header + "\n" + body,
        "target_path": str(root),
        "files_scanned": len(scanned_paths),
        "semgrep_results": results,
        "scanner": "semgrep",
    }


async def _tool_codeql() -> dict[str, Any]:
    """Report real CodeQL CLI presence and next-step commands. CodeQL needs a
    per-language database build before it can analyze anything, so there's no
    single safe generic invocation for an arbitrary repo/target — this tool
    is honest about that instead of faking a scan result. Actual automated
    CodeQL coverage of SecuraIQ's own repo runs via the `codeql` job in
    .github/workflows/security-scan.yml (github/codeql-action) on every push."""
    codeql_bin = shutil.which("codeql")
    if codeql_bin:
        return {
            "ok": True,
            "output": (
                f"CodeQL CLI found at {codeql_bin}. Build + analyze this repo:\n"
                "  1) codeql database create <db-dir> --language=<python|javascript|...> "
                "--source-root=<path>\n"
                "  2) codeql database analyze <db-dir> <query-pack, e.g. codeql/python-queries> "
                "--format=sarif-latest --output=results.sarif\n"
                "  3) Import results.sarif under Vulnerabilities (Import scanner results).\n"
                "SecuraIQ also runs real CodeQL automatically against its own repo on every "
                "push via the `codeql` job in .github/workflows/security-scan.yml — see the "
                "repo's GitHub Security tab for those results."
            ),
            "scanner": "codeql",
            "mode": "cli_detected",
        }
    return {
        "ok": False,
        "error": "codeql CLI not installed (PATH)",
        "output": (
            "CodeQL CLI isn't on PATH. Install from "
            "https://github.com/github/codeql-action/releases (bundle includes CLI + "
            "query packs), or rely on the automated `codeql` GitHub Actions job already "
            "wired into .github/workflows/security-scan.yml, which scans this repo on "
            "every push with no local install needed. `semgrep` and `code_scan` also "
            "cover this codebase locally right now."
        ),
        "scanner": "codeql",
    }


async def iter_security_tools(
    message: str,
    *,
    target: str | None = None,
    tools: list[str] | None = None,
    authorized: bool = False,
    allow_public: bool = False,
    auto: bool = False,
    include_heavy: bool = False,
    mode: str | None = None,
    user_id: str = "local",
    engagement_id: str | None = None,
):
    """Yield realtime progress events; light builtins run in parallel."""
    if not settings.local_tools_enabled:
        yield {"event": "done", "payload": {"ok": False, "error": "Local tools disabled", "runs": []}}
        return

    tool_ids = parse_tool_request(
        message,
        explicit=tools,
        auto=auto,
        include_heavy=include_heavy,
        mode=mode,
    )
    if not tool_ids:
        yield {"event": "done", "payload": {"ok": False, "error": "No tools selected", "runs": []}}
        return

    # Early engagement existence / lifecycle check (full scope gate after resolve)
    if engagement_id:
        from app.workspace import get_engagement

        eng = get_engagement(user_id, engagement_id)
        if not eng:
            yield {
                "event": "done",
                "payload": {
                    "ok": False,
                    "error": "Engagement not found or not visible to this user",
                    "runs": [],
                    "requested": tool_ids,
                },
            }
            return
        st = (eng.get("status") or "active").lower()
        if st in {"archived", "completed"}:
            yield {
                "event": "done",
                "payload": {
                    "ok": False,
                    "error": f"Engagement is '{st}' — reopen or choose an active engagement before scanning",
                    "runs": [],
                    "requested": tool_ids,
                },
            }
            return

    awareness_only = all(
        tid in {
            "phishing_url",
            "email_auth",
            "suite_guide",
            "cve_lookup",
            "defender_hunt",
            "code_scan",
            "securaiq_code",
            "semgrep",
            "codeql",
            "siem_sync",
            "xdr_sync",
            "thehive_sync",
            "inventory_sync",
        }
        for tid in tool_ids
    )
    # Path-based SAST tools must not be DNS-resolved as hostnames.
    path_tools = {"code_scan", "securaiq_code", "semgrep", "codeql"}
    using_path_tools = bool(path_tools.intersection(tool_ids))
    code_scan_path = (target or "").strip() if using_path_tools else ""
    skip_net_target = using_path_tools and (
        not target
        or "/" in (target or "")
        or "\\" in (target or "")
        or (bool((target or "").strip()) and Path((target or "").strip()).exists())
    )
    # When only path/SAST tools run, never treat words from the prompt (e.g. "scan code …")
    # as network hosts — extract_targets() matches `scan <token>` and would DNS-fail.
    if skip_net_target and set(tool_ids).issubset(path_tools | {"suite_guide", "cve_lookup", "phishing_url"}):
        targets = []
    else:
        targets = extract_targets(message, None if skip_net_target else target)
        if skip_net_target:
            # Drop non-path junk extracted from the message (e.g. host hint "code")
            targets = [
                t
                for t in targets
                if t == (target or "").strip()
                or "/" in t
                or "\\" in t
                or Path(t).exists()
            ]
    if "email_auth" in tool_ids and not targets:
        for m in _DOMAIN_RE.finditer(message or ""):
            d = m.group(0).lower()
            if d not in {"example.com", "localhost"} and not d.endswith(".local"):
                targets = [d]
                break
    if target and not targets and not skip_net_target:
        targets = [target.strip()]

    needs_target = any(TOOL_CATALOG[t].needs_target for t in tool_ids if t in TOOL_CATALOG)
    if needs_target and not targets:
        non_target = [t for t in tool_ids if t in TOOL_CATALOG and not TOOL_CATALOG[t].needs_target]
        if non_target:
            tool_ids = non_target
            targets = []
        else:
            yield {
                "event": "done",
                "payload": {
                    "ok": False,
                    "error": "No target IP/host — set Target IP or include an address in the message",
                    "runs": [],
                    "requested": tool_ids,
                },
            }
            return

    runs: list[dict[str, Any]] = []
    open_ports: list[int] = []
    meta = None
    ip = ""
    host = ""
    if targets:
        host = targets[0]
        if awareness_only and "email_auth" in tool_ids:
            meta = {"ok": True, "ip": "", "private": None}
            ip = ""
        else:
            meta = resolve_and_authorize(
                host,
                authorized=authorized or awareness_only,
                allow_public=allow_public or awareness_only,
            )
            if not meta.get("ok"):
                soft = [t for t in tool_ids if t in {"phishing_url", "suite_guide", "cve_lookup", "defender_hunt"}]
                if soft and not any(TOOL_CATALOG[t].needs_target for t in soft):
                    tool_ids = soft
                    host = ""
                    meta = None
                else:
                    yield {
                        "event": "done",
                        "payload": {
                            "ok": False,
                            "error": meta.get("error") or "Target not authorized",
                            "runs": [],
                            "requested": tool_ids,
                            "target": host,
                        },
                    }
                    return
            else:
                ip = meta.get("ip") or ""
                # resolve_and_authorize returns the cleaned host (scheme/path
                # stripped) when the raw target was a full URL — use that for
                # every downstream tool (e.g. email_auth's domain lookup)
                # instead of the raw URL string.
                host = meta.get("target") or host

    # Engagement structured scope gate (deterministic — AI cannot bypass)
    policy_meta: dict[str, Any] | None = None
    if engagement_id and (host or code_scan_path or target):
        from app.services.tool_policy import assert_tool_target_allowed

        try:
            policy_meta = assert_tool_target_allowed(
                user_id=user_id,
                engagement_id=engagement_id,
                target=code_scan_path or target or host,
                ip=ip or None,
                authorized=authorized,
            )
        except ValueError as exc:
            yield {
                "event": "done",
                "payload": {
                    "ok": False,
                    "error": str(exc),
                    "runs": [],
                    "requested": tool_ids,
                    "target": host or target,
                    "engagement_id": engagement_id,
                },
            }
            return

    ordered = sorted(tool_ids, key=lambda t: 0 if t == "ports" else 1)
    light_mode = not include_heavy
    progress_q: asyncio.Queue = asyncio.Queue()

    async def _progress_cb(tid: str, info: dict[str, Any]) -> None:
        evt = {"event": "tool_progress", "tool": tid, **info}
        try:
            await progress_q.put(evt)
        except Exception:
            pass

    async def _execute(tid: str, ports_hint: list[int]) -> dict[str, Any]:
        spec = TOOL_CATALOG.get(tid)
        if not spec:
            return {"tool": tid, "name": tid, "ok": False, "error": "unknown tool", "output": ""}
        entry: dict[str, Any] = {"tool": tid, "name": spec.name, "kind": spec.kind, "heavy": spec.heavy}

        async def on_progress(info: dict[str, Any]) -> None:
            await _progress_cb(tid, info)

        try:
            if tid == "cve_lookup":
                result = await _tool_cve_lookup(message)
            elif tid == "defender_hunt":
                result = await _tool_defender_hunt(message)
            elif tid == "siem_sync":
                result = await _tool_siem_sync(user_id or "local")
            elif tid == "xdr_sync":
                result = await _tool_xdr_sync(user_id or "local")
            elif tid == "thehive_sync":
                result = await _tool_thehive_sync(user_id or "local")
            elif tid == "inventory_sync":
                result = await _tool_inventory_sync(user_id or "local")
            elif tid == "phishing_url":
                result = await _tool_phishing_url(message)
            elif tid == "suite_guide":
                result = await _tool_suite_guide()
            elif tid == "email_auth":
                domain = host if host and not re.match(r"^\d{1,3}(\.\d{1,3}){3}$", host) else ""
                if not domain:
                    m = _DOMAIN_RE.search(message or "")
                    domain = m.group(0) if m else (target or "")
                result = await _tool_email_auth(domain or host or "")
            elif tid == "code_scan":
                # Path-based, not IP-based — bypasses the network target gate below.
                result = await _tool_code_scan(
                    code_scan_path or target or "",
                    authorized=authorized,
                    on_progress=on_progress,
                )
            elif tid == "securaiq_code":
                result = await _tool_securaiq_code(
                    target=code_scan_path or target or host or "",
                    message=message or "",
                    authorized=bool(authorized),
                    user_id=user_id or "local",
                    on_progress=on_progress,
                )
            elif tid == "semgrep":
                # Path-based, like code_scan — bypasses the network target gate below.
                result = await _tool_semgrep(
                    code_scan_path or target or "",
                    authorized=authorized,
                    on_progress=on_progress,
                )
            elif tid == "codeql":
                result = await _tool_codeql()
            elif not ip and spec.needs_target:
                result = {"ok": False, "error": "no target", "output": ""}
            elif tid == "ports":
                result = await _tool_ports(ip, light=light_mode)
            elif tid == "dns":
                result = await _tool_dns(host, ip)
            elif tid == "http":
                result = await _tool_http(ip, ports_hint)
            elif tid == "headers_security":
                result = await _tool_headers_security(ip, ports_hint)
            elif tid == "tls":
                result = await _tool_tls(ip, ports_hint)
            elif tid == "robots":
                result = await _tool_robots(ip, ports_hint)
            elif tid == "tech":
                result = await _tool_tech(ip, ports_hint)
            elif tid == "whois":
                result = await _tool_whois(host, ip)
            elif tid == "hardening_baseline":
                result = await _tool_hardening_baseline(host, ip, ports_hint)
            elif tid == "netvuln_scan":
                result = await _tool_netvuln_scan(host, ip, ports_hint)
            elif tid == "openvas":
                result = await _tool_openvas(host, ip, ports_hint)
            elif tid == "zap":
                result = await _tool_zap(
                    host,
                    ip,
                    ports_hint,
                    authorized=bool(authorized),
                    user_id=user_id or "local",
                    engagement_id=engagement_id,
                    light=light_mode,
                )
            elif tid in {"combo_assessment", "combo", "integrated_va"}:
                eng_target = host or ip or (target or "").strip()
                result = await _tool_combo_assessment(
                    eng_target,
                    authorized=bool(authorized),
                    user_id=user_id or "local",
                    engagement_id=engagement_id,
                    profile="vulnerability" if not light_mode else "discovery",
                )
            elif tid == "securaiq" or tid in ENGINE_TOOLS:
                scanner_key = ENGINE_TOOLS.get(tid, "securaiq")
                eng_target = host or ip or (target or "").strip()
                if scanner_key == "combo_assessment":
                    result = await _tool_combo_assessment(
                        eng_target,
                        authorized=bool(authorized),
                        user_id=user_id or "local",
                        engagement_id=engagement_id,
                        profile="discovery" if light_mode else "vulnerability",
                    )
                else:
                    result = await _tool_engine_scan(
                        scanner_key,
                        eng_target,
                        authorized=bool(authorized),
                        user_id=user_id or "local",
                        engagement_id=engagement_id,
                        profile="discovery" if light_mode else "vulnerability",
                    )
                if result.get("scanner_unavailable") and tid != "securaiq":
                    if not is_available(tid):
                        fb = EXTERNAL_FALLBACKS.get(tid)
                        if fb and fb in TOOL_CATALOG:
                            fb_entry = await _execute(fb, ports_hint)
                            note = (
                                f"{spec.name} engine/PATH unavailable — ran builtin "
                                f"`{fb}` instead.\n\n"
                            )
                            result = {
                                "ok": fb_entry.get("ok"),
                                "output": note + (fb_entry.get("output") or ""),
                                "error": fb_entry.get("error"),
                                "fallback_to": fb,
                                "open_ports": fb_entry.get("open_ports"),
                                "findings": fb_entry.get("findings"),
                            }
                        else:
                            result = {
                                "ok": False,
                                "error": "not installed on PATH",
                                "output": (
                                    f"{spec.name} is not available via scan engine or PATH. "
                                    "Use tool `securaiq` or install the binary."
                                ),
                            }
                    else:
                        result = await _run_external(tid, host, ip, ports_hint)
            elif tid == "hardeningkitty":
                # HardeningKitty has no PATH binary (binaries=()) — it runs via a
                # dedicated Windows/PowerShell module, not a generic subprocess.
                # Route to the real flow instead of falling through to
                # _run_external, which would always report "not installed (PATH)"
                # even when the module is actually detected.
                from app.hardeningkitty import is_installed as _hk_installed

                if _hk_installed():
                    result = {
                        "ok": True,
                        "output": (
                            "HardeningKitty module detected. Run it from Frameworks → "
                            "Windows hardening → \"Run HardeningKitty audit\" "
                            "(POST /api/hardeningkitty/audit), or import an existing "
                            "Audit report CSV under Vulnerabilities — it is not run "
                            "through the generic tool runner because it writes "
                            "findings straight into the database."
                        ),
                    }
                else:
                    result = {
                        "ok": False,
                        "error": "HardeningKitty module not found",
                        "output": (
                            "Set the module path in Settings → Windows hardening (CIS), "
                            "or install HardeningKitty, then use Frameworks → "
                            "Windows hardening → Run HardeningKitty audit."
                        ),
                    }
            elif spec.kind == "external":
                if not is_available(tid):
                    fb = EXTERNAL_FALLBACKS.get(tid)
                    if fb and fb in TOOL_CATALOG:
                        fb_entry = await _execute(fb, ports_hint)
                        note = (
                            f"{spec.name} (`{tid}`) is not installed on PATH — "
                            f"ran builtin `{fb}` instead so the PT workflow still produces evidence.\n"
                            f"Install `{tid}` (or rebuild the Docker image) for the real scanner.\n\n"
                        )
                        out = fb_entry.get("output") or ""
                        result = {
                            "ok": bool(fb_entry.get("ok")),
                            "error": "" if fb_entry.get("ok") else (fb_entry.get("error") or "fallback failed"),
                            "output": note + str(out),
                            "fallback_from": tid,
                            "fallback_to": fb,
                            "open_ports": fb_entry.get("open_ports"),
                            "findings": fb_entry.get("findings"),
                        }
                    else:
                        result = {
                            "ok": False,
                            "error": "not installed on PATH",
                            "output": (
                                f"{spec.name} is not installed. Use New scan (SecuraIQ scanner) "
                                f"or install the binary and ensure it is on PATH."
                            ),
                        }
                else:
                    result = await _run_external(tid, host, ip, ports_hint)
            else:
                result = {"ok": False, "error": "unknown tool", "output": ""}
        except Exception as exc:
            result = {"ok": False, "error": str(exc), "output": ""}
        # Parse nuclei JSONL before truncating chat output (persist needs full rows)
        if tid == "nuclei" and result.get("ok") and isinstance(result.get("output"), str):
            result["findings"] = _parse_nuclei_jsonl(result["output"])
        if isinstance(result.get("output"), str) and len(result["output"]) > 2500:
            result["output"] = result["output"][:2500] + "\n…(truncated)"
        entry.update(result)
        return entry

    display_target = host or code_scan_path or (target or "").strip() or None
    yield {
        "event": "start",
        "target": display_target,
        "ip": ip or None,
        "tools": ordered,
        "light": light_mode,
    }

    rest = list(ordered)
    # Found via live end-to-end testing: any tool whose _run_external branch
    # calls _guess_base_urls() picks its target port from `open_ports`. Only
    # the builtin HTTP-family tools were in this set, so running e.g. curl or
    # nikto *by themselves* (without also requesting `ports` or one of the
    # builtins) left open_ports == [] and _guess_base_urls() silently guessed
    # https://ip/ or http://ip/ (80/443) — wrong for any service on a
    # non-standard port (8080, 8443, 3000, ...), even though a port probe
    # would have found it. Every external tool that depends on the guessed
    # base URL now triggers the same implicit port pre-scan.
    _NEEDS_PORT_DISCOVERY = {
        "ports",
        "hardening_baseline",
        "netvuln_scan",
        "openvas",
        "http",
        "headers_security",
        "tls",
        "robots",
        "tech",
        "curl",
        "nikto",
        "nuclei",
        "whatweb",
        "gobuster",
        "ffuf",
        "zap",
        "sqlmap",
        "wpscan",
        "wafw00f",
    }
    needs_ports = ip and any(t in _NEEDS_PORT_DISCOVERY for t in rest)
    if needs_ports:
        rest = [t for t in rest if t != "ports"]
        yield {"event": "tool_start", "tool": "ports", "name": "Port probe"}
        _publish_tool_pulse(
            kind="ports",
            status="running",
            user_id=user_id,
            target=str(ip or target or "")[:120],
            message="Port probe running",
        )
        entry = await _execute("ports", open_ports)
        open_ports = entry.get("open_ports") or open_ports
        runs.append(entry)
        yield {"event": "tool_done", "run": entry}

    light_ids = [
        t
        for t in rest
        if t in TOOL_CATALOG and TOOL_CATALOG[t].kind == "builtin" and not TOOL_CATALOG[t].heavy
    ]
    heavy_ids = [t for t in rest if t not in light_ids]
    sem = asyncio.Semaphore(4)

    async def _guarded(tid: str) -> dict[str, Any]:
        async with sem:
            return await _execute(tid, open_ports)

    if light_ids:
        for tid in light_ids:
            yield {
                "event": "tool_start",
                "tool": tid,
                "name": TOOL_CATALOG[tid].name if tid in TOOL_CATALOG else tid,
            }
            _publish_tool_pulse(
                kind=tid,
                status="running",
                user_id=user_id,
                target=str(target or "")[:120],
                tools=light_ids,
                message=f"{TOOL_CATALOG[tid].name if tid in TOOL_CATALOG else tid} running",
            )
        tasks = [asyncio.create_task(_guarded(tid)) for tid in light_ids]
        for fut in asyncio.as_completed(tasks):
            while True:
                try:
                    evt = progress_q.get_nowait()
                    yield evt
                except asyncio.QueueEmpty:
                    break
            entry = await fut
            runs.append(entry)
            yield {"event": "tool_done", "run": entry}

    for tid in heavy_ids:
        yield {
            "event": "tool_start",
            "tool": tid,
            "name": TOOL_CATALOG[tid].name if tid in TOOL_CATALOG else tid,
        }
        _publish_tool_pulse(
            kind=tid,
            status="running",
            user_id=user_id,
            target=str(target or "")[:120],
            message=f"{TOOL_CATALOG[tid].name if tid in TOOL_CATALOG else tid} running",
        )
        task = asyncio.create_task(_execute(tid, open_ports))
        while not task.done():
            try:
                evt = await asyncio.wait_for(progress_q.get(), timeout=0.25)
                yield evt
            except asyncio.TimeoutError:
                continue
        while True:
            try:
                evt = progress_q.get_nowait()
                yield evt
            except asyncio.QueueEmpty:
                break
        entry = await task
        if tid == "ports":
            open_ports = entry.get("open_ports") or open_ports
        runs.append(entry)
        yield {"event": "tool_done", "run": entry}

    ok_any = any(r.get("ok") for r in runs)
    resolved_path = ""
    for r in runs:
        if r.get("target_path"):
            resolved_path = str(r["target_path"])
            break
    effective_target = host or resolved_path or code_scan_path or (target or "").strip() or None
    fp = hashlib.sha1(f"{effective_target or ''}:{ip}:{','.join(tool_ids)}".encode()).hexdigest()[:10]
    payload: dict[str, Any] = {
        "ok": ok_any,
        "target": effective_target,
        "ip": ip or None,
        "private": (meta or {}).get("private"),
        "ptr": (meta or {}).get("ptr"),
        "requested": tool_ids,
        "open_ports": open_ports,
        "runs": runs,
        "light": light_mode,
        "fingerprint": fp,
        "authorized": bool(authorized or (meta or {}).get("private")),
        "engagement_id": engagement_id,
        "scope_policy": policy_meta,
    }
    # Persist real findings into vulnerabilities when the scan was authorized / private-lab
    if payload.get("authorized") and ok_any:
        try:
            persisted = persist_tool_findings_to_vulns(
                user_id or "local",
                payload,
            )
            payload["vulnerabilities_persisted"] = persisted
        except Exception as exc:  # noqa: BLE001
            payload["vulnerabilities_persisted"] = {"ok": False, "error": str(exc)[:200]}
    # Audit trail — every completed tool run (including code_scan reading local
    # files, and any authorized-target network probe) gets a record: who ran
    # what, against what target, with what outcome. Previously only account/
    # data-mutation actions were audited; tool execution had no trail at all.
    try:
        from app.db import audit as _audit_log

        _audit_log(
            "tool_run",
            user_id or "local",
            {
                "tools": tool_ids,
                "target": effective_target,
                "ip": ip or None,
                "authorized": payload.get("authorized"),
                "ok": ok_any,
                "fingerprint": fp,
            },
        )
    except Exception:
        pass
    try:
        from app.realtime_bus import publish

        findings_n = int((payload.get("vulnerabilities_persisted") or {}).get("created") or 0)
        publish(
            type="tool",
            kind="security_tools",
            status="done" if ok_any else "error",
            tools=tool_ids,
            target=str(effective_target or "")[:120],
            findings=findings_n,
            user_id=user_id or "local",
            message=(
                f"{', '.join(tool_ids[:4])} finished"
                + (f" · {findings_n} finding(s)" if findings_n else "")
            ),
        )
        if findings_n:
            publish(
                type="vuln_batch",
                source="local_tools",
                count=findings_n,
                target=str(effective_target or "")[:120],
                user_id=user_id or "local",
            )
    except Exception:
        pass
    yield {"event": "done", "payload": payload}


def _parse_nuclei_jsonl(output: str) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for line in (output or "").splitlines():
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
        elif isinstance(classification, list):
            for cls in classification:
                if isinstance(cls, str) and cls.upper().startswith("CVE-"):
                    cve = cls.upper()
                    break
        if not cve:
            for m in _CVE_RE.finditer(json.dumps(row)[:2000]):
                cve = m.group(0).upper()
                break
        matched = row.get("matched-at") or row.get("host") or row.get("ip") or ""
        host_label = str(matched)
        if host_label.startswith("http://") or host_label.startswith("https://"):
            try:
                from app.scanners.nuclei import _hostname_from_target

                host_label = _hostname_from_target(host_label) or host_label
            except Exception:
                pass
        findings.append(
            {
                "title": str(title)[:300],
                "severity": sev if sev in {"critical", "high", "medium", "low", "info"} else "medium",
                "cve": cve[:40],
                "asset_name": host_label[:200],
                "source": f"nuclei:{row.get('template-id') or row.get('template_id') or 'scan'}",
                "raw": row,
            }
        )
    return findings[:80]


def persist_tool_findings_to_vulns(user_id: str, payload: dict[str, Any]) -> dict[str, Any]:
    """Turn authorized tool output into real vulnerability rows (not chat-only).

    Cross-tool dedupe: the same risky port from ports + openvas + hardening_baseline
    becomes one finding. Private Windows LAN ports (135/139/445) are info-severity.
    """
    from app.asset_names import canonical_vuln_asset_name, resolve_target_labels
    from app.enterprise import ensure_asset_for_target, list_vulnerabilities, upsert_vulnerability

    target = payload.get("target") or payload.get("ip") or "unknown"
    ip = str(payload.get("ip") or "") or None
    ptr = str(payload.get("ptr") or "") or None
    labels = resolve_target_labels(str(target), ptr=ptr, resolve_ptr=True)
    notes = json.dumps(
        {
            "source": "live_tools",
            "ip": labels["ip"] or ip or "",
            "hostname": labels["hostname"],
            "host": labels["host"],
            "tools": payload.get("requested") or [],
        }
    )[:2000]
    asset = None
    try:
        asset = ensure_asset_for_target(
            user_id,
            labels["asset_name"],
            notes=notes,
            resolve_ptr=True,
        )
    except Exception:
        asset = None
    target_display = canonical_vuln_asset_name(labels["asset_name"], asset=asset if isinstance(asset, dict) else None)

    existing = {
        ((v.get("title") or "").strip().lower(), (v.get("asset_name") or "").strip().lower())
        for v in list_vulnerabilities(user_id)
    }
    # Also remember ports already filed for this asset (prior scans + this run)
    seen_ports: set[tuple[str, int]] = set()
    for v in list_vulnerabilities(user_id):
        raw = v.get("raw") or {}
        if isinstance(raw, str):
            try:
                import json as _json

                raw = _json.loads(raw)
            except Exception:
                raw = {}
        if isinstance(raw, dict) and raw.get("port") is not None:
            try:
                seen_ports.add(port_dedupe_key(v.get("asset_name") or target, int(raw["port"])))
            except (TypeError, ValueError):
                pass
        else:
            p = _extract_port(v.get("title") or "")
            if p is not None:
                seen_ports.add(port_dedupe_key(v.get("asset_name") or target, p))

    to_create: list[dict[str, Any]] = []

    def _claim_risky_port(port: int, source: str) -> dict[str, Any] | None:
        """Return canonical finding once per (asset, port); None if duplicate."""
        key = port_dedupe_key(str(target), port)
        if key in seen_ports:
            return None
        seen_ports.add(key)
        item = _risky_port_finding(port, target=target_display, source=source, ip=ip)
        item["asset_name"] = target_display[:200]
        tkey = (item["title"].lower(), target_display.lower())
        if tkey in existing:
            return None
        existing.add(tkey)
        return item

    for run in payload.get("runs") or []:
        if not run.get("ok"):
            continue
        tid = run.get("tool") or ""
        out = run.get("output") or ""

        if tid == "nuclei":
            parsed = run.get("findings") if isinstance(run.get("findings"), list) else _parse_nuclei_jsonl(out)
            for f in parsed:
                if not isinstance(f, dict):
                    continue
                if not f.get("asset_name"):
                    f["asset_name"] = target_display[:200]
                else:
                    f["asset_name"] = canonical_vuln_asset_name(str(f["asset_name"]), asset=asset if isinstance(asset, dict) else None)
                key = (str(f.get("title") or "").lower(), (f.get("asset_name") or "").lower())
                if key in existing:
                    continue
                existing.add(key)
                to_create.append(f)

        elif tid in {"nmap", "ports"}:
            ports = run.get("open_ports")
            if not isinstance(ports, list):
                ports = []
                for line in out.splitlines():
                    m = re.match(r"^(\d+)/tcp\s+open\b", line.strip())
                    if m:
                        ports.append(int(m.group(1)))
            for p in ports or []:
                if p not in _RISKY_PORTS:
                    continue
                item = _claim_risky_port(int(p), f"{tid}:port-{p}")
                if item:
                    to_create.append(item)

        elif tid == "hardening_baseline":
            for line in out.splitlines():
                if not line.strip().startswith("[FAIL]"):
                    continue
                msg = line.strip()[6:].strip()
                port = _extract_port(msg)
                if port is not None and port in _RISKY_PORTS:
                    item = _claim_risky_port(port, "hardening_baseline")
                    if item:
                        to_create.append(item)
                    continue
                title = f"Hardening gap: {msg}"[:300]
                key = (title.lower(), str(target).lower())
                if key in existing:
                    continue
                existing.add(key)
                scope = _target_network_scope(str(target), ip)
                if scope == "loopback" and any(x in msg.lower() for x in ("smb", "rdp", "port")):
                    sev = "info"
                elif any(x in msg.lower() for x in ("tls", "rdp", "smb", "patch")):
                    sev = "high" if scope == "public" else ("info" if scope == "private" else "medium")
                else:
                    sev = "medium" if scope != "private" else "low"
                to_create.append(
                    {
                        "title": title,
                        "severity": sev,
                        "asset_name": target_display[:200],
                        "source": "hardening_baseline",
                        "raw": {"line": line, "scope": scope},
                    }
                )

        elif tid in {"netvuln_scan", "openvas"}:
            matched_products = {m.get("product") for m in (run.get("cve_matches") or []) if m.get("product")}
            for cm in run.get("cve_matches") or []:
                title = f"{cm.get('product')} — {cm.get('cve')}"[:300]
                key = (title.lower(), str(target).lower())
                if key in existing:
                    continue
                existing.add(key)
                cve_val = str(cm.get("cve") or "")
                to_create.append(
                    {
                        "title": title,
                        "cve": cve_val if cve_val.upper().startswith("CVE-") else "",
                        "severity": "critical" if "backdoor" in (cm.get("note") or "").lower() else "high",
                        "asset_name": target_display[:200],
                        "source": "securaiq_network" if tid == "openvas" else "netvuln_scan",
                        "raw": cm,
                    }
                )
            for line in out.splitlines():
                if not line.strip().startswith("[FAIL]"):
                    continue
                msg = line.strip()[6:].strip()
                if any(msg.startswith(prod) for prod in matched_products):
                    continue
                port = _extract_port(msg)
                if port is not None and port in _RISKY_PORTS:
                    item = _claim_risky_port(port, "securaiq_network" if tid == "openvas" else "netvuln_scan")
                    if item:
                        to_create.append(item)
                    continue
                title = f"Network finding: {msg}"[:300]
                key = (title.lower(), str(target).lower())
                if key in existing:
                    continue
                existing.add(key)
                scope = _target_network_scope(str(target), ip)
                if scope == "loopback" and any(x in msg.lower() for x in ("smb", "rdp", "risky", "port")):
                    sev = "info"
                elif any(x in msg.lower() for x in ("tls", "rdp", "smb", "risky", "backdoor")):
                    sev = "high" if scope == "public" else "info" if scope == "private" else "medium"
                else:
                    sev = "medium" if scope != "private" else "low"
                to_create.append(
                    {
                        "title": title,
                        "severity": sev,
                        "asset_name": target_display[:200],
                        "source": "securaiq_network" if tid == "openvas" else "netvuln_scan",
                        "raw": {"line": line, "scope": scope},
                    }
                )

        elif tid in {"code_scan", "securaiq_code"}:
            code_target = run.get("target_path") or str(target)
            code_source = "securaiq_code" if tid == "securaiq_code" else "code_scan"
            for s in run.get("secret_findings") or []:
                title = f"Possible hardcoded secret ({s.get('rule')}) in {s.get('file')}"[:300]
                key = (title.lower(), str(code_target).lower())
                if key in existing:
                    continue
                existing.add(key)
                to_create.append(
                    {
                        "title": title,
                        "severity": "high",
                        "asset_name": str(code_target)[:200],
                        "source": code_source,
                        "raw": {
                            "file": s.get("file"),
                            "line": s.get("line"),
                            "rule": s.get("rule"),
                            "context": s.get("context"),
                        },
                    }
                )
            for p in run.get("pattern_findings") or []:
                title = f"{p.get('rule')} in {p.get('file')}"[:300]
                key = (title.lower(), str(code_target).lower())
                if key in existing:
                    continue
                existing.add(key)
                to_create.append(
                    {
                        "title": title,
                        "severity": p.get("severity") or "medium",
                        "asset_name": str(code_target)[:200],
                        "source": code_source,
                        "raw": p,
                    }
                )
            for d in run.get("dependency_findings") or []:
                title = f"Vulnerable dependency: {d.get('name')}@{d.get('version')} ({d.get('ecosystem')})"[:300]
                key = (title.lower(), str(code_target).lower())
                if key in existing:
                    continue
                existing.add(key)
                to_create.append(
                    {
                        "title": title,
                        "severity": "high" if (d.get("count") or 0) >= 3 else "medium",
                        "asset_name": str(code_target)[:200],
                        "source": code_source,
                        "raw": d,
                    }
                )

        elif tid == "semgrep":
            code_target = run.get("target_path") or str(target)
            from app.scanner_adapters import parse_semgrep

            semgrep_results = run.get("semgrep_results") or []
            for item in parse_semgrep(semgrep_results, engagement_id=None, filename=str(code_target)):
                title = str(item.get("title") or "Semgrep finding")[:300]
                key = (title.lower(), str(code_target).lower())
                if key in existing:
                    continue
                existing.add(key)
                item["asset_name"] = str(code_target)[:200]
                to_create.append(item)

        elif tid == "nikto":
            # Nikto text: "+ OSVDB-…" / "+ CVE-…" style lines — capture CVE hits
            for m in _CVE_RE.finditer(out):
                cve = m.group(0).upper()
                title = f"Nikto finding referencing {cve}"
                key = (title.lower(), str(target).lower())
                if key in existing:
                    continue
                existing.add(key)
                to_create.append(
                    {
                        "title": title,
                        "cve": cve,
                        "severity": "medium",
                        "asset_name": target_display[:200],
                        "source": "nikto",
                        "raw": {"cve": cve},
                    }
                )

    created = []
    # Real-time: emit `vuln` updates so the Vulns page refreshes while tools run
    for item in to_create[:100]:
        if asset and asset.get("id") and not item.get("asset_id"):
            item["asset_id"] = asset["id"]
        if asset and asset.get("name") and not item.get("asset_name"):
            item["asset_name"] = asset["name"]
        created.append(upsert_vulnerability(user_id, item, emit_realtime=True))
    if created:
        try:
            from app.realtime_bus import publish

            publish(
                type="vuln_batch",
                source=(
                    "securaiq_code"
                    if any(r.get("tool") in {"code_scan", "securaiq_code", "semgrep"} for r in (payload.get("runs") or []))
                    else "local_tools"
                ),
                count=len(created),
                target=str(target)[:120],
                user_id=user_id,
            )
        except Exception:
            pass
    return {
        "ok": True,
        "created": len(created),
        "asset_id": (asset or {}).get("id"),
        "asset_name": (asset or {}).get("name") or target_display[:200],
        "titles": [c.get("title") for c in created[:15]],
    }


async def run_security_tools(
    message: str,
    *,
    target: str | None = None,
    tools: list[str] | None = None,
    authorized: bool = False,
    allow_public: bool = False,
    auto: bool = False,
    include_heavy: bool = False,
    mode: str | None = None,
    user_id: str = "local",
    engagement_id: str | None = None,
) -> dict[str, Any]:
    final: dict[str, Any] | None = None
    async for ev in iter_security_tools(
        message,
        target=target,
        tools=tools,
        authorized=authorized,
        allow_public=allow_public,
        auto=auto,
        include_heavy=include_heavy,
        mode=mode,
        user_id=user_id,
        engagement_id=engagement_id,
    ):
        if ev.get("event") == "done":
            final = ev.get("payload")
    return final or {"ok": False, "error": "No tool output", "runs": []}



def format_tools_context(payload: dict[str, Any]) -> str:
    runs = payload.get("runs") or []
    if not runs:
        err = payload.get("error") or "No tool output"
        return (
            "## Local security tools\n"
            f"No runs ({err}). Built-in tools work without installs; "
            "install nmap/nuclei/nikto/etc. on PATH for deeper scans.\n"
            "Ask e.g. `run nmap and http on 192.168.56.101` (authorized lab only)."
        )

    lines = [
        "## Local security tools output (authorized / lab scope)",
        f"Target: `{payload.get('target')}` → `{payload.get('ip')}` · private={payload.get('private')}",
        f"Requested: {', '.join(payload.get('requested') or [])}",
        "Use this evidence for findings, CVE mapping, verify commands, detection, and remediation.",
        "",
    ]
    vp = payload.get("vulnerabilities_persisted") or {}
    if vp.get("created") or vp.get("asset_id"):
        bits = []
        if vp.get("asset_name") or vp.get("asset_id"):
            bits.append(f"asset `{vp.get('asset_name') or vp.get('asset_id')}`")
        if vp.get("created"):
            bits.append(
                f"**{vp['created']} finding(s)** into Vulnerabilities (source=local_tools)"
            )
        else:
            bits.append("inventory asset registered (no new findings)")
        lines.append("**Live inventory:** " + " · ".join(bits) + " — open Assets / Vulnerabilities / Mission Control.")
        lines.append("")
    for r in runs:
        status = "OK" if r.get("ok") else "FAIL"
        lines.append(f"### {r.get('name', r.get('tool'))} [{status}]")
        if r.get("error"):
            lines.append(f"- Error: {r['error']}")
        if r.get("open_ports") is not None:
            lines.append(f"- Open ports: {r['open_ports']}")
        out = (r.get("output") or "").strip()
        if out:
            lines.append("```")
            lines.append(out[-3500:])
            lines.append("```")
        lines.append("")
    return "\n".join(lines)
