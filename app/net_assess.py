"""Authorized local/lab network vulnerability assessment (passive + light probes)."""

from __future__ import annotations

import asyncio
import ipaddress
import re
import shutil
import socket
import ssl
from typing import Any

import httpx

from app.config import settings

_IP_RE = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
)
_HOST_HINT_RE = re.compile(
    r"\b(?:target|host|ip|scan|assess)\s*[:=]?\s*([A-Za-z0-9_.-]+)\b",
    re.IGNORECASE,
)

# Fast common service ports for lab/HTB/THM style targets
COMMON_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995,
    1433, 1521, 2049, 3000, 3306, 3389, 5432, 5900, 5985, 6379,
    8009, 8080, 8180, 8443, 9200, 27017,
]

PORT_HINTS = {
    21: "FTP — check anonymous / banner",
    22: "SSH — version / weak creds in labs",
    23: "Telnet — cleartext auth risk",
    25: "SMTP — open relay / info leak",
    53: "DNS — zone transfer / version",
    80: "HTTP — enum paths, headers, CMS",
    110: "POP3",
    135: "MSRPC — Windows",
    139: "NetBIOS",
    143: "IMAP",
    443: "HTTPS — TLS, cert, vulns",
    445: "SMB — EternalBlue / shares (lab)",
    1433: "MSSQL",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5985: "WinRM",
    6379: "Redis — unauth risk",
    8080: "HTTP-alt",
    8443: "HTTPS-alt",
    9200: "Elasticsearch",
}


def extract_targets(text: str, explicit: str | None = None) -> list[str]:
    found: list[str] = []
    if explicit and explicit.strip():
        found.append(explicit.strip())
    for m in _IP_RE.finditer(text or ""):
        found.append(m.group(0))
    _HINT_STOP = {
        "target", "host", "ip", "scan", "assess", "the", "a", "an", "my",
        "code", "folder", "path", "local", "repo", "project", "with", "for",
        "this", "that", "using", "run", "check", "probe",
    }
    for m in _HOST_HINT_RE.finditer(text or ""):
        host = m.group(1).strip(".,;:")
        if host.lower() not in _HINT_STOP and not host.lower().endswith((".py", ".js", ".ts", ".go", ".java", ".json")):
            found.append(host)
    # de-dupe
    seen: set[str] = set()
    out: list[str] = []
    for item in found:
        key = item.lower()
        if key not in seen:
            seen.add(key)
            out.append(item)
    return out[:3]


def _is_lab_or_private(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    return bool(
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_reserved
    )


def resolve_and_authorize(
    target: str,
    *,
    authorized: bool,
    allow_public: bool = False,
) -> dict[str, Any]:
    target = (target or "").strip()
    if not target:
        return {"ok": False, "error": "No target"}

    # Real bug found live: a plain https:// URL (https://example.com/,
    # https://example.com/login) contains "/" from its scheme and path, and
    # was being misread as CIDR notation and rejected outright with a
    # confusing "CIDR/ranges not supported" error — so web URL scans never
    # got past target resolution. Extract just the host when a URL scheme is
    # present; anything else containing "/" (no scheme) is still treated as
    # a CIDR/range and rejected, same as before.
    scheme_match = re.match(r"^[a-zA-Z][a-zA-Z0-9+.\-]*://", target)
    if scheme_match:
        host_part = target[scheme_match.end():]
        host_part = host_part.split("/", 1)[0].split("?", 1)[0].split("#", 1)[0]
        host_part = host_part.rsplit("@", 1)[-1]  # drop userinfo@ if present
        if host_part.startswith("["):
            host_part = host_part.split("]")[0].lstrip("[")
        else:
            host_part = host_part.split(":")[0]
        host_part = host_part.strip()
        if not host_part:
            return {"ok": False, "error": "Could not extract a host from that URL"}
        target = host_part
    elif "/" in target:
        return {"ok": False, "error": "CIDR/ranges not supported — use a single host, IP, or URL"}

    try:
        infos = socket.getaddrinfo(target, None, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        return {"ok": False, "error": f"DNS/resolve failed: {exc}"}

    ips: list[str] = []
    for info in infos:
        addr = info[4][0]
        if addr not in ips:
            ips.append(addr)

    if not ips:
        return {"ok": False, "error": "No addresses resolved"}

    primary = ips[0]
    try:
        ip_obj = ipaddress.ip_address(primary)
    except ValueError:
        return {"ok": False, "error": f"Invalid IP {primary}"}

    private = _is_lab_or_private(ip_obj)
    if not private and not (authorized and allow_public):
        return {
            "ok": False,
            "error": (
                f"`{target}` resolves to public IP `{primary}`. "
                "SecuraIQ only probes lab/private ranges (RFC1918 / loopback) by default. "
                "For a host you own on a public IP, enable **Authorized target** and confirm ownership."
            ),
            "ip": primary,
            "public": True,
        }
    if not private and not authorized:
        return {
            "ok": False,
            "error": "Public IP requires the Authorized target confirmation.",
            "ip": primary,
            "public": True,
        }

    return {
        "ok": True,
        "target": target,
        "ip": primary,
        "all_ips": ips,
        "private": private,
        "ptr": _ptr_lookup(primary),
    }


def _ptr_lookup(ip: str) -> str | None:
    try:
        name, _, _ = socket.gethostbyaddr(ip)
        return name
    except (socket.herror, socket.gaierror, OSError):
        return None


async def _probe_port(ip: str, port: int, timeout: float = 0.35) -> bool:
    try:
        conn = asyncio.open_connection(ip, port)
        reader, writer = await asyncio.wait_for(conn, timeout=timeout)
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        del reader
        return True
    except Exception:
        return False


async def _banner_tcp(ip: str, port: int, timeout: float = 0.8) -> str:
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout=timeout)
        try:
            if port in (80, 8080, 8000, 8888):
                writer.write(b"HEAD / HTTP/1.0\r\nHost: " + ip.encode() + b"\r\n\r\n")
                await writer.drain()
            data = await asyncio.wait_for(reader.read(256), timeout=timeout)
            return data.decode("utf-8", errors="replace").strip()[:200]
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
    except Exception:
        return ""


async def _http_fingerprint(ip: str, ports: list[int]) -> list[dict[str, str]]:
    out: list[dict[str, str]] = []
    timeout = httpx.Timeout(connect=0.8, read=2.0, write=1.0, pool=1.0)
    schemes = []
    if 443 in ports or 8443 in ports:
        schemes.append(("https", 443 if 443 in ports else 8443))
    if 80 in ports or 8080 in ports:
        schemes.append(("http", 80 if 80 in ports else 8080))
    async with httpx.AsyncClient(timeout=timeout, follow_redirects=True, verify=False) as client:
        for scheme, port in schemes[:2]:
            url = f"{scheme}://{ip}:{port}/"
            try:
                r = await client.get(url)
                server = r.headers.get("server", "")
                title = ""
                m = re.search(r"<title[^>]*>(.*?)</title>", r.text[:8000], re.I | re.S)
                if m:
                    title = re.sub(r"\s+", " ", m.group(1)).strip()[:120]
                out.append(
                    {
                        "url": str(r.url),
                        "status": str(r.status_code),
                        "server": server,
                        "title": title,
                        "powered_by": r.headers.get("x-powered-by", ""),
                    }
                )
            except Exception as exc:
                out.append({"url": url, "error": str(exc)[:160]})
    return out


def _tls_summary(ip: str, port: int = 443) -> dict[str, str] | None:
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((ip, port), timeout=1.2) as sock:
            with ctx.wrap_socket(sock, server_hostname=ip) as ssock:
                cert = ssock.getpeercert()
                if not cert:
                    # binary form
                    return {"port": str(port), "tls": ssock.version() or "unknown", "note": "cert details unavailable"}
                sub = dict(x[0] for x in cert.get("subject", ()))
                iss = dict(x[0] for x in cert.get("issuer", ()))
                return {
                    "port": str(port),
                    "tls": ssock.version() or "",
                    "subject": sub.get("commonName", ""),
                    "issuer": iss.get("commonName", ""),
                    "notAfter": cert.get("notAfter", ""),
                }
    except Exception:
        return None


async def _run_nmap(ip: str) -> dict[str, Any] | None:
    nmap = shutil.which("nmap")
    if not nmap:
        return None
    cmd = [
        nmap,
        "-Pn",
        "-sT",
        "--top-ports",
        "40",
        "-T4",
        "--open",
        "--host-timeout",
        "20s",
        ip,
    ]
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=28)
        except asyncio.TimeoutError:
            proc.kill()
            await proc.communicate()
            return {"tool": "nmap", "error": "timed out"}
        text = (stdout or b"").decode("utf-8", errors="replace")
        err = (stderr or b"").decode("utf-8", errors="replace")
        return {"tool": "nmap", "output": text[-4000:], "stderr": err[-500:] if err else ""}
    except Exception as exc:
        return {"tool": "nmap", "error": str(exc)}


async def assess_target(
    target: str,
    *,
    authorized: bool = False,
    allow_public: bool = False,
    use_nmap: bool = True,
) -> dict[str, Any]:
    meta = resolve_and_authorize(target, authorized=authorized, allow_public=allow_public)
    if not meta.get("ok"):
        return {"target": target, **meta, "open_ports": [], "findings": []}

    ip = meta["ip"]
    # Parallel port probes
    results = await asyncio.gather(*[_probe_port(ip, p) for p in COMMON_PORTS])
    open_ports = [p for p, ok in zip(COMMON_PORTS, results) if ok]

    banners: dict[str, str] = {}
    for port in open_ports[:8]:
        if port in (21, 22, 25, 80, 110, 143, 8080):
            ban = await _banner_tcp(ip, port)
            if ban:
                banners[str(port)] = ban

    http_info = await _http_fingerprint(ip, open_ports)
    tls = None
    if 443 in open_ports:
        tls = await asyncio.to_thread(_tls_summary, ip, 443)
    elif 8443 in open_ports:
        tls = await asyncio.to_thread(_tls_summary, ip, 8443)

    nmap_data = None
    if use_nmap:
        nmap_data = await _run_nmap(ip)

    findings: list[str] = []
    for port in open_ports:
        hint = PORT_HINTS.get(port, "Review service version and known CVEs")
        findings.append(f"Port {port}/tcp open — {hint}")
    if not open_ports:
        findings.append("No common ports responded (host filtered/down, or non-standard ports).")
    for h in http_info:
        if h.get("server"):
            findings.append(f"HTTP Server header: `{h['server']}` — check version CVEs")
        if h.get("title"):
            findings.append(f"Web title: {h['title']}")
    if tls and tls.get("notAfter"):
        findings.append(f"TLS cert CN={tls.get('subject')} issuer={tls.get('issuer')} expires={tls.get('notAfter')}")

    return {
        "ok": True,
        "target": meta["target"],
        "ip": ip,
        "all_ips": meta.get("all_ips") or [ip],
        "private": meta.get("private"),
        "ptr": meta.get("ptr"),
        "open_ports": open_ports,
        "banners": banners,
        "http": http_info,
        "tls": tls,
        "nmap": nmap_data,
        "findings": findings,
        "note": "Passive/light lab probe only. Expand with full nmap/nuclei in your engagement scope.",
    }


async def assess_from_request(
    message: str,
    *,
    target: str | None = None,
    authorized: bool = False,
    allow_public: bool = False,
    # Optional: when provided and `authorized=True`, persist Assets/Vulns to the register
    # so the UI updates via realtime SSE (same mechanism as other tool findings).
    user_id: str | None = None,
) -> dict[str, Any]:
    targets = extract_targets(message, target)
    if not targets:
        return {
            "ok": False,
            "error": "No IP/hostname found. Set Target IP or include an address like 192.168.1.10 / 10.10.x.x.",
            "results": [],
        }
    # Public allow only when user checked authorized
    results = []
    for t in targets:
        res = await assess_target(
            t,
            authorized=authorized,
            allow_public=allow_public and authorized,
            use_nmap=settings.net_assess_use_nmap,
        )
        results.append(res)

        # Persist "network scan" output as live Assets/Vulns (authorized scope only)
        if user_id and authorized and res.get("ok"):
            try:
                await _persist_net_assessment(user_id, res)
            except Exception:
                # Network assess should never break chat flow if persistence fails
                pass
    any_ok = any(r.get("ok") for r in results)
    return {
        "ok": any_ok,
        "targets": targets,
        "results": results,
        "error": None if any_ok else (results[0].get("error") if results else "Assessment failed"),
    }


async def _persist_net_assessment(user_id: str, assessment: dict[str, Any]) -> None:
    """Persist network probe results as live findings + inventory.

    Goal: "network scan" updates Assets/Vulnerabilities in realtime (no demo/canned UI),
    matching the behavior of scan-engine and local tool pipelines.
    """

    from app.enterprise import ensure_asset_for_target, upsert_vulnerability
    from app.exposure import risky_port_finding

    target = str(assessment.get("target") or assessment.get("ip") or "unknown")[:200]
    ip = assessment.get("ip")
    open_ports = assessment.get("open_ports") or []

    # Register asset first so findings show under the correct inventory entry
    ensure_asset_for_target(
        user_id,
        target,
        notes="Live network assess (net_assess) · passive/light probes",
        asset_type="host",
    )

    ports = [p for p in open_ports if isinstance(p, int)]
    ports = ports[:50]

    if ports:
        # Single discovery finding (dedupes by fixed title+source for non-port-id findings).
        upsert_vulnerability(
            user_id,
            {
                "title": f"Open ports discovered on {target}",
                "severity": "info",
                "asset_name": target,
                "source": "securaiq:discovery",
                "raw": {"ports": ports, "ip": ip},
            },
            emit_realtime=True,
        )

    # One finding per port (dedupes by stable finding identity: asset+port).
    for p in ports:
        item = risky_port_finding(
            int(p),
            target=target,
            source="securaiq:net_assess",
            ip=str(ip) if ip else None,
        )
        # Add light evidence for UI detail view
        item.setdefault("raw", {}).update({"evidence": f"{p}/tcp open (net_assess)"})
        upsert_vulnerability(user_id, item, emit_realtime=True)


def format_assess_context(payload: dict[str, Any]) -> str:
    results = payload.get("results") or []
    if not results:
        err = payload.get("error") or "No assessment"
        return (
            "## Network vulnerability assessment\n"
            f"Skipped / empty: {err}\n"
            "Ask the user for a lab/private IP (or enable Authorized target for owned hosts)."
        )

    lines = [
        "## Live network vulnerability assessment (authorized / lab scope)",
        "Use these probe results to prioritize service enumeration, CVE checks, and next steps.",
        "Always include detection + remediation. Stay on in-scope hosts only.",
        "",
    ]
    for r in results:
        if not r.get("ok"):
            lines.append(f"### Target `{r.get('target', '?')}` — blocked/failed")
            lines.append(f"- {r.get('error', 'unknown error')}")
            lines.append("")
            continue
        lines.append(f"### Target `{r.get('target')}` → `{r.get('ip')}`")
        if r.get("ptr"):
            lines.append(f"- PTR: `{r['ptr']}`")
        lines.append(f"- Private/lab range: `{r.get('private')}`")
        ports = r.get("open_ports") or []
        lines.append(f"- Open common ports: `{', '.join(map(str, ports)) if ports else 'none'}`")
        for finding in r.get("findings") or []:
            lines.append(f"- Finding: {finding}")
        banners = r.get("banners") or {}
        for port, ban in banners.items():
            lines.append(f"- Banner {port}: ```{ban[:180]}```")
        for h in r.get("http") or []:
            if h.get("error"):
                lines.append(f"- HTTP error ({h.get('url')}): {h['error']}")
            else:
                lines.append(
                    f"- HTTP {h.get('status')} `{h.get('url')}` server=`{h.get('server','')}` title=`{h.get('title','')}`"
                )
        if r.get("tls"):
            tls = r["tls"]
            lines.append(
                f"- TLS: {tls.get('tls')} CN={tls.get('subject')} issuer={tls.get('issuer')} notAfter={tls.get('notAfter')}"
            )
        nmap = r.get("nmap")
        if nmap:
            if nmap.get("error"):
                lines.append(f"- nmap: {nmap['error']}")
            elif nmap.get("output"):
                lines.append("- nmap output:")
                lines.append("```")
                lines.append(nmap["output"][-2500:])
                lines.append("```")
        lines.append("")
    lines.append(
        "Produce a structured assessment: asset summary → open services → likely vulns/CVEs → "
        "manual verify commands → detection → remediation / patch priority."
    )
    return "\n".join(lines)
