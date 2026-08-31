"""SecuraIQ Web Scanner — built-in DAST (no ZAP daemon or install required).

Pure-Python HTTP checks: security headers, cookies, sensitive paths, CORS,
technology disclosure, and light reflection probes. Output is ZAP-compatible JSON
for the existing ``ZapScanner`` parse/normalize pipeline.
"""

from __future__ import annotations

import asyncio
import json
import re
import ssl
import socket
from pathlib import Path
from typing import Any
from urllib.parse import quote, urljoin, urlparse

import httpx

from app.scanners.nuclei import _hostname_from_target

_SECURITY_HEADERS = (
    ("strict-transport-security", "Strict-Transport-Security Missing", "2", "10035"),
    ("content-security-policy", "Content Security Policy Missing", "2", "10038"),
    ("x-frame-options", "Missing Anti-clickjacking Header", "1", "10020"),
    ("x-content-type-options", "X-Content-Type-Options Missing", "1", "10021"),
    ("referrer-policy", "Referrer Policy Not Set", "0", "10027"),
    ("permissions-policy", "Permissions Policy Not Set", "0", "10063"),
)

_DISCOVERY_PATHS = ("robots.txt", "sitemap.xml")
_VULN_PATHS = (
    ".env",
    ".git/HEAD",
    "phpinfo.php",
    "server-status",
    "actuator/health",
    "wp-login.php",
    "admin",
    "login",
    "api/swagger.json",
    "debug",
)

_CANARY = "SecuraIQCanary7x"


def _alert(
    name: str,
    *,
    riskcode: str,
    riskdesc: str,
    pluginid: str,
    url: str = "",
) -> dict[str, Any]:
    return {
        "name": name,
        "riskcode": riskcode,
        "riskdesc": riskdesc,
        "pluginid": pluginid,
        "instances": [{"uri": url}] if url else [{}],
    }


def _risk_label(code: str) -> str:
    return {"3": "High", "2": "Medium", "1": "Low", "0": "Informational"}.get(code, "Informational")


# Maps this scanner's real internal checkpoints onto the generic phase list
# every scan uses (app/scan_engine/models.py DEFAULT_PROGRESS). Real UI bug
# found live: app/scan_engine/executor.py marks "discovery" and "port_scan"
# both "active" once, right before the single opaque `await scanner.execute()`
# call, and only flips them to "done" after it returns — for a web/DAST scan
# that single call can run 1-6 minutes (see _TIMEOUT in app/scanners/zap.py),
# so the "New scan" modal's phase list just sat frozen the whole time even
# though this scanner was actively working through real checkpoints
# internally (and already publishing them over the realtime bus). Advancing
# the DB-persisted progress here means both the live SSE push AND the
# polling `GET /api/scans/{id}` (which the modal reads via
# applyScanRecordToUi -> renderScanSteps) show real forward motion.
_WEB_STEP_SEQUENCE = ("discovery", "port_scan", "service_detect", "collecting")
_DB_STEP_FOR_EVENT = {
    "web_fetch": "discovery",
    "web_headers": "port_scan",
    "web_paths": "service_detect",
    "web_active": "collecting",
}


async def _emit(scan_id: str | None, step: str, *, pct: int | None = None) -> None:
    if not scan_id:
        return
    try:
        from app.realtime_bus import publish

        payload: dict[str, Any] = {
            "type": "scan",
            "id": scan_id,
            "step": step,
            "status": "active",
            "scanner": "securaiq_web",
        }
        if pct is not None:
            payload["pct"] = pct
        publish(**payload)
    except Exception:
        pass
    try:
        from app.scan_engine.models import set_progress

        if step == "web_done":
            for sid in _WEB_STEP_SEQUENCE:
                set_progress(scan_id, sid, "done")
            return
        mapped = _DB_STEP_FOR_EVENT.get(step)
        if mapped:
            idx = _WEB_STEP_SEQUENCE.index(mapped)
            for prior in _WEB_STEP_SEQUENCE[:idx]:
                set_progress(scan_id, prior, "done")
            set_progress(scan_id, mapped, "active")
    except Exception:
        pass


async def _fetch(
    client: httpx.AsyncClient,
    url: str,
    *,
    headers: dict[str, str] | None = None,
) -> tuple[httpx.Response | None, str]:
    try:
        r = await client.get(url, headers=headers or {"User-Agent": "SecuraIQ-WebScanner/1.0"})
        return r, ""
    except Exception as exc:
        return None, str(exc)


def _tls_probe(hostname: str, port: int = 443) -> dict[str, str]:
    out: dict[str, str] = {}
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((hostname, port), timeout=3.0) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                out["tls_version"] = ssock.version() or ""
                cert = ssock.getpeercert() or {}
                out["not_after"] = str(cert.get("notAfter") or "")
    except Exception as exc:
        out["error"] = str(exc)
    return out


async def run_builtin_web_scan(
    *,
    target_url: str,
    profile: str,
    evidence_dir: Path,
    scan_id: str | None = None,
    timeout_sec: float = 120.0,
) -> dict[str, Any]:
    """Run install-free web assessment; writes ``zap.json`` evidence."""
    evidence_dir.mkdir(parents=True, exist_ok=True)
    prof = (profile or "web").lower()
    deep = prof in {"vulnerability", "full"}
    base_url = target_url.rstrip("/") + "/"
    host = _hostname_from_target(target_url) or target_url
    alerts: list[dict[str, Any]] = []
    trace: list[dict[str, Any]] = []
    timeout = httpx.Timeout(connect=2.0, read=8.0, write=4.0, pool=4.0)
    deadline = asyncio.get_running_loop().time() + max(30.0, timeout_sec)

    async def _log(step: str, detail: Any = None) -> None:
        trace.append({"step": step, "detail": detail})

    await _emit(scan_id, "web_fetch", pct=0)
    async with httpx.AsyncClient(timeout=timeout, follow_redirects=True, verify=False) as client:
        resp, err = await _fetch(client, base_url)
        await _log("fetch.base", {"url": base_url, "error": err, "status": getattr(resp, "status_code", None)})
        if resp is None:
            alerts.append(
                _alert(
                    f"Target unreachable: {err or 'no response'}",
                    riskcode="2",
                    riskdesc="Medium",
                    pluginid="seciq-0001",
                    url=base_url,
                )
            )
        else:
            hdr = {k.lower(): v for k, v in resp.headers.items()}
            final_url = str(resp.url)
            await _emit(scan_id, "web_headers", pct=15)

            for header, title, code, plugin in _SECURITY_HEADERS:
                if not hdr.get(header):
                    alerts.append(
                        _alert(
                            title,
                            riskcode=code,
                            riskdesc=_risk_label(code),
                            pluginid=plugin,
                            url=final_url,
                        )
                    )

            server = hdr.get("server") or hdr.get("x-powered-by")
            if server:
                alerts.append(
                    _alert(
                        f"Server technology disclosure: {server[:120]}",
                        riskcode="0",
                        riskdesc="Informational",
                        pluginid="seciq-1000",
                        url=final_url,
                    )
                )

            cookies = resp.headers.get_list("set-cookie") if hasattr(resp.headers, "get_list") else []
            if not cookies and hdr.get("set-cookie"):
                cookies = [hdr["set-cookie"]]
            missing_flags = False
            missing_samesite = False
            for ck in cookies:
                low = ck.lower()
                if "httponly" not in low or ("secure" not in low and final_url.startswith("https")):
                    missing_flags = True
                if "samesite" not in low:
                    missing_samesite = True
            if missing_flags:
                alerts.append(
                    _alert(
                        "Cookie without Secure/HttpOnly flags",
                        riskcode="1",
                        riskdesc="Low",
                        pluginid="seciq-1002",
                        url=final_url,
                    )
                )
            if missing_samesite:
                alerts.append(
                    _alert(
                        "Cookie without SameSite attribute (CSRF exposure)",
                        riskcode="1",
                        riskdesc="Low",
                        pluginid="seciq-1006",
                        url=final_url,
                    )
                )

            body_sample = (resp.text or "")[:50000].lower()
            if re.search(r"(stack trace|syntax error|mysql_|postgresql|sqlite_|exception in)", body_sample):
                alerts.append(
                    _alert(
                        "Verbose error / stack trace in HTTP response",
                        riskcode="2",
                        riskdesc="Medium",
                        pluginid="seciq-1003",
                        url=final_url,
                    )
                )

            await _emit(scan_id, "web_paths", pct=35)
            paths = list(_DISCOVERY_PATHS)
            if deep:
                paths.extend(_VULN_PATHS)
            for i, path in enumerate(paths):
                if asyncio.get_running_loop().time() >= deadline:
                    break
                probe = urljoin(base_url, path)
                pr, perr = await _fetch(client, probe)
                await _log("path", {"path": path, "status": getattr(pr, "status_code", None), "error": perr})
                if pr is None:
                    continue
                if pr.status_code in {200, 401, 403} and path in _VULN_PATHS:
                    snippet = (pr.text or "")[:400].lower()
                    interesting = path.endswith(".env") and "=" in snippet
                    interesting = interesting or (path.endswith("HEAD") and "ref:" in snippet)
                    interesting = interesting or ("phpinfo" in path and "php version" in snippet)
                    interesting = interesting or pr.status_code == 200
                    if interesting:
                        alerts.append(
                            _alert(
                                f"Sensitive path exposed: /{path} [{pr.status_code}]",
                                riskcode="2" if path in {".env", ".git/HEAD", "phpinfo.php"} else "1",
                                riskdesc="Medium" if path in {".env", ".git/HEAD", "phpinfo.php"} else "Low",
                                pluginid=f"seciq-path-{path.replace('/', '-')[:20]}",
                                url=probe,
                            )
                        )
                if "index of /" in (pr.text or "").lower()[:2000]:
                    alerts.append(
                        _alert(
                            "Directory listing enabled",
                            riskcode="1",
                            riskdesc="Low",
                            pluginid="seciq-1004",
                            url=probe,
                        )
                    )
                pct = 35 + int((i + 1) / max(1, len(paths)) * 40)
                await _emit(scan_id, "web_paths", pct=min(75, pct))

            if deep and asyncio.get_running_loop().time() < deadline:
                await _emit(scan_id, "web_active", pct=80)
                xss_url = f"{base_url.rstrip('/')}?q={quote(_CANARY)}"
                xr, _ = await _fetch(client, xss_url)
                if xr and _CANARY in (xr.text or ""):
                    alerts.append(
                        _alert(
                            "User input reflected in response (review for XSS)",
                            riskcode="2",
                            riskdesc="Medium",
                            pluginid="seciq-4001",
                            url=xss_url,
                        )
                    )
                cors_headers = {"Origin": "https://evil.securaiq-lab.invalid"}
                cr, _ = await _fetch(client, base_url, headers=cors_headers)
                if cr:
                    acao = cr.headers.get("access-control-allow-origin", "")
                    if acao in {"*", "https://evil.securaiq-lab.invalid"}:
                        alerts.append(
                            _alert(
                                "Permissive CORS (Access-Control-Allow-Origin)",
                                riskcode="2",
                                riskdesc="Medium",
                                pluginid="seciq-1005",
                                url=base_url,
                            )
                        )

                # HTTP method exposure — TRACE enables classic XST (cross-site
                # tracing) attacks that read cookies/headers past HttpOnly;
                # PUT/DELETE open on the root path is almost always a
                # misconfiguration worth flagging.
                try:
                    tr = await client.request("TRACE", base_url, headers={"User-Agent": "SecuraIQ-WebScanner/1.0"})
                    await _log("trace", {"status": tr.status_code})
                    if tr.status_code < 400:
                        alerts.append(
                            _alert(
                                "HTTP TRACE method enabled (Cross-Site Tracing risk)",
                                riskcode="1",
                                riskdesc="Low",
                                pluginid="seciq-1007",
                                url=base_url,
                            )
                        )
                except Exception as exc:
                    await _log("trace", {"error": str(exc)})
                try:
                    opt = await client.options(base_url, headers={"User-Agent": "SecuraIQ-WebScanner/1.0"})
                    allow = (opt.headers.get("allow") or "").upper()
                    await _log("options", {"status": opt.status_code, "allow": allow})
                    risky_methods = {"PUT", "DELETE"} & {m.strip() for m in allow.split(",") if m.strip()}
                    if risky_methods:
                        alerts.append(
                            _alert(
                                f"Potentially unsafe HTTP method(s) allowed: {', '.join(sorted(risky_methods))}",
                                riskcode="1",
                                riskdesc="Low",
                                pluginid="seciq-1008",
                                url=base_url,
                            )
                        )
                except Exception as exc:
                    await _log("options", {"error": str(exc)})

    parsed = urlparse(base_url)
    if parsed.scheme == "https":
        tls = await asyncio.to_thread(_tls_probe, parsed.hostname or host, parsed.port or 443)
        await _log("tls", tls)
        ver = (tls.get("tls_version") or "").upper()
        if ver and ver < "TLSv1.2":
            alerts.append(
                _alert(
                    f"Weak TLS protocol: {ver}",
                    riskcode="2",
                    riskdesc="Medium",
                    pluginid="seciq-2001",
                    url=base_url,
                )
            )

    report = {"@version": "SecuraIQ-WebScanner", "site": [{"@name": base_url, "alerts": alerts}]}
    (evidence_dir / "zap.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    (evidence_dir / "web_builtin_trace.json").write_text(json.dumps(trace, indent=2), encoding="utf-8")
    await _emit(scan_id, "web_done", pct=100)

    return {
        "ok": True,
        "mode": "securaiq_web_builtin",
        "alerts": len(alerts),
        "artifacts": [
            str(evidence_dir / "zap.json"),
            str(evidence_dir / "web_builtin_trace.json"),
        ],
        "profile": prof,
        "target": base_url,
    }
