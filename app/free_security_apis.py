"""Built-in threat-intel provider catalog (Security + Anti-Malware).

Integration model:
  - catalog: registered provider with docs/auth metadata
  - live: no-auth / community endpoints SecuraIQ can call today
  - keyed: optional API keys in Settings / .env unlock richer lookups
  - skipped: client-only JS, privacy/fraud-banking, or unsafe cracking APIs
"""

from __future__ import annotations

import asyncio
import ipaddress
import re
from typing import Any
from urllib.parse import quote

import httpx

from app.config import settings
from app.intel_feeds import _cache_get, _cache_put, lookup_nvd_cve

UA = {"User-Agent": "SecuraIQ/1.0 (+authorized-labs; https://github.com/nrbns/Hackgpt-ai)"}

# Built-in Security + Anti-Malware provider catalog (auth/status for SecuraIQ).
FREE_SECURITY_CATALOG: list[dict[str, Any]] = [
    # --- Security ---
    {"id": "aev", "name": "Application Environment Verification", "auth": "apiKey", "docs": "https://github.com/fingerprintjs/aev", "status": "catalog", "notes": "Client Android library"},
    {"id": "binaryedge", "name": "BinaryEdge", "auth": "apiKey", "docs": "https://docs.binaryedge.io/api-v2.html", "status": "keyed"},
    {"id": "bitwarden", "name": "Bitwarden", "auth": "OAuth", "docs": "https://bitwarden.com/help/api/", "status": "catalog"},
    {"id": "botd", "name": "Botd", "auth": "apiKey", "docs": "https://github.com/fingerprintjs/botd", "status": "catalog", "notes": "Browser JS library"},
    {"id": "bugcrowd", "name": "Bugcrowd", "auth": "apiKey", "docs": "https://docs.bugcrowd.com/api/getting-started/", "status": "catalog"},
    {"id": "censys", "name": "Censys", "auth": "apiKey", "docs": "https://search.censys.io/api", "status": "keyed"},
    {"id": "classify", "name": "Classify", "auth": "No", "docs": "https://classify-web.herokuapp.com/#/api", "status": "catalog", "notes": "Encrypt/decrypt demo — not threat intel"},
    {"id": "criminal_checks", "name": "Complete Criminal Checks", "auth": "apiKey", "docs": "https://completecriminalchecks.com/Developers", "status": "skipped", "notes": "PII / background checks — out of scope"},
    {"id": "crxcavator", "name": "CRXcavator", "auth": "apiKey", "docs": "https://crxcavator.io/apidocs", "status": "catalog"},
    {"id": "deaddrop", "name": "dead-drop", "auth": "No", "docs": "https://api.dead-drop.xyz/api/v1/docs", "status": "catalog"},
    {"id": "dehash", "name": "Dehash.lt", "auth": "No", "docs": "https://github.com/Dehash-lt/api", "status": "skipped", "notes": "Hash cracking — not integrated"},
    {"id": "domain_intelligence", "name": "Domain Intelligence", "auth": "apiKey", "docs": "https://oti-labs.com/domain-intelligence-api", "status": "keyed"},
    {"id": "emailrep", "name": "EmailRep", "auth": "apiKey", "docs": "https://docs.emailrep.io/", "status": "keyed", "notes": "Unauthenticated API disabled"},
    {"id": "escape", "name": "Escape", "auth": "No", "docs": "https://github.com/polarspetroll/EscapeAPI", "status": "catalog"},
    {"id": "filterlists", "name": "FilterLists", "auth": "No", "docs": "https://filterlists.com", "status": "live"},
    {"id": "fingerprintjs", "name": "FingerprintJS Pro", "auth": "apiKey", "docs": "https://dev.fingerprintjs.com/docs", "status": "catalog"},
    {"id": "fraudlabs", "name": "FraudLabs Pro", "auth": "apiKey", "docs": "https://www.fraudlabspro.com/developer/api/screen-order", "status": "catalog"},
    {"id": "fullhunt", "name": "FullHunt", "auth": "apiKey", "docs": "https://api-docs.fullhunt.io/#introduction", "status": "keyed"},
    {"id": "gitguardian", "name": "GitGuardian", "auth": "apiKey", "docs": "https://api.gitguardian.com/doc", "status": "keyed"},
    {"id": "greynoise", "name": "GreyNoise", "auth": "apiKey", "docs": "https://docs.greynoise.io/reference/get_v3-community-ip", "status": "live", "notes": "Community IP endpoint is free"},
    {"id": "hackerone", "name": "HackerOne", "auth": "apiKey", "docs": "https://api.hackerone.com/", "status": "catalog"},
    {"id": "hashable", "name": "Hashable", "auth": "No", "docs": "https://hashable.space/pages/api/", "status": "catalog"},
    {"id": "hibp", "name": "HaveIBeenPwned", "auth": "apiKey", "docs": "https://haveibeenpwned.com/API/v3", "status": "keyed"},
    {"id": "intelx", "name": "Intelligence X", "auth": "apiKey", "docs": "https://github.com/IntelligenceX/SDK", "status": "keyed"},
    {"id": "iplogs", "name": "IPLogs", "auth": "No", "docs": "https://iplogs.com/docs", "status": "catalog", "notes": "Public API unavailable"},
    {"id": "loginradius", "name": "LoginRadius", "auth": "apiKey", "docs": "https://www.loginradius.com/docs/", "status": "catalog"},
    {"id": "msrc", "name": "Microsoft Security Response Center", "auth": "No", "docs": "https://msrc.microsoft.com/report/developer", "status": "live"},
    {"id": "http_observatory", "name": "Mozilla HTTP Observatory", "auth": "No", "docs": "https://github.com/mozilla/http-observatory", "status": "catalog", "notes": "Service retired / unstable"},
    {"id": "tls_observatory", "name": "Mozilla TLS Observatory", "auth": "No", "docs": "https://github.com/mozilla/tls-observatory", "status": "catalog", "notes": "Service retired / unstable"},
    {"id": "nvd", "name": "National Vulnerability Database", "auth": "No", "docs": "https://nvd.nist.gov/developers", "status": "live"},
    {"id": "passwordinator", "name": "Passwordinator", "auth": "No", "docs": "https://github.com/fawazsullia/password-generator/", "status": "live", "notes": "Local generator (remote host unreliable)"},
    {"id": "phishstats", "name": "PhishStats", "auth": "No", "docs": "https://phishstats.info/", "status": "live"},
    {"id": "privacy_com", "name": "Privacy.com", "auth": "apiKey", "docs": "https://privacy.com/developer/docs", "status": "skipped", "notes": "Banking virtual cards — out of scope"},
    {"id": "pulsedive", "name": "Pulsedive", "auth": "apiKey", "docs": "https://pulsedive.com/api/", "status": "keyed"},
    {"id": "securitytrails", "name": "SecurityTrails", "auth": "apiKey", "docs": "https://securitytrails.com/corp/apidocs", "status": "keyed"},
    {"id": "shodan", "name": "Shodan", "auth": "apiKey", "docs": "https://developer.shodan.io/", "status": "keyed"},
    {"id": "spyse", "name": "Spyse", "auth": "apiKey", "docs": "https://spyse-dev.readme.io/reference/quick-start", "status": "catalog", "notes": "Service sunset"},
    {"id": "threatjammer", "name": "Threat Jammer", "auth": "apiKey", "docs": "https://threatjammer.com/docs/index", "status": "keyed"},
    {"id": "uk_police", "name": "UK Police", "auth": "No", "docs": "https://data.police.uk/docs/", "status": "live"},
    {"id": "urlhaus", "name": "URLhaus", "auth": "apiKey", "docs": "https://urlhaus.abuse.ch/api/", "status": "keyed", "notes": "Auth-Key required"},
    {"id": "virushee", "name": "Virushee", "auth": "No", "docs": "https://api.virushee.com/", "status": "catalog"},
    {"id": "vuldb", "name": "VulDB", "auth": "apiKey", "docs": "https://vuldb.com/?doc.api", "status": "keyed"},
    # --- Anti-Malware ---
    {"id": "abuseipdb", "name": "AbuseIPDB", "auth": "apiKey", "docs": "https://docs.abuseipdb.com/", "status": "keyed"},
    {"id": "otx", "name": "AlienVault OTX", "auth": "apiKey", "docs": "https://otx.alienvault.com/api", "status": "live", "notes": "Indicator lookup works without key"},
    {"id": "cape", "name": "CAPEsandbox", "auth": "apiKey", "docs": "https://capev2.readthedocs.io/en/latest/usage/api.html", "status": "catalog"},
    {"id": "safebrowsing", "name": "Google Safe Browsing", "auth": "apiKey", "docs": "https://developers.google.com/safe-browsing/", "status": "keyed"},
    {"id": "maldatabase", "name": "MalDatabase", "auth": "apiKey", "docs": "https://maldatabase.com/api-doc.html", "status": "catalog"},
    {"id": "malshare", "name": "MalShare", "auth": "apiKey", "docs": "https://malshare.com/doc.php", "status": "keyed"},
    {"id": "malwarebazaar", "name": "MalwareBazaar", "auth": "apiKey", "docs": "https://bazaar.abuse.ch/api/", "status": "keyed"},
    {"id": "metacert", "name": "Metacert", "auth": "apiKey", "docs": "https://metacert.com/", "status": "catalog"},
    {"id": "nophishy", "name": "NoPhishy", "auth": "apiKey", "docs": "https://rapidapi.com/Amiichu/api/exerra-phishing-check/", "status": "catalog"},
    {"id": "phisherman", "name": "Phisherman", "auth": "apiKey", "docs": "https://phisherman.gg/", "status": "keyed"},
    {"id": "scanii", "name": "Scanii", "auth": "apiKey", "docs": "https://docs.scanii.com/", "status": "catalog"},
    {"id": "urlscan", "name": "URLScan.io", "auth": "apiKey", "docs": "https://urlscan.io/about-api/", "status": "live", "notes": "Search works without key; submit needs key"},
    {"id": "virustotal", "name": "VirusTotal", "auth": "apiKey", "docs": "https://docs.virustotal.com/reference/overview", "status": "keyed"},
    {"id": "wot", "name": "Web of Trust", "auth": "apiKey", "docs": "https://support.mywot.com/hc/en-us/sections/360004477734-API-", "status": "catalog"},
    # Already shipped in SecuraIQ
    {"id": "cisa_kev", "name": "CISA KEV", "auth": "No", "docs": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog", "status": "live"},
]

_KEYED_IDS = (
    "abuseipdb",
    "virustotal",
    "shodan",
    "otx",
    "urlscan",
    "hibp",
    "greynoise",
    "pulsedive",
    "malwarebazaar",
    "emailrep",
    "urlhaus",
)


def _key(name: str) -> str:
    return (getattr(settings, name, "") or "").strip()


def catalog_summary() -> dict[str, Any]:
    counts: dict[str, int] = {}
    for item in FREE_SECURITY_CATALOG:
        counts[item["status"]] = counts.get(item["status"], 0) + 1
    keyed_ready = {kid: bool(_key(f"{kid}_api_key")) for kid in _KEYED_IDS}
    items = []
    for item in FREE_SECURITY_CATALOG:
        row = dict(item)
        if item["id"] in keyed_ready:
            row["key_configured"] = keyed_ready[item["id"]]
            if keyed_ready[item["id"]] and item["status"] == "keyed":
                row["status"] = "live"
        items.append(row)
    return {
        "total": len(items),
        "counts": counts,
        "keys_configured": keyed_ready,
        "items": items,
        "live_without_keys": [
            "greynoise",
            "otx",
            "urlscan",
            "msrc",
            "filterlists",
            "nvd",
            "cisa_kev",
            "phishstats",
        ],
    }


def _detect_kind(q: str) -> str:
    s = (q or "").strip()
    if not s:
        return "unknown"
    if re.match(r"^CVE-\d{4}-\d+$", s, re.I):
        return "cve"
    if "@" in s and "." in s.split("@")[-1]:
        return "email"
    if re.match(r"^[a-fA-F0-9]{32}$", s) or re.match(r"^[a-fA-F0-9]{40}$", s) or re.match(r"^[a-fA-F0-9]{64}$", s):
        return "hash"
    if re.match(r"^https?://", s, re.I):
        return "url"
    try:
        ipaddress.ip_address(s)
        return "ip"
    except ValueError:
        pass
    if "." in s and " " not in s:
        return "domain"
    return "text"


async def _get_json(url: str, *, headers: dict | None = None, params: dict | None = None, timeout: float = 25.0) -> Any:
    async with httpx.AsyncClient(timeout=timeout, follow_redirects=True, headers={**UA, **(headers or {})}) as client:
        r = await client.get(url, params=params)
        r.raise_for_status()
        return r.json()


async def _post_form(url: str, data: dict[str, str], *, headers: dict | None = None) -> Any:
    async with httpx.AsyncClient(timeout=25.0, follow_redirects=True, headers={**UA, **(headers or {})}) as client:
        r = await client.post(url, data=data)
        r.raise_for_status()
        return r.json()


async def lookup_urlhaus(host_or_url: str) -> dict[str, Any]:
    key = _key("urlhaus_api_key")
    if not key:
        raise ValueError("Set URLHAUS_API_KEY (abuse.ch Auth-Key) in Settings / .env")
    q = host_or_url.strip()
    headers = {"Auth-Key": key}
    if q.lower().startswith("http"):
        data = await _post_form("https://urlhaus-api.abuse.ch/v1/url/", {"url": q}, headers=headers)
        return {"source": "urlhaus", "kind": "url", "query": q, "data": data}
    data = await _post_form("https://urlhaus-api.abuse.ch/v1/host/", {"host": q}, headers=headers)
    return {"source": "urlhaus", "kind": "host", "query": q, "data": data}


async def lookup_emailrep(email: str) -> dict[str, Any]:
    key = _key("emailrep_api_key")
    if not key:
        raise ValueError("Set EMAILREP_API_KEY in Settings / .env (unauthenticated API disabled)")
    email = email.strip()
    cached = _cache_get("emailrep", email.lower(), max_age_sec=86400)
    if cached:
        return {"source": "emailrep", "cached": True, "query": email, "data": cached}
    data = await _get_json(f"https://emailrep.io/{quote(email)}", headers={"Key": key})
    _cache_put("emailrep", email.lower(), data if isinstance(data, dict) else {"raw": data})
    return {"source": "emailrep", "cached": False, "query": email, "data": data}


async def lookup_greynoise(ip: str) -> dict[str, Any]:
    ip = ip.strip()
    cached = _cache_get("greynoise", ip, max_age_sec=21600)
    if cached:
        return {"source": "greynoise", "cached": True, "query": ip, "data": cached}
    headers = {}
    key = _key("greynoise_api_key")
    if key:
        headers["key"] = key
    async with httpx.AsyncClient(timeout=25.0, follow_redirects=True, headers={**UA, **headers}) as client:
        r = await client.get(f"https://api.greynoise.io/v3/community/{quote(ip)}")
        # Community API returns 404 JSON when IP was not observed scanning — still useful.
        if r.status_code not in (200, 404):
            r.raise_for_status()
        data = r.json()
    _cache_put("greynoise", ip, data if isinstance(data, dict) else {"raw": data})
    return {"source": "greynoise", "cached": False, "query": ip, "data": data}


async def lookup_phishstats(query: str, *, size: int = 5) -> dict[str, Any]:
    q = query.strip().replace("'", "")
    sz = min(20, max(1, size))

    async def _fetch(field: str) -> Any:
        url = (
            "https://phishstats.info:2096/api/phishing"
            f"?_where=({field},like,~{quote(q)}~)&_size={sz}&_sort=-date"
        )
        return await _get_json(url, timeout=6.0)

    settled = await asyncio.gather(_fetch("url"), _fetch("host"), return_exceptions=True)
    data: Any = []
    for item in settled:
        if isinstance(item, list) and item:
            data = item
            break
    if not data:
        for item in settled:
            if isinstance(item, list):
                data = item
                break
    if not data and any(isinstance(item, Exception) for item in settled):
        raise ValueError("phishstats unavailable")
    return {"source": "phishstats", "query": q, "count": len(data) if isinstance(data, list) else 1, "data": data}


async def lookup_filterlists(*, limit: int = 20) -> dict[str, Any]:
    cached = _cache_get("filterlists", "all", max_age_sec=86400)
    if cached:
        items = cached[:limit]
        return {"source": "filterlists", "cached": True, "count": len(items), "items": items}
    data = await _get_json("https://api.filterlists.com/lists")
    if not isinstance(data, list):
        data = []
    slim = [
        {
            "id": x.get("id"),
            "name": x.get("name"),
            "description": (x.get("description") or "")[:180],
            "syntaxId": x.get("syntaxId"),
            "licenseId": x.get("licenseId"),
        }
        for x in data[:200]
    ]
    _cache_put("filterlists", "all", slim)
    return {"source": "filterlists", "cached": False, "count": len(slim[:limit]), "items": slim[:limit]}


async def lookup_msrc(*, limit: int = 15) -> dict[str, Any]:
    cached = _cache_get("msrc", "updates", max_age_sec=43200)
    if cached:
        return {"source": "msrc", "cached": True, "count": len(cached[:limit]), "items": cached[:limit]}
    data = await _get_json("https://api.msrc.microsoft.com/cvrf/v3.0/updates")
    value = data.get("value") if isinstance(data, dict) else data
    items = []
    for row in (value or [])[:100]:
        items.append(
            {
                "id": row.get("ID") or row.get("id"),
                "alias": row.get("Alias") or row.get("alias"),
                "document_title": row.get("DocumentTitle") or row.get("documentTitle"),
                "current_release_date": row.get("CurrentReleaseDate") or row.get("currentReleaseDate"),
                "cvrf_url": row.get("CvrfUrl") or row.get("cvrfUrl"),
            }
        )
    _cache_put("msrc", "updates", items)
    return {"source": "msrc", "cached": False, "count": len(items[:limit]), "items": items[:limit]}


async def lookup_uk_police_forces() -> dict[str, Any]:
    cached = _cache_get("uk_police", "forces", max_age_sec=604800)
    if cached:
        return {"source": "uk_police", "cached": True, "count": len(cached), "items": cached}
    data = await _get_json("https://data.police.uk/api/forces")
    items = [{"id": x.get("id"), "name": x.get("name")} for x in (data or [])]
    _cache_put("uk_police", "forces", items)
    return {"source": "uk_police", "cached": False, "count": len(items), "items": items}


async def generate_password(*, length: int = 16) -> dict[str, Any]:
    length = min(64, max(8, int(length)))
    import secrets
    import string

    alphabet = string.ascii_letters + string.digits + "!@#$%^&*-_"
    pwd = "".join(secrets.choice(alphabet) for _ in range(length))
    return {
        "source": "passwordinator_local",
        "note": "Generated locally (lab/password-policy demos). External Passwordinator hosts are unreliable.",
        "password": pwd,
        "length": length,
    }


async def check_password_pwned(password: str) -> dict[str, Any]:
    """HIBP Pwned Passwords range API (k-anonymity). Never sends the full password."""
    import hashlib

    pwd = (password or "").strip()
    if not pwd:
        raise ValueError("password required")
    if len(pwd) > 256:
        raise ValueError("password too long")
    digest = hashlib.sha1(pwd.encode("utf-8")).hexdigest().upper()
    prefix, suffix = digest[:5], digest[5:]
    async with httpx.AsyncClient(timeout=20.0, headers=UA) as client:
        r = await client.get(f"https://api.pwnedpasswords.com/range/{prefix}")
        r.raise_for_status()
        body = r.text
    count = 0
    for line in body.splitlines():
        parts = line.split(":")
        if len(parts) != 2:
            continue
        if parts[0].strip().upper() == suffix:
            try:
                count = int(parts[1].strip())
            except ValueError:
                count = 1
            break
    return {
        "source": "hibp_pwnedpasswords",
        "exposed": count > 0,
        "count": count,
        "note": "Checked via SHA-1 prefix only (k-anonymity). Password is not stored or logged by SecuraIQ.",
    }


async def lookup_abuseipdb(ip: str) -> dict[str, Any]:
    key = _key("abuseipdb_api_key")
    if not key:
        raise ValueError("Set ABUSEIPDB_API_KEY in Settings / .env")
    headers = {"Key": key, "Accept": "application/json"}
    async with httpx.AsyncClient(timeout=25.0, headers={**UA, **headers}) as client:
        r = await client.get(
            "https://api.abuseipdb.com/api/v2/check",
            params={"ipAddress": ip.strip(), "maxAgeInDays": 90, "verbose": ""},
        )
        r.raise_for_status()
        data = r.json()
    return {"source": "abuseipdb", "query": ip, "data": data.get("data") or data}


async def lookup_virustotal(q: str, kind: str) -> dict[str, Any]:
    key = _key("virustotal_api_key")
    if not key:
        raise ValueError("Set VIRUSTOTAL_API_KEY in Settings / .env")
    headers = {"x-apikey": key}
    if kind == "ip":
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{quote(q)}"
    elif kind == "domain":
        url = f"https://www.virustotal.com/api/v3/domains/{quote(q)}"
    elif kind == "url":
        import base64

        url_id = base64.urlsafe_b64encode(q.encode()).decode().strip("=")
        url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
    elif kind == "hash":
        url = f"https://www.virustotal.com/api/v3/files/{quote(q)}"
    else:
        raise ValueError("VirusTotal supports ip, domain, url, hash")
    data = await _get_json(url, headers=headers)
    return {"source": "virustotal", "kind": kind, "query": q, "data": data.get("data") or data}


async def lookup_shodan(ip: str) -> dict[str, Any]:
    key = _key("shodan_api_key")
    if not key:
        raise ValueError("Set SHODAN_API_KEY in Settings / .env")
    data = await _get_json(f"https://api.shodan.io/shodan/host/{quote(ip.strip())}", params={"key": key})
    return {"source": "shodan", "query": ip, "data": data}


async def lookup_otx(indicator: str, kind: str) -> dict[str, Any]:
    headers = {}
    key = _key("otx_api_key")
    if key:
        headers["X-OTX-API-KEY"] = key
    section = {
        "ip": "IPv4",
        "domain": "domain",
        "url": "url",
        "hash": "file",
        "hostname": "hostname",
    }.get(kind, "hostname")
    url = f"https://otx.alienvault.com/api/v1/indicators/{section}/{quote(indicator)}/general"
    data = await _get_json(url, headers=headers, timeout=12.0)
    return {"source": "otx", "kind": kind, "query": indicator, "data": data}


async def lookup_urlscan(q: str) -> dict[str, Any]:
    headers = {"Content-Type": "application/json"}
    key = _key("urlscan_api_key")
    if key:
        headers["API-Key"] = key
    data = await _get_json(
        "https://urlscan.io/api/v1/search/", params={"q": q, "size": 5}, headers=headers, timeout=12.0
    )
    return {"source": "urlscan", "query": q, "data": data}


async def lookup_hibp_breaches(account: str) -> dict[str, Any]:
    key = _key("hibp_api_key")
    if not key:
        raise ValueError("Set HIBP_API_KEY in Settings / .env (required by HIBP v3)")
    headers = {"hibp-api-key": key, "user-agent": "SecuraIQ"}
    url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{quote(account.strip())}"
    async with httpx.AsyncClient(timeout=25.0, headers={**UA, **headers}) as client:
        r = await client.get(url, params={"truncateResponse": "false"})
        if r.status_code == 404:
            return {"source": "hibp", "query": account, "breached": False, "breaches": []}
        r.raise_for_status()
        data = r.json()
    return {"source": "hibp", "query": account, "breached": True, "count": len(data), "breaches": data}


async def lookup_pulsedive(indicator: str) -> dict[str, Any]:
    key = _key("pulsedive_api_key")
    if not key:
        raise ValueError("Set PULSEDIVE_API_KEY in Settings / .env")
    data = await _get_json(
        "https://pulsedive.com/api/info.php",
        params={"indicator": indicator.strip(), "key": key},
    )
    return {"source": "pulsedive", "query": indicator, "data": data}


async def lookup_malwarebazaar(file_hash: str) -> dict[str, Any]:
    key = _key("malwarebazaar_api_key")
    if not key:
        raise ValueError("Set MALWAREBAZAAR_API_KEY (abuse.ch Auth-Key) in Settings / .env")
    data = await _post_form(
        "https://mb-api.abuse.ch/api/v1/",
        {"query": "get_info", "hash": file_hash.strip()},
        headers={"Auth-Key": key},
    )
    return {"source": "malwarebazaar", "query": file_hash, "data": data}


async def unified_lookup(query: str) -> dict[str, Any]:
    """Route a single indicator to the best free/keyed providers (parallel with per-provider errors)."""
    q = (query or "").strip()
    kind = _detect_kind(q)
    tasks: list[tuple[str, Any]] = []

    def _add(name: str, coro):
        tasks.append((name, coro))

    if kind == "cve":
        _add("nvd", lookup_nvd_cve(q))
        _add("msrc", lookup_msrc(limit=8))
    elif kind == "email":
        if _key("emailrep_api_key"):
            _add("emailrep", lookup_emailrep(q))
        else:
            pass  # appended after gather
        if _key("hibp_api_key"):
            _add("hibp", lookup_hibp_breaches(q))
    elif kind == "ip":
        _add("greynoise", lookup_greynoise(q))
        _add("otx", lookup_otx(q, "ip"))
        if _key("urlhaus_api_key"):
            _add("urlhaus", lookup_urlhaus(q))
        if _key("abuseipdb_api_key"):
            _add("abuseipdb", lookup_abuseipdb(q))
        if _key("shodan_api_key"):
            _add("shodan", lookup_shodan(q))
        if _key("virustotal_api_key"):
            _add("virustotal", lookup_virustotal(q, "ip"))
        if _key("pulsedive_api_key"):
            _add("pulsedive", lookup_pulsedive(q))
    elif kind in {"domain", "url"}:
        host = q
        if kind == "url":
            if _key("urlhaus_api_key"):
                _add("urlhaus", lookup_urlhaus(q))
            _add("urlscan", lookup_urlscan(q))
            try:
                from urllib.parse import urlparse

                host = urlparse(q).hostname or q
            except Exception:
                host = q
        if _key("urlhaus_api_key"):
            _add("urlhaus_host", lookup_urlhaus(host))
        _add("phishstats", lookup_phishstats(host))
        _add("otx", lookup_otx(host, "domain" if kind == "domain" else "url"))
        if kind == "domain":
            _add("urlscan", lookup_urlscan(f"domain:{host}"))
        if _key("virustotal_api_key"):
            _add("virustotal", lookup_virustotal(host if kind == "domain" else q, kind))
        if _key("pulsedive_api_key"):
            _add("pulsedive", lookup_pulsedive(host))
    elif kind == "hash":
        _add("otx", lookup_otx(q, "hash"))
        if _key("virustotal_api_key"):
            _add("virustotal", lookup_virustotal(q, "hash"))
        if _key("malwarebazaar_api_key"):
            _add("malwarebazaar", lookup_malwarebazaar(q))
    else:
        _add("phishstats", lookup_phishstats(q))
        _add("urlscan", lookup_urlscan(q))

    async def _run(name: str, coro):
        try:
            return name, await coro, None
        except Exception as exc:  # noqa: BLE001
            return name, None, str(exc)[:240] or "unavailable"

    results: list[dict[str, Any]] = []
    errors: list[dict[str, str]] = []
    if tasks:
        settled = await asyncio.gather(*[_run(name, coro) for name, coro in tasks])
        for name, payload, err in settled:
            if err:
                errors.append({"provider": name, "error": err})
            elif payload:
                results.append(payload)

    if kind == "email" and not _key("emailrep_api_key"):
        errors.append({"provider": "emailrep", "error": "Configure EMAILREP_API_KEY"})
    if kind == "hash" and not results:
        errors.append(
            {
                "provider": "hash",
                "error": "Configure VIRUSTOTAL_API_KEY or MALWAREBAZAAR_API_KEY for richer hash lookups (OTX tried)",
            }
        )

    return {
        "query": q,
        "kind": kind,
        "providers_ok": len(results),
        "providers_failed": len(errors),
        "results": results,
        "errors": errors,
    }
