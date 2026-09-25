"""Lab EASM — DNS / SAN / owned-host discovery.

Only enumerates hostnames already in the tenant inventory (plus .local/.lan
prefix guesses). Does not spray the public internet for unauthorized apexes.
"""

from __future__ import annotations

import ipaddress
import socket
import ssl
from typing import Any

from app.exposure import network_scope

_SAFE_SUFFIXES = (".local", ".lan", ".lab", ".test", ".internal", ".home", ".localdomain")
_LAB_PREFIXES = ("www", "api", "mail", "vpn", "staging", "dev", "app", "admin")


def _host_token(name: str) -> str:
    raw = (name or "").strip().lower()
    raw = raw.replace("https://", "").replace("http://", "").split("/")[0].split(":")[0]
    return raw.strip(".")


def _apex(host: str) -> str:
    parts = [p for p in _host_token(host).split(".") if p]
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return _host_token(host)


def _is_safe_lab_domain(host: str) -> bool:
    h = _host_token(host)
    return any(h.endswith(suf) for suf in _SAFE_SUFFIXES)


def resolve_hostname(host: str) -> dict[str, Any]:
    name = _host_token(host)
    if not name:
        return {"host": "", "ok": False, "addresses": [], "error": "empty host"}
    try:
        infos = socket.getaddrinfo(name, None)
        addrs = sorted({i[4][0] for i in infos if i[4]})
    except Exception as exc:
        return {"host": name, "ok": False, "addresses": [], "error": str(exc)[:160]}
    scopes = [network_scope(name, a) for a in addrs] or [network_scope(name)]
    scope = "public" if "public" in scopes else (scopes[0] if scopes else "unknown")
    ptr = ""
    if addrs:
        try:
            ptr, _, _ = socket.gethostbyaddr(addrs[0])
        except Exception:
            ptr = ""
    return {
        "host": name,
        "ok": True,
        "addresses": addrs,
        "ptr": ptr,
        "scope": scope,
        "error": "",
    }


def fetch_cert_sans(host: str, port: int = 443, timeout: float = 2.0) -> dict[str, Any]:
    """TLS SAN extraction against an already-owned hostname. Never invents hosts."""
    name = _host_token(host)
    if not name:
        return {"ok": False, "sans": [], "error": "empty host"}
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((name, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=name) as tls:
                cert = tls.getpeercert() or {}
    except Exception as exc:
        return {"ok": False, "host": name, "sans": [], "error": str(exc)[:160]}
    sans: list[str] = []
    for typ, val in cert.get("subjectAltName") or []:
        if typ.lower() == "dns" and val:
            sans.append(str(val).lower().rstrip("."))
    cn = ""
    for rdn in cert.get("subject") or ():
        for key, val in rdn:
            if str(key).lower() == "commonname":
                cn = str(val)
    return {"ok": True, "host": name, "sans": sorted(set(sans)), "cn": cn, "error": ""}


def _inventory_hosts(user_id: str) -> list[str]:
    from app.agents import list_agents
    from app.enterprise import list_assets

    hosts: list[str] = []
    for a in list_assets(user_id):
        for key in ("name", "hostname", "ip"):
            token = _host_token(str(a.get(key) or ""))
            if token:
                hosts.append(token)
    for ag in list_agents(user_id):
        payload = ag.get("last_payload") if isinstance(ag.get("last_payload"), dict) else {}
        for key in ("hostname", "ip"):
            token = _host_token(str(ag.get(key) or payload.get(key) or ""))
            if token:
                hosts.append(token)
    seen: set[str] = set()
    out: list[str] = []
    for h in hosts:
        if h in seen:
            continue
        seen.add(h)
        out.append(h)
    return out


def _guess_lab_subdomains(owned: list[str]) -> list[str]:
    guesses: list[str] = []
    apexes = {_apex(h) for h in owned if _is_safe_lab_domain(h)}
    for apex in apexes:
        if not apex:
            continue
        for prefix in _LAB_PREFIXES:
            guesses.append(f"{prefix}.{apex}")
    return guesses


def discover_attack_surface(
    user_id: str,
    *,
    extra_seeds: list[str] | None = None,
    include_cert_sans: bool = True,
    limit: int = 40,
) -> dict[str, Any]:
    owned = _inventory_hosts(user_id)
    seeds = list(owned)
    for extra in extra_seeds or []:
        token = _host_token(extra)
        if token and token not in seeds:
            # Extra seeds must already be owned or a safe lab suffix.
            if token in owned or _is_safe_lab_domain(token):
                seeds.append(token)
    candidates = list(seeds) + _guess_lab_subdomains(owned)
    hosts: list[dict[str, Any]] = []
    findings: list[dict[str, Any]] = []
    seen: set[str] = set()
    for name in candidates:
        if name in seen or len(hosts) >= limit:
            continue
        seen.add(name)
        row = resolve_hostname(name)
        hosts.append(row)
        if not row.get("ok"):
            continue
        scope = row.get("scope") or "unknown"
        if scope == "public":
            findings.append(
                {
                    "kind": "internet_facing_hostname",
                    "host": name,
                    "addresses": row.get("addresses") or [],
                    "title": f"Internet-facing hostname {name}",
                }
            )
        if name not in owned and row.get("ok"):
            findings.append(
                {
                    "kind": "discovered_subdomain",
                    "host": name,
                    "addresses": row.get("addresses") or [],
                    "title": f"Resolved lab subdomain {name}",
                }
            )
        if include_cert_sans and scope in {"private", "loopback"}:
            cert = fetch_cert_sans(name)
            if cert.get("ok"):
                row["cert"] = {"cn": cert.get("cn"), "sans": cert.get("sans")}
                for san in cert.get("sans") or []:
                    if san.startswith("*."):
                        findings.append(
                            {
                                "kind": "wildcard_san",
                                "host": name,
                                "san": san,
                                "title": f"Wildcard certificate SAN {san} on {name}",
                            }
                        )
                    elif san not in seen:
                        findings.append(
                            {
                                "kind": "cert_san",
                                "host": name,
                                "san": san,
                                "title": f"Certificate SAN {san} on {name}",
                            }
                        )
    return {
        "ok": True,
        "owned_count": len(owned),
        "hosts": hosts,
        "findings": findings[:limit],
        "finding_count": min(len(findings), limit),
        "disclaimer": (
            "Lab EASM — DNS/SAN of inventory and .local/.lan guesses only. "
            "Not commercial internet-wide attack-surface management."
        ),
    }


def easm_status() -> dict[str, Any]:
    return {
        "ok": True,
        "lab_production": True,
        "engine": "securaiq_easm",
        "standalone_engine": False,
        "endpoint": "POST /api/easm/discover",
        "note": "Owned-host DNS + optional TLS SAN. No unauthorized public spray.",
    }
