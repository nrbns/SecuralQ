"""Canonical device / asset naming for inventory, scans, and findings."""

from __future__ import annotations

import json
import re
from typing import Any

_IPV4 = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")
_HOST_IP_NAME = re.compile(r"^(.+?)\s+\((\d{1,3}(?:\.\d{1,3}){3})\)\s*$")


def is_ipv4(value: str) -> bool:
    s = (value or "").strip()
    if not _IPV4.match(s):
        return False
    try:
        return all(0 <= int(p) <= 255 for p in s.split("."))
    except ValueError:
        return False


def parse_notes_meta(notes: str) -> dict[str, Any]:
    """Parse JSON notes or legacy ``key=value`` OpenAudit lines."""
    raw = (notes or "").strip()
    if not raw:
        return {}
    if raw.startswith("{"):
        try:
            parsed = json.loads(raw)
            return parsed if isinstance(parsed, dict) else {}
        except Exception:
            return {}
    meta: dict[str, Any] = {"source": "text_notes"}
    for line in raw.splitlines():
        line = line.strip()
        if not line or "=" not in line:
            continue
        key, _, val = line.partition("=")
        key = key.strip().lower()
        val = val.strip()
        if key in {"ip", "hostname", "host", "mac", "os", "domain", "openaudit_id", "oa_type", "source"}:
            meta[key] = val
    return meta


def resolve_ptr_if_ip(ip: str) -> str:
    ip = (ip or "").strip()
    if not is_ipv4(ip):
        return ""
    try:
        from app.lan_inventory import ptr_hostname

        return ptr_hostname(ip)
    except Exception:
        return ""


def canonical_asset_name(
    *,
    name: str = "",
    ip: str = "",
    hostname: str = "",
    ptr: str = "",
) -> str:
    """Best persisted asset name — hostname preferred over bare IP."""
    host = (hostname or ptr or "").strip().rstrip(".")
    nm = (name or "").strip()
    ip_s = (ip or "").strip()
    m = _HOST_IP_NAME.match(nm)
    if m:
        if not host:
            host = m.group(1).strip()
        if not ip_s:
            ip_s = m.group(2).strip()
    if not host and nm and not is_ipv4(nm):
        host = nm.split("/")[0].split(":")[0]
    if not ip_s and is_ipv4(nm):
        ip_s = nm
    if host and ip_s and is_ipv4(ip_s) and host.lower() != ip_s.lower():
        return f"{host} ({ip_s})"[:200]
    if host and not is_ipv4(host):
        return host[:200]
    if ip_s and is_ipv4(ip_s):
        return ip_s[:200]
    return (nm or ip_s or "device")[:200]


def display_asset_label(
    *,
    name: str = "",
    ip: str = "",
    hostname: str = "",
    os: str = "",
) -> str:
    """Human-friendly label for UI tables."""
    label = canonical_asset_name(name=name, ip=ip, hostname=hostname)
    if os and os.strip():
        return f"{label} · {os.strip()}"[:240]
    return label[:240]


def asset_meta_from_record(asset: dict[str, Any] | None) -> dict[str, str]:
    if not asset:
        return {"name": "", "ip": "", "hostname": ""}
    meta = parse_notes_meta(str(asset.get("notes") or ""))
    name = str(asset.get("name") or "").strip()
    ip = str(meta.get("ip") or "").strip()
    hostname = str(meta.get("hostname") or meta.get("host") or "").strip()
    if not ip and is_ipv4(name):
        ip = name
    m = _HOST_IP_NAME.match(name)
    if m:
        if not hostname:
            hostname = m.group(1).strip()
        if not ip:
            ip = m.group(2).strip()
    return {"name": name, "ip": ip, "hostname": hostname}


def display_name_for_asset(asset: dict[str, Any] | None) -> str:
    bits = asset_meta_from_record(asset)
    os_name = str(parse_notes_meta(str((asset or {}).get("notes") or "")).get("os") or "").strip()
    return display_asset_label(
        name=bits["name"],
        ip=bits["ip"],
        hostname=bits["hostname"],
        os=os_name,
    )


def host_correlation_key(value: str) -> str:
    """Stable dedupe key — prefer IPv4 when present."""
    raw = (value or "").strip().lower()
    if not raw:
        return ""
    m = _HOST_IP_NAME.match(raw)
    if m:
        return m.group(2).strip().lower()
    if raw.startswith("http://") or raw.startswith("https://"):
        try:
            from app.scanners.nuclei import _hostname_from_target

            host = (_hostname_from_target(raw) or "").lower()
            if is_ipv4(host):
                return host
            return host or raw
        except Exception:
            pass
    if is_ipv4(raw.split(":")[0]):
        return raw.split(":")[0]
    return raw.split("/")[0].split(":")[0]


def canonical_vuln_asset_name(
    asset_name: str,
    *,
    asset: dict[str, Any] | None = None,
    ip: str = "",
    hostname: str = "",
) -> str:
    if asset:
        return display_name_for_asset(asset).split(" · ")[0]
    raw = (asset_name or "").strip()
    if raw.startswith("http://") or raw.startswith("https://"):
        try:
            from app.scanners.nuclei import _hostname_from_target

            host = _hostname_from_target(raw) or raw
            if is_ipv4(host) and hostname:
                return canonical_asset_name(ip=host, hostname=hostname)
            return host[:200]
        except Exception:
            pass
    return canonical_asset_name(name=raw, ip=ip, hostname=hostname)[:200]


def is_better_asset_name(new_name: str, old_name: str) -> bool:
    new_name = (new_name or "").strip()
    old_name = (old_name or "").strip()
    if not old_name:
        return bool(new_name)
    if is_ipv4(old_name) and not is_ipv4(new_name):
        return True
    if is_ipv4(old_name) and "(" in new_name:
        return True
    return len(new_name) > len(old_name) and not is_ipv4(new_name)


def resolve_target_labels(target: str, *, ptr: str | None = None, resolve_ptr: bool = False) -> dict[str, str]:
    """Derive ip, hostname, and canonical asset name from a scan/tool target."""
    from app.scanners.nuclei import _hostname_from_target

    t = (target or "").strip()
    ip = ""
    hostname = ""
    if t.startswith("http://") or t.startswith("https://"):
        hostname = (_hostname_from_target(t) or "").strip().rstrip(".")
        if is_ipv4(hostname):
            ip = hostname
            hostname = (ptr or "").strip().rstrip(".") if ptr else ""
    elif is_ipv4(t.split(":")[0] if ":" in t else t):
        ip = t.split(":")[0] if ":" in t else t
        hostname = (ptr or "").strip().rstrip(".") if ptr else ""
    else:
        hostname = (_hostname_from_target(t) or t).strip().rstrip(".")
        if is_ipv4(hostname):
            ip = hostname
            hostname = ""
    if resolve_ptr and ip and not hostname:
        hostname = resolve_ptr_if_ip(ip)
    asset_name = canonical_asset_name(ip=ip, hostname=hostname, name=hostname or ip or t)
    display = display_asset_label(name=asset_name, ip=ip, hostname=hostname)
    return {
        "ip": ip,
        "hostname": hostname,
        "host": hostname or ip or t,
        "asset_name": asset_name,
        "display_name": display,
    }


def enrich_asset_row(asset: dict[str, Any]) -> dict[str, Any]:
    row = dict(asset)
    meta = parse_notes_meta(str(asset.get("notes") or ""))
    bits = asset_meta_from_record(asset)
    ip = bits["ip"]
    hostname = bits["hostname"]
    if not ip and is_ipv4(bits["name"]):
        ip = bits["name"]
    row["ip"] = ip
    row["hostname"] = hostname
    row["display_name"] = display_asset_label(
        name=bits["name"],
        ip=ip,
        hostname=hostname,
        os=str(meta.get("os") or ""),
    )
    return row
