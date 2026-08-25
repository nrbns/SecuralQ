"""Inventory asset categories — server, computer, endpoint, mobile, etc."""

from __future__ import annotations

import re
from typing import Any

CATEGORY_ORDER = (
    "server",
    "computer",
    "endpoint",
    "mobile",
    "network",
    "printer",
    "iot",
    "database",
    "web",
    "cloud",
    "container",
    "code",
    "other",
)

CATEGORY_LABELS: dict[str, str] = {
    "server": "Server",
    "computer": "Computer",
    "endpoint": "Endpoint",
    "mobile": "Mobile",
    "network": "Network",
    "printer": "Printer",
    "iot": "IoT",
    "database": "Database",
    "web": "Web app",
    "cloud": "Cloud",
    "container": "Container",
    "code": "Code",
    "other": "Other",
}

_ALIASES: dict[str, str] = {
    "servers": "server",
    "vm": "server",
    "virtual": "server",
    "hypervisor": "server",
    "nas": "server",
    "host": "endpoint",
    "device": "other",
    "workstation": "computer",
    "desktop": "computer",
    "laptop": "computer",
    "pc": "computer",
    "phone": "mobile",
    "tablet": "mobile",
    "ipad": "mobile",
    "iphone": "mobile",
    "android": "mobile",
    "router": "network",
    "switch": "network",
    "firewall": "network",
    "access_point": "network",
    "accesspoint": "network",
    "wlan": "network",
    "sql": "database",
    "db": "database",
    "app": "web",
    "application": "web",
    "url": "web",
    "api": "web",
    "saas": "cloud",
    "aws": "cloud",
    "azure": "cloud",
    "gcp": "cloud",
    "k8s": "container",
    "kubernetes": "container",
    "pod": "container",
    "docker": "container",
}

_GENERIC = frozenset({"", "other", "endpoint", "host", "device"})

_MOBILE_HOST = re.compile(r"(iphone|ipad|android|galaxy|mobile|phone|tablet)", re.I)
_PRINTER_HOST = re.compile(r"(print|printer|hp-|canon|epson|brother|mfp)", re.I)
_NETWORK_HOST = re.compile(r"(router|switch|fw-|firewall|ap-|wifi|gateway|core-|sw\d|uplink)", re.I)
_IOT_HOST = re.compile(r"(camera|cam-|nest|ring|hue|smart|iot|sensor|doorbell)", re.I)


def normalize_asset_category(value: str | None) -> str:
    t = (value or "").strip().lower().replace("-", "_")
    t = re.sub(r"\s+", "_", t)
    if not t:
        return "other"
    if t in CATEGORY_LABELS:
        return t
    if t in _ALIASES:
        return _ALIASES[t]
    for key, canon in _ALIASES.items():
        if key in t:
            return canon
    return "other"


def category_label(category_id: str | None) -> str:
    cid = normalize_asset_category(category_id)
    return CATEGORY_LABELS.get(cid, cid.replace("_", " ").title())


def list_categories() -> list[dict[str, str]]:
    return [{"id": c, "label": CATEGORY_LABELS[c]} for c in CATEGORY_ORDER]


def _port_ints(ports: list[Any] | None) -> set[int]:
    out: set[int] = set()
    for p in ports or []:
        try:
            if isinstance(p, int):
                out.add(p)
            else:
                out.add(int(str(p).split("/")[0].strip()))
        except (TypeError, ValueError):
            continue
    return out


def infer_asset_category(
    *,
    asset_type: str = "",
    os: str = "",
    hostname: str = "",
    oa_type: str = "",
    ports: list[Any] | None = None,
    http_server: str = "",
    name: str = "",
) -> str:
    explicit = normalize_asset_category(asset_type)
    oa = normalize_asset_category(oa_type)
    host_blob = f"{hostname} {name}".strip().lower()

    if _MOBILE_HOST.search(host_blob):
        return "mobile"
    if _PRINTER_HOST.search(host_blob):
        return "printer"
    if _NETWORK_HOST.search(host_blob):
        return "network"
    if _IOT_HOST.search(host_blob):
        return "iot"

    port_set = _port_ints(ports)
    if port_set & {9100, 631, 515}:
        return "printer"
    if port_set & {3306, 5432, 1433, 1521, 27017}:
        return "database"
    if port_set & {161, 23} and not port_set & {22, 3389, 445}:
        return "network"

    os_l = (os or "").lower()
    server_hdr = (http_server or "").lower()
    if any(x in os_l for x in ("ios", "android", "ipad", "iphone")):
        return "mobile"

    if port_set & {135, 139, 445, 3389}:
        return "computer"
    if 22 in port_set:
        if port_set & {80, 443, 8080, 8443} or "nginx" in server_hdr or "apache" in server_hdr:
            return "server"
        return "server"

    if explicit not in _GENERIC:
        return explicit
    if oa not in _GENERIC:
        return oa

    nm = (name or "").strip()
    if "://" in nm or nm.startswith("http"):
        return "web"
    if nm.endswith((".py", ".js", ".ts", ".go")) or "/" in nm or "\\" in nm:
        return "code"
    if port_set & {80, 443, 8080, 8443}:
        return "web" if "://" in nm else "server"
    if nm.replace(".", "").isdigit() or ":" in nm:
        return "server"
    return "endpoint"


def is_better_category(new: str, old: str) -> bool:
    new_n = normalize_asset_category(new)
    old_n = normalize_asset_category(old)
    if new_n == old_n:
        return False
    if old_n in _GENERIC:
        return new_n not in _GENERIC
    specificity = {
        "server": 3,
        "computer": 3,
        "mobile": 3,
        "network": 3,
        "printer": 3,
        "iot": 3,
        "database": 3,
        "web": 3,
        "cloud": 3,
        "container": 3,
        "code": 3,
        "endpoint": 2,
        "other": 1,
    }
    return specificity.get(new_n, 1) > specificity.get(old_n, 1)


def ports_from_meta(meta: dict[str, Any]) -> list[int]:
    return _ports_from_meta(meta)


def _ports_from_meta(meta: dict[str, Any]) -> list[int]:
    ports: list[int] = []
    for svc in meta.get("services") or []:
        if isinstance(svc, dict) and svc.get("port") is not None:
            try:
                ports.append(int(svc["port"]))
            except (TypeError, ValueError):
                pass
    raw = meta.get("open_ports")
    if isinstance(raw, list):
        ports.extend(list(_port_ints(raw)))
    raw_obj = meta.get("raw")
    if isinstance(raw_obj, dict):
        ports.extend(list(_port_ints(raw_obj.get("open_ports"))))
    return ports


def asset_category_id(asset: dict[str, Any]) -> str:
    """Alias used by software inventory and OS patch ingest."""
    return category_for_asset_row(asset)


def category_for_asset_row(asset: dict[str, Any]) -> str:
    from app.asset_names import parse_notes_meta

    meta = parse_notes_meta(asset.get("notes") or "")
    http_server = ""
    raw_obj = meta.get("raw")
    if isinstance(raw_obj, dict):
        http = raw_obj.get("http")
        if isinstance(http, list) and http:
            http_server = str((http[0] or {}).get("server") or "")
    return infer_asset_category(
        asset_type=str(asset.get("asset_type") or asset.get("type") or ""),
        os=str(meta.get("os") or asset.get("os") or ""),
        hostname=str(meta.get("hostname") or meta.get("host") or asset.get("hostname") or ""),
        oa_type=str(meta.get("oa_type") or ""),
        ports=_ports_from_meta(meta) or _ports_from_meta({"open_ports": asset.get("open_ports")}),
        http_server=http_server,
        name=str(asset.get("name") or ""),
    )


def enrich_asset_category(asset: dict[str, Any]) -> dict[str, Any]:
    row = dict(asset)
    cat = category_for_asset_row(row)
    row["asset_category"] = cat
    row["category_label"] = category_label(cat)
    return row


def inventory_breakdown(assets: list[dict[str, Any]]) -> dict[str, int]:
    counts: dict[str, int] = {c: 0 for c in CATEGORY_ORDER}
    for a in assets:
        cat = category_for_asset_row(a)
        counts[cat] = counts.get(cat, 0) + 1
    return {k: v for k, v in counts.items() if v > 0}
