"""Product name normalization — one canonical identity per vendor/product."""

from __future__ import annotations

import re

_ALIASES: dict[str, tuple[str, str, str]] = {
    "google chrome": ("Google", "Chrome", "google.chrome"),
    "chrome": ("Google", "Chrome", "google.chrome"),
    "google-chrome": ("Google", "Chrome", "google.chrome"),
    "microsoft edge": ("Microsoft", "Edge", "microsoft.edge"),
    "msedge": ("Microsoft", "Edge", "microsoft.edge"),
    "edge": ("Microsoft", "Edge", "microsoft.edge"),
    "mozilla firefox": ("Mozilla", "Firefox", "mozilla.firefox"),
    "firefox": ("Mozilla", "Firefox", "mozilla.firefox"),
    "openssl": ("OpenSSL", "OpenSSL", "openssl.openssl"),
    "nginx": ("NGINX", "nginx", "nginx.nginx"),
    "apache http server": ("Apache", "httpd", "apache.httpd"),
    "apache": ("Apache", "httpd", "apache.httpd"),
    "httpd": ("Apache", "httpd", "apache.httpd"),
    "openssh": ("OpenBSD", "OpenSSH", "openbsd.openssh"),
    "postgresql": ("PostgreSQL", "PostgreSQL", "postgresql.postgresql"),
    "mysql": ("Oracle", "MySQL", "oracle.mysql"),
    "mariadb": ("MariaDB", "MariaDB", "mariadb.mariadb"),
    "python": ("Python", "Python", "python.python"),
    "node.js": ("OpenJS", "Node.js", "openjs.nodejs"),
    "nodejs": ("OpenJS", "Node.js", "openjs.nodejs"),
}

_VENDOR_PREFIX = re.compile(r"^(microsoft|google|oracle|apache|nginx|mozilla)\s+", re.I)


def _slug(text: str) -> str:
    t = re.sub(r"[^a-z0-9]+", ".", (text or "").lower()).strip(".")
    return t or "unknown.product"


def normalize_product(name: str, vendor: str = "", publisher: str = "") -> dict[str, str]:
    raw = (name or "").strip()
    if not raw:
        return {
            "name": "Unknown",
            "normalized_name": "unknown",
            "canonical_id": "unknown.product",
            "vendor": "",
            "publisher": "",
        }
    key = raw.lower()
    key = re.sub(r"\s+", " ", key)
    if key in _ALIASES:
        vendor, product, canonical = _ALIASES[key]
        return {
            "name": product,
            "normalized_name": product.lower(),
            "canonical_id": canonical,
            "vendor": vendor,
            "publisher": publisher or vendor,
        }
    vend = (vendor or publisher or "").strip()
    if not vend:
        m = _VENDOR_PREFIX.match(raw)
        if m:
            vend = m.group(1).title()
            raw = raw[m.end() :].strip() or raw
    canonical = f"{_slug(vend)}.{_slug(raw)}" if vend else _slug(raw)
    return {
        "name": raw[:200],
        "normalized_name": raw.lower()[:200],
        "canonical_id": canonical[:120],
        "vendor": vend[:120],
        "publisher": (publisher or vend)[:120],
    }
