"""Shared scanner constants (avoid circular imports with nmap/builtin)."""

from __future__ import annotations

import ipaddress
import re
import socket

HOST_OR_IP = re.compile(
    r"^(?:"
    r"(?:\d{1,3}\.){3}\d{1,3}"
    r"|(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(?:\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*\.?"
    r")$"
)

# Ports that warrant a finding (not every open port = vuln)
RISKY_PORTS = {
    21: ("ftp", "medium", "FTP service exposed"),
    23: ("telnet", "high", "Telnet (cleartext) exposed"),
    25: ("smtp", "low", "SMTP service exposed"),
    135: ("msrpc", "medium", "MSRPC exposed"),
    139: ("netbios", "medium", "NetBIOS exposed"),
    445: ("smb", "high", "SMB exposed"),
    1433: ("mssql", "high", "MSSQL exposed"),
    3306: ("mysql", "high", "MySQL exposed"),
    3389: ("rdp", "high", "RDP exposed"),
    5432: ("postgres", "high", "PostgreSQL exposed"),
    5900: ("vnc", "high", "VNC exposed"),
    6379: ("redis", "critical", "Redis exposed"),
    27017: ("mongodb", "high", "MongoDB exposed"),
}

_INTERNAL_DOMAIN_SUFFIXES = (
    ".local",
    ".internal",
    ".lan",
    ".corp",
    ".home",
    ".intranet",
    ".localdomain",
)


def _blocked_ip_reason(ip: "ipaddress.IPv4Address | ipaddress.IPv6Address") -> str:
    """Empty string = fine to reach; non-empty = why it's blocked."""
    if ip.is_loopback:
        return "loopback address"
    if ip.is_private:
        return "private/internal IP address"
    if ip.is_link_local:
        return "link-local address"
    if ip.is_reserved:
        return "reserved address"
    if ip.is_multicast:
        return "multicast address"
    if ip.is_unspecified:
        return "unspecified address"
    return ""


def internal_target_reason(host: str) -> str:
    """Empty string = `host` looks like a real public web target. Otherwise
    the reason it was rejected.

    Used by the Web Scanner (app/scanners/zap.py) — that tool is scoped to
    public-facing web apps, not internal infrastructure (the network/VAPT
    scanner in app/scanners/builtin.py legitimately targets private IPs, so
    this check is intentionally NOT applied there). Rejecting loopback,
    RFC1918/private, link-local, and internal-only-suffix hosts before any
    request is made also closes the SSRF hole where a web-scan target could
    otherwise be pointed at internal services (e.g. a cloud metadata
    endpoint or an internal admin panel) reachable from this server.

    Resolves the hostname and checks every returned address, not just the
    first, since a name can round-robin between a public and an internal
    IP. DNS resolution happens again independently at actual fetch time in
    app/scanners/web_builtin.py, so this is a pre-flight check, not the
    only line of defense against DNS-rebinding.
    """
    h = (host or "").strip().lower().rstrip(".")
    if not h:
        return "empty host"
    if h == "localhost" or h.endswith(".localhost"):
        return "localhost is not a public web target"
    if h.endswith(_INTERNAL_DOMAIN_SUFFIXES):
        return "internal-only domain suffix — not a public web target"

    # Direct IP literal (IPv4 or IPv6, brackets stripped by caller already).
    try:
        return _blocked_ip_reason(ipaddress.ip_address(h))
    except ValueError:
        pass

    # Hostname — resolve and check every address DNS returns.
    try:
        infos = socket.getaddrinfo(h, None)
    except Exception:
        # Can't resolve here (offline sandbox, transient DNS hiccup, etc.) —
        # don't false-positive block; the real fetch will surface its own
        # honest "unreachable" error if the name genuinely doesn't resolve.
        return ""
    for info in infos:
        raw_addr = info[4][0]
        try:
            ip = ipaddress.ip_address(raw_addr.split("%")[0])
        except ValueError:
            continue
        reason = _blocked_ip_reason(ip)
        if reason:
            return reason
    return ""
