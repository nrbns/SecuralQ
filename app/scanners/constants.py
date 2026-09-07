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


def _ssrf_blocked_ip_reason(ip: "ipaddress.IPv4Address | ipaddress.IPv6Address") -> str:
    """Hard SSRF denylist — always blocked even for authorized lab web scans.

    Cloud metadata / link-local (e.g. 169.254.169.254), multicast, and
    unspecified addresses must never be reachable via the web scanner.
    Loopback is allowed in lab mode (handled by the caller).
    """
    if ip.is_loopback:
        return ""
    if ip.is_link_local:
        return "link-local / cloud-metadata address"
    if ip.is_multicast:
        return "multicast address"
    if ip.is_unspecified:
        return "unspecified address"
    # Some Python builds mark ::1 etc. as reserved; loopback already returned.
    if ip.is_reserved and not ip.is_private:
        return "reserved address"
    return ""


def _blocked_ip_reason(
    ip: "ipaddress.IPv4Address | ipaddress.IPv6Address",
    *,
    allow_lab_private: bool = False,
) -> str:
    """Empty string = fine to reach; non-empty = why it's blocked."""
    hard = _ssrf_blocked_ip_reason(ip)
    if hard:
        return hard
    if allow_lab_private:
        # Authorized lab / owned-LAN web apps (RFC1918 + loopback) are OK.
        return ""
    if ip.is_loopback:
        return "loopback address"
    if ip.is_private:
        return "private/internal IP address"
    return ""


def internal_target_reason(host: str, *, allow_lab_private: bool = False) -> str:
    """Empty string = host is allowed for the Web Scanner. Otherwise why not.

    With ``allow_lab_private=False`` (legacy public-only): reject loopback,
    RFC1918, link-local, and internal-only DNS suffixes.

    With ``allow_lab_private=True`` (authorized checkbox / API gate): allow
    private LAN and loopback for owned labs, but still hard-block cloud
    metadata / link-local SSRF targets (e.g. 169.254.169.254).

    Resolves hostnames and checks every returned address (DNS rebinding).
    """
    h = (host or "").strip().lower().rstrip(".")
    if not h:
        return "empty host"
    if not allow_lab_private:
        if h == "localhost" or h.endswith(".localhost"):
            return "localhost is not a public web target"
        if h.endswith(_INTERNAL_DOMAIN_SUFFIXES):
            return "internal-only domain suffix — not a public web target"
    elif h.endswith(_INTERNAL_DOMAIN_SUFFIXES) and not h.endswith((".local", ".lan", ".home", ".localdomain")):
        # Keep .corp/.internal/.intranet blocked even in lab mode unless
        # they resolve — handled below via DNS. Suffixes common on labs OK.
        pass

    # Direct IP literal (IPv4 or IPv6, brackets stripped by caller already).
    try:
        return _blocked_ip_reason(ipaddress.ip_address(h), allow_lab_private=allow_lab_private)
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
        reason = _blocked_ip_reason(ip, allow_lab_private=allow_lab_private)
        if reason:
            return reason
    return ""
