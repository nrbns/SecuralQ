"""The Web Scanner (app.scanners.zap.ZapScanner) is scoped to public-facing
web apps only — internal hosts (loopback, RFC1918/private IPs, link-local,
.local/.internal names) belong to the network/VAPT scanner
(app.scanners.builtin.BuiltinScanner) instead. Rejecting them here also
closes an SSRF hole where a "web scan" target could otherwise reach internal
services (e.g. a cloud metadata endpoint) from this server.

BuiltinScanner is intentionally NOT restricted this way — internal-network
vulnerability scanning against private IPs is exactly what it's for.
"""

from __future__ import annotations

import pytest

from app.scanners.constants import internal_target_reason
from app.scanners.zap import ZapScanner
from app.scanners.builtin import BuiltinScanner


# --- internal_target_reason (pure logic, no I/O for IP literals) -----------


@pytest.mark.parametrize(
    "host",
    [
        "127.0.0.1",
        "127.0.0.53",
        "10.0.0.5",
        "172.16.5.1",
        "192.168.1.1",
        "169.254.1.1",  # link-local / cloud metadata range (169.254.169.254)
        "0.0.0.0",
        "::1",
        "localhost",
        "web01.local",
        "db.internal",
        "host.lan",
        "server.corp",
    ],
)
def test_internal_target_reason_blocks_internal_hosts(host):
    assert internal_target_reason(host) != ""


@pytest.mark.parametrize("host", ["example.com", "8.8.8.8", "1.1.1.1"])
def test_internal_target_reason_allows_public_hosts(host):
    assert internal_target_reason(host) == ""


def test_internal_target_reason_empty_host():
    assert internal_target_reason("") != ""
    assert internal_target_reason("   ") != ""


# --- ZapScanner.validate_target ---------------------------------------------


@pytest.mark.parametrize(
    "target",
    [
        "http://127.0.0.1/",
        "https://127.0.0.1:8443/",
        "http://10.0.0.5/",
        "http://192.168.1.10/",
        "http://172.20.0.5/",
        "http://localhost:8080/",
        "http://169.254.169.254/latest/meta-data/",  # classic SSRF cloud-metadata target
        "internal-app.local",
        "192.168.1.1",
    ],
)
def test_zap_validate_target_rejects_internal(target):
    sc = ZapScanner()
    ok, detail = sc.validate_target(target)
    assert ok is False
    assert "public web" in detail.lower()


def test_zap_validate_target_accepts_public_host():
    sc = ZapScanner()
    ok, detail = sc.validate_target("http://example.com/")
    assert ok is True
    assert detail.startswith("http")


def test_zap_validate_target_still_rejects_shell_metacharacters():
    """Existing injection guard must keep working alongside the new check."""
    sc = ZapScanner()
    ok, detail = sc.validate_target("example.com; rm -rf /")
    assert ok is False
    assert "invalid target characters" in detail


# --- BuiltinScanner (network/VAPT) is unaffected ----------------------------


@pytest.mark.parametrize("target", ["127.0.0.1", "10.0.0.5", "192.168.1.10"])
def test_builtin_network_scanner_still_allows_internal_targets(target):
    """The internal-network vulnerability scanner must keep working against
    private IPs — that's its whole purpose, unlike the Web Scanner above."""
    sc = BuiltinScanner()
    ok, detail = sc.validate_target(target)
    assert ok is True
    assert detail == target
