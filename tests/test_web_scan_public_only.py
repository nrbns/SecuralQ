"""Web Scanner target policy: public http(s) only; SSRF + private blocked.

ZapScanner.validate_target rejects RFC1918/loopback (use Network scan for LAN).
internal_target_reason(..., allow_lab_private=True) still exists for lab helpers,
but cloud metadata / link-local stay hard-blocked either way.
"""

from __future__ import annotations

import pytest

from app.scanners.constants import internal_target_reason
from app.scanners.zap import ZapScanner, _web_scan_url
from app.scanners.builtin import BuiltinScanner


@pytest.mark.parametrize(
    "host",
    [
        "169.254.1.1",
        "169.254.169.254",
        "0.0.0.0",
    ],
)
def test_internal_target_reason_hard_blocks_ssrf_ranges(host):
    assert internal_target_reason(host, allow_lab_private=True) != ""
    assert internal_target_reason(host, allow_lab_private=False) != ""


@pytest.mark.parametrize(
    "host",
    [
        "127.0.0.1",
        "10.0.0.5",
        "172.16.5.1",
        "192.168.1.1",
        "localhost",
    ],
)
def test_lab_mode_allows_private_and_loopback(host):
    assert internal_target_reason(host, allow_lab_private=True) == ""


@pytest.mark.parametrize(
    "host",
    [
        "127.0.0.1",
        "10.0.0.5",
        "192.168.1.1",
        "localhost",
        "web01.local",
    ],
)
def test_public_only_mode_still_blocks_private(host):
    assert internal_target_reason(host, allow_lab_private=False) != ""


@pytest.mark.parametrize("host", ["example.com", "8.8.8.8", "1.1.1.1"])
def test_internal_target_reason_allows_public_hosts(host):
    assert internal_target_reason(host, allow_lab_private=False) == ""
    assert internal_target_reason(host, allow_lab_private=True) == ""


def test_internal_target_reason_empty_host():
    assert internal_target_reason("") != ""
    assert internal_target_reason("   ") != ""


@pytest.mark.parametrize(
    "target",
    [
        "http://127.0.0.1/",
        "https://127.0.0.1:8443/",
        "http://10.0.0.5/",
        "http://192.168.1.10/",
        "http://172.20.0.5/",
        "http://localhost:8080/",
        "192.168.1.1",
        "192.168.0.1/24",
    ],
)
def test_zap_validate_target_rejects_lab_private(target):
    """Web Scanner path is public URLs only — LAN/loopback use Network scan."""
    sc = ZapScanner()
    ok, detail = sc.validate_target(target)
    assert ok is False, detail
    assert "blocked" in detail.lower() or "private" in detail.lower() or "loopback" in detail.lower() or "localhost" in detail.lower()


@pytest.mark.parametrize(
    "target",
    [
        "http://169.254.169.254/latest/meta-data/",
        "169.254.169.254",
    ],
)
def test_zap_validate_target_rejects_cloud_metadata(target):
    sc = ZapScanner()
    ok, detail = sc.validate_target(target)
    assert ok is False
    assert "link-local" in detail.lower() or "metadata" in detail.lower() or "blocked" in detail.lower()


def test_zap_validate_target_accepts_public_host():
    sc = ZapScanner()
    ok, detail = sc.validate_target("http://example.com/")
    assert ok is True
    assert detail.startswith("http")


def test_zap_validate_target_still_rejects_shell_metacharacters():
    sc = ZapScanner()
    ok, detail = sc.validate_target("example.com; rm -rf /")
    assert ok is False
    assert "invalid target characters" in detail


def test_web_scan_url_prefers_http_for_private_ip():
    assert _web_scan_url("192.168.0.1/24") == "http://192.168.0.1"
    assert _web_scan_url("10.0.0.5:8080").startswith("http://10.0.0.5:8080")


@pytest.mark.parametrize("target", ["127.0.0.1", "10.0.0.5", "192.168.1.10"])
def test_builtin_network_scanner_still_allows_internal_targets(target):
    sc = BuiltinScanner()
    ok, detail = sc.validate_target(target)
    assert ok is True
    assert detail == target
