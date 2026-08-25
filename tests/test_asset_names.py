"""Asset display naming helpers."""

from __future__ import annotations

from app.asset_names import (
    canonical_asset_name,
    display_asset_label,
    host_correlation_key,
    is_ipv4,
    parse_notes_meta,
    resolve_target_labels,
)


def test_canonical_prefers_hostname_with_ip():
    name = canonical_asset_name(ip="192.168.1.10", hostname="lab.local")
    assert name == "lab.local (192.168.1.10)"


def test_parse_openaudit_text_notes():
    meta = parse_notes_meta("openaudit_id=abc\nip=10.0.0.5\nhostname=printer.local\n")
    assert meta["ip"] == "10.0.0.5"
    assert meta["hostname"] == "printer.local"


def test_host_correlation_key_ip_and_hostname():
    assert host_correlation_key("lab.local (192.168.1.10)") == "192.168.1.10"
    assert host_correlation_key("https://192.168.1.10:8080/x") == "192.168.1.10"


def test_resolve_target_labels_url():
    labels = resolve_target_labels("http://192.168.56.101/path", resolve_ptr=False)
    assert labels["ip"] == "192.168.56.101"
    assert is_ipv4(labels["ip"])


def test_display_asset_label_with_os():
    label = display_asset_label(name="pc-01", ip="192.168.1.20", hostname="pc-01", os="Windows")
    assert "pc-01" in label
    assert "Windows" in label
