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


# --- code_scan / semgrep / securaiq_code pass a local path, not a network
# host, as the "target" — resolve_target_labels must not run it through
# hostname/URL parsing (which mangled "E:\Regen Browser" into asset name
# "e": the drive letter before the first ":", same rule that correctly
# extracts "host" from "host:port/path").


def test_resolve_target_labels_windows_path_uses_folder_name():
    labels = resolve_target_labels(r"E:\Regen Browser")
    assert labels["asset_name"] == "Regen Browser"
    assert labels["ip"] == ""
    assert labels["asset_name"] != "e"
    assert labels["asset_name"] != "E"


def test_resolve_target_labels_windows_path_forward_slashes():
    labels = resolve_target_labels("E:/Regen Browser")
    assert labels["asset_name"] == "Regen Browser"


def test_resolve_target_labels_posix_path_uses_folder_name():
    labels = resolve_target_labels("/home/user/my-project")
    assert labels["asset_name"] == "my-project"
    assert labels["ip"] == ""


def test_resolve_target_labels_still_treats_real_hosts_as_hosts():
    """Guard against the fix overcorrecting — a bare hostname/IP target
    (the common case for network scans) must be unaffected."""
    labels = resolve_target_labels("192.168.56.101")
    assert labels["ip"] == "192.168.56.101"
    labels2 = resolve_target_labels("scanme.example.com")
    assert labels2["hostname"] == "scanme.example.com"
