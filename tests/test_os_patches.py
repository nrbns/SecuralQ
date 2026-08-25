"""OS patch probe tests."""

from unittest.mock import patch

from app.os_patches import (
    ingest_local_os_patches,
    ingest_remote_os_patches,
    probe_local_os_patches,
    probe_remote_via_ssh,
)


def test_ingest_local_os_no_pending():
    with patch("app.os_patches.probe_local_os_patches") as mock_probe:
        mock_probe.return_value = {
            "platform": "windows",
            "pending_count": 0,
            "packages": [{"id": "KB503", "name": "Security Update", "installed": "2024-01-01"}],
            "last_patch": "2024-01-01",
            "manager": "windows-update",
        }
        out = ingest_local_os_patches("test-os-user")
        assert out["ingested"] >= 1


def test_ingest_local_os_pending_packages():
    with patch("app.os_patches.probe_local_os_patches") as mock_probe:
        mock_probe.return_value = {
            "platform": "linux",
            "pending_count": 2,
            "manager": "apt",
            "packages": [
                {"id": "openssl", "name": "openssl", "version": "1.1.1", "target": "1.1.1w"},
                {"id": "curl", "name": "curl", "version": "7.68", "target": "7.88"},
            ],
        }
        out = ingest_local_os_patches("test-os-user-2")
        assert out["ingested"] >= 2


def test_probe_local_os_patches_returns_shape():
    data = probe_local_os_patches()
    assert "platform" in data
    assert "pending_count" in data
    assert "packages" in data


def test_probe_remote_via_ssh_apt():
    with patch("app.os_patches._run") as mock_run:
        mock_run.return_value = (0, "openssl/jammy-updates 3.0.2 amd64 [upgradable from: 3.0.0]", "")
        data = probe_remote_via_ssh("192.168.1.50", user="ubuntu")
        assert data.get("host") == "192.168.1.50"
        assert data.get("pending_count", 0) >= 1


def test_ingest_remote_disabled_by_default():
    out = ingest_remote_os_patches("test-remote-user")
    assert out.get("skipped") == "SSH patch probes disabled"
