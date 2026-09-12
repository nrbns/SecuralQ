"""Scan Sources lab paths: cloud import, honest sync rejects, hardening gates."""

from __future__ import annotations

from pathlib import Path

from tests._http_test_utils import configure_isolated_settings


def _admin(tmp_path, monkeypatch, username="scan_src_admin"):
    configure_isolated_settings(monkeypatch, tmp_path)
    from app.auth import login, register_user
    from app.tenancy import ensure_tenant_schema

    ensure_tenant_schema()
    register_user(username, "password123", role="admin")
    user, token = login(username, "password123")
    return user, token


def test_cloud_import_and_lab_sample(tmp_path, monkeypatch):
    from fastapi.testclient import TestClient

    from app.main import app

    user, token = _admin(tmp_path, monkeypatch, "cloud_imp")
    client = TestClient(app)
    headers = {"Authorization": f"Bearer {token}"}

    sample = client.get("/api/cloud/lab-sample", headers=headers)
    assert sample.status_code == 200
    body = sample.json()
    assert body.get("findings")

    imp = client.post(
        "/api/cloud/import",
        headers=headers,
        json={"vendor": "cloud_import", "findings": body["findings"]},
    )
    assert imp.status_code == 200
    assert imp.json().get("imported", 0) >= 1

    st = client.get("/api/cloud/status", headers=headers)
    assert st.status_code == 200
    assert st.json().get("findings_cached", 0) >= 1

    sync = client.post("/api/cloud/sync", headers=headers)
    assert sync.status_code == 400
    assert "Import JSON" in (sync.json().get("detail") or "")


def test_code_sync_rejects_when_unconfigured(tmp_path, monkeypatch):
    from fastapi.testclient import TestClient

    from app.main import app

    _user, token = _admin(tmp_path, monkeypatch, "code_sync")
    client = TestClient(app)
    headers = {"Authorization": f"Bearer {token}"}
    # Ensure no sonar env in this isolated settings run
    monkeypatch.setenv("SONARQUBE_URL", "")
    monkeypatch.setenv("SONAR_HOST_URL", "")
    res = client.post("/api/code/sync", headers=headers)
    assert res.status_code == 400
    assert "Scan folder" in (res.json().get("detail") or "")


def test_hardening_audit_rejects_when_not_installed(tmp_path, monkeypatch):
    from fastapi.testclient import TestClient

    from app.main import app

    _user, token = _admin(tmp_path, monkeypatch, "hk_gate")
    client = TestClient(app)
    headers = {"Authorization": f"Bearer {token}"}

    st = client.get("/api/hardeningkitty/status", headers=headers)
    assert st.status_code == 200
    status = st.json()
    assert "installed" in status
    assert "platform" in status

    if not status.get("installed"):
        audit = client.post(
            "/api/hardeningkitty/audit",
            headers=headers,
            json={"mode": "Audit", "import_findings": True},
        )
        assert audit.status_code == 400
        detail = audit.json().get("detail") or ""
        assert "Windows" in detail or "not installed" in detail.lower() or "HardeningKitty" in detail


def test_cloud_lab_sample_file_exists():
    root = Path(__file__).resolve().parents[1]
    path = root / "data" / "samples" / "cloud_findings_lab.json"
    assert path.is_file()
