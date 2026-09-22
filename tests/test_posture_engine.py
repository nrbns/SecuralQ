"""Continuous Posture Engine — Layer B refresh (not deep scans)."""

from __future__ import annotations

from tests._http_test_utils import configure_isolated_settings


def _uid(monkeypatch, tmp_path, name="posture_user"):
    configure_isolated_settings(monkeypatch, tmp_path)
    from app.auth import login, register_user
    from app.tenancy import ensure_tenant_schema

    ensure_tenant_schema()
    register_user(name, "password123", role="admin")
    u, _ = login(name, "password123")
    return u.id


def test_posture_refresh_excludes_deep_scans(tmp_path, monkeypatch):
    uid = _uid(monkeypatch, tmp_path, "posture_a")
    from app.posture.orchestrator import run_posture_refresh
    from app.posture.refresh_policy import architecture_layers, list_refresh_policies

    layers = architecture_layers()
    assert "nmap" in layers["C_deep_scans"]["kinds"]
    assert "asset_health" in layers["B_posture_refresh"]["stages"]

    out = run_posture_refresh(uid, trigger="manual", force=True)
    assert out["ok"] is True
    assert out["status"] in {"completed", "partial"}
    assert "Nmap" in out["disclaimer"] or "nmap" in out["disclaimer"].lower()
    run = out["run"]
    assert run["trigger"] == "manual"
    assert run["assets_checked"] >= 0
    assert any(s.get("name") == "risk" for s in (run.get("stages") or []))
    # Policies mark deep scans as not part of posture
    deep = [p for p in list_refresh_policies() if p.get("includes_deep_scan")]
    assert deep
    assert all(p["layer"] == "C_deep_scan" for p in deep)


def test_refresh_now_idempotent_lock(tmp_path, monkeypatch):
    uid = _uid(monkeypatch, tmp_path, "posture_b")
    from app.posture.orchestrator import run_posture_refresh
    from app.posture.refresh_lock import acquire_refresh_lock, release_refresh_lock
    from app.tenancy import primary_org_id

    first = run_posture_refresh(uid, trigger="manual", force=True)
    assert first["ok"] is True
    oid = primary_org_id(uid) or uid
    key = f"posture:{oid}:posture"
    release_refresh_lock(key)
    assert acquire_refresh_lock(key, run_id="blocker", user_id=uid, ttl_sec=600)
    blocked = run_posture_refresh(uid, trigger="manual", force=True)
    assert blocked.get("status") == "cancelled" or blocked.get("reason") == "refresh_already_running"
    release_refresh_lock(key, run_id="blocker")


def test_dashboard_baseline_drift_and_api(tmp_path, monkeypatch):
    uid = _uid(monkeypatch, tmp_path, "posture_c")
    from app.posture.drift import create_baseline, detect_drift
    from app.posture.orchestrator import run_posture_refresh
    from app.posture.views import posture_dashboard, posture_health, posture_history

    run_posture_refresh(uid, trigger="manual", force=True)
    dash = posture_dashboard(uid)
    assert dash["ok"] is True
    assert dash["engine"].startswith("SecuraIQ")
    assert "layers" in dash
    hist = posture_history(uid)
    assert hist["count"] >= 1

    base = create_baseline(uid, name="v1")
    assert base["version"] >= 1
    # Second refresh then drift
    run_posture_refresh(uid, trigger="manual", force=True)
    drift = detect_drift(uid)
    assert drift["available"] is True

    health = posture_health()
    assert health["handler_registered"] is True or health["scheduler"] in {
        "healthy",
        "unregistered",
    }

    # HTTP smoke
    configure_isolated_settings(monkeypatch, tmp_path / "api")
    from fastapi.testclient import TestClient

    from app.auth import login, register_user
    from app.main import app
    from app.tenancy import ensure_tenant_schema

    ensure_tenant_schema()
    register_user("posture_api", "password123", role="admin")
    _, token = login("posture_api", "password123")
    client = TestClient(app)
    headers = {"Authorization": f"Bearer {token}"}
    r = client.get("/api/posture/dashboard", headers=headers)
    assert r.status_code == 200, r.text
    r2 = client.post("/api/posture/refresh", headers=headers, json={"force": True})
    assert r2.status_code == 200
    assert r2.json().get("ok") is True or r2.json().get("status") in {
        "completed",
        "partial",
        "cancelled",
    }
    r3 = client.get("/api/posture/policies", headers=headers)
    assert r3.status_code == 200
    assert "B_posture_refresh" in r3.json()["layers"]
