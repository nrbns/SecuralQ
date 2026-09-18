"""HTTP-layer tests for log management / SIEM
(app.services.log_management + app.log_management_api).

Coverage that matters most:
  * ingestion is real (POST /api/logs/ingest -> row in ingested_logs -> shows
    up in GET /api/logs)
  * search unifies ingested_logs + audit_log without relabeling sources
  * the repeated-auth-failure correlation rule fires off *real* login
    failures recorded by app.auth (not a synthetic fixture) and creates a
    real incident, and is idempotent (won't double-create while one is open)
"""

from __future__ import annotations

from tests._http_test_utils import configure_isolated_settings


def _client_and_token(tmp_path, monkeypatch, username="log_tester"):
    configure_isolated_settings(monkeypatch, tmp_path)
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    from app.auth import login, register_user
    from app.log_management_api import router as log_router
    from app.tenancy import ensure_tenant_schema

    ensure_tenant_schema()
    register_user(username, "password123", role="admin")
    u, token = login(username, "password123")

    test_app = FastAPI()
    test_app.include_router(log_router)
    client = TestClient(test_app)
    return client, token, u.id


def _auth(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


def test_logs_require_auth(tmp_path, monkeypatch):
    client, _token, _uid = _client_and_token(tmp_path, monkeypatch)
    res = client.get("/api/logs")
    assert res.status_code == 401


def test_ingest_and_search_roundtrip(tmp_path, monkeypatch):
    client, token, _uid = _client_and_token(tmp_path, monkeypatch)
    res = client.post(
        "/api/logs/ingest",
        headers=_auth(token),
        json={
            "host": "web-01",
            "actor": "deploy-bot",
            "severity": "medium",
            "event_type": "config_change",
            "message": "nginx.conf modified",
        },
    )
    assert res.status_code == 200, res.text
    body = res.json()
    assert body["source"] == "api"

    search = client.get("/api/logs", headers=_auth(token))
    assert search.status_code == 200
    logs = search.json()["logs"]
    match = next((l for l in logs if l["message"] == "nginx.conf modified"), None)
    assert match is not None
    assert match["source"] == "ingested"
    assert match["host"] == "web-01"


def test_search_unifies_audit_log_without_relabeling(tmp_path, monkeypatch):
    client, token, uid = _client_and_token(tmp_path, monkeypatch)
    from app.db import audit

    audit("evidence_link", uid, {"id": "ev1"})

    res = client.get("/api/logs?source=audit", headers=_auth(token))
    assert res.status_code == 200
    logs = res.json()["logs"]
    assert any(l["event_type"] == "evidence_link" and l["source"] == "audit" for l in logs)
    # Filtering by 'ingested' must not leak audit rows in under a different tag.
    res2 = client.get("/api/logs?source=ingested", headers=_auth(token))
    assert all(l["source"] == "ingested" for l in res2.json()["logs"])


def test_severity_filter(tmp_path, monkeypatch):
    client, token, _uid = _client_and_token(tmp_path, monkeypatch)
    client.post(
        "/api/logs/ingest",
        headers=_auth(token),
        json={"severity": "critical", "message": "critical thing", "event_type": "x"},
    )
    client.post(
        "/api/logs/ingest",
        headers=_auth(token),
        json={"severity": "low", "message": "low thing", "event_type": "x"},
    )
    res = client.get("/api/logs?source=ingested&severity=critical", headers=_auth(token))
    logs = res.json()["logs"]
    assert len(logs) == 1
    assert logs[0]["message"] == "critical thing"


def test_stats_reflect_real_counts(tmp_path, monkeypatch):
    client, token, _uid = _client_and_token(tmp_path, monkeypatch)
    client.post(
        "/api/logs/ingest", headers=_auth(token), json={"message": "m1", "event_type": "x"}
    )
    client.post(
        "/api/logs/ingest", headers=_auth(token), json={"message": "m2", "event_type": "x"}
    )
    stats = client.get("/api/logs/stats", headers=_auth(token)).json()
    assert stats["ingested_count"] == 2
    assert stats["correlation_rule"]["name"] == "repeated-auth-failure"


def test_real_login_failures_trigger_correlation_incident(tmp_path, monkeypatch):
    """This is the important one: the correlation rule must fire from actual
    app.auth.login() failures, not a fixture standing in for them."""
    configure_isolated_settings(monkeypatch, tmp_path)
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    from app.auth import login, register_user
    from app.log_management_api import router as log_router
    from app.tenancy import ensure_tenant_schema

    ensure_tenant_schema()
    register_user("brute_target", "correctpassword1", role="admin")
    _u, token = login("brute_target", "correctpassword1")

    test_app = FastAPI()
    test_app.include_router(log_router)
    client = TestClient(test_app)

    # Real repeated failed logins against the real auth module.
    for _ in range(6):
        try:
            login("brute_target", "wrongpassword")
        except ValueError:
            pass

    res = client.post("/api/logs/ingest", headers=_auth(token), json={"message": "trigger check", "event_type": "noop"})
    assert res.status_code == 200
    assert len(res.json()["incidents_created"]) == 1
    inc = res.json()["incidents_created"][0]
    assert "brute_target" in inc["title"]
    assert inc["source"] == "log_correlation"

    # Idempotent: doing it again while the incident is still open must not
    # create a second one.
    for _ in range(6):
        try:
            login("brute_target", "wrongpassword")
        except ValueError:
            pass
    res2 = client.post("/api/logs/ingest", headers=_auth(token), json={"message": "trigger check 2", "event_type": "noop"})
    assert res2.json()["incidents_created"] == []


def test_unknown_username_failures_are_still_grouped(tmp_path, monkeypatch):
    """A brute force against a username that doesn't exist must still be
    catchable -- app.auth audits it under a synthetic 'unknown:<username>'
    actor rather than silently dropping it."""
    configure_isolated_settings(monkeypatch, tmp_path)
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    from app.auth import login, register_user
    from app.log_management_api import router as log_router
    from app.tenancy import ensure_tenant_schema

    ensure_tenant_schema()
    register_user("someone_real", "password123", role="admin")
    _u, token = login("someone_real", "password123")

    test_app = FastAPI()
    test_app.include_router(log_router)
    client = TestClient(test_app)

    for _ in range(6):
        try:
            login("ghost_user_does_not_exist", "whatever")
        except ValueError:
            pass

    res = client.post("/api/logs/ingest", headers=_auth(token), json={"message": "trigger", "event_type": "noop"})
    assert len(res.json()["incidents_created"]) == 1
