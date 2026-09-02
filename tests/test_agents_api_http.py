"""HTTP-layer tests for app/agents_api.py — the native SecuraIQ agent API.

Earlier suite coverage called agent backend functions (app.agents) directly,
never through the actual FastAPI routes, so auth wiring (user-bearer vs
agent-bearer), status codes, and route-shadowing (the literal `/threats` and
`/install-script/{platform}` segments vs the dynamic `/{agent_id}`) were
unverified. These tests exercise the real HTTP layer with fastapi's
TestClient, following the pattern already established in
tests/test_builtin_scanner.py (AUTH_ENABLED=true, register_user + login for
a real bearer token, a minimal FastAPI app wrapping only the router under
test).
"""

from __future__ import annotations

import pytest

from tests._http_test_utils import configure_isolated_settings


def _reload_db(monkeypatch, data_dir):
    return configure_isolated_settings(monkeypatch, data_dir)


def _client_and_token(tmp_path, monkeypatch, username="agent_tester"):
    _reload_db(monkeypatch, tmp_path)
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    from app.agents_api import router as agents_router
    from app.auth import login, register_user
    from app.tenancy import ensure_tenant_schema

    ensure_tenant_schema()
    register_user(username, "password123", role="admin")
    _u, token = login(username, "password123")

    test_app = FastAPI()
    test_app.include_router(agents_router)
    client = TestClient(test_app)
    return client, token


def _auth(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


# --- enrollment (user-authed) ------------------------------------------------


def test_enroll_requires_auth(tmp_path, monkeypatch):
    client, _token = _client_and_token(tmp_path, monkeypatch)
    res = client.post("/api/agents/enroll", json={"name": "web-01"})
    assert res.status_code == 401


def test_enroll_returns_agent_id_and_one_time_token(tmp_path, monkeypatch):
    client, token = _client_and_token(tmp_path, monkeypatch)
    res = client.post("/api/agents/enroll", json={"name": "web-01"}, headers=_auth(token))
    assert res.status_code == 200, res.text
    data = res.json()
    assert data["agent_id"]
    assert "." in data["agent_token"]
    assert "install_hint" in data and "linux" in data["install_hint"].lower()


def test_list_agents_empty_then_populated(tmp_path, monkeypatch):
    client, token = _client_and_token(tmp_path, monkeypatch)
    res = client.get("/api/agents", headers=_auth(token))
    assert res.status_code == 200
    assert res.json()["agents"] == []

    client.post("/api/agents/enroll", json={"name": "db-01"}, headers=_auth(token))
    res = client.get("/api/agents", headers=_auth(token))
    agents = res.json()["agents"]
    assert len(agents) == 1
    assert agents[0]["name"] == "db-01"


def test_get_agent_404_for_unknown(tmp_path, monkeypatch):
    client, token = _client_and_token(tmp_path, monkeypatch)
    res = client.get("/api/agents/does-not-exist", headers=_auth(token))
    assert res.status_code == 404


def test_get_agent_cross_user_isolation(tmp_path, monkeypatch):
    """A user cannot fetch another user's agent by id."""
    client, token_a = _client_and_token(tmp_path, monkeypatch, username="owner_a")
    from app.auth import login, register_user

    register_user("owner_b", "password123", role="admin")
    _u, token_b = login("owner_b", "password123")

    enroll = client.post("/api/agents/enroll", json={"name": "a-only"}, headers=_auth(token_a))
    agent_id = enroll.json()["agent_id"]

    res = client.get(f"/api/agents/{agent_id}", headers=_auth(token_b))
    assert res.status_code == 404


# --- install-script serving (no auth) ---------------------------------------


def test_install_script_served_without_auth(tmp_path, monkeypatch):
    client, _token = _client_and_token(tmp_path, monkeypatch)
    res = client.get("/api/agents/install-script")
    assert res.status_code == 200
    assert "SecuraIQ" in res.text or "sentinel" in res.text.lower()


@pytest.mark.parametrize("platform", ["linux", "macos", "windows"])
def test_install_script_platform_served_without_auth(tmp_path, monkeypatch, platform):
    client, _token = _client_and_token(tmp_path, monkeypatch)
    res = client.get(f"/api/agents/install-script/{platform}")
    assert res.status_code == 200
    assert len(res.text) > 100


def test_install_script_unknown_platform_404(tmp_path, monkeypatch):
    client, _token = _client_and_token(tmp_path, monkeypatch)
    res = client.get("/api/agents/install-script/solaris")
    assert res.status_code == 404


def test_install_script_route_not_shadowed_by_agent_id_route(tmp_path, monkeypatch):
    """`/install-script` and `/install-script/{platform}` are literal-segment
    routes registered ahead of the dynamic `/{agent_id}` catch-all — confirm
    they don't get swallowed as an agent_id lookup (which would 404 with a
    different error body, "Agent not found", instead of serving the script)."""
    client, _token = _client_and_token(tmp_path, monkeypatch)
    res = client.get("/api/agents/install-script")
    assert res.status_code == 200
    assert res.headers.get("content-type", "").startswith("text/x-python")


# --- agent-authed check-in ---------------------------------------------------


def test_checkin_rejects_missing_token(tmp_path, monkeypatch):
    client, _token = _client_and_token(tmp_path, monkeypatch)
    res = client.post("/api/agents/checkin", json={"hostname": "h1"})
    assert res.status_code == 401


def test_checkin_rejects_invalid_token(tmp_path, monkeypatch):
    client, _token = _client_and_token(tmp_path, monkeypatch)
    res = client.post(
        "/api/agents/checkin",
        json={"hostname": "h1"},
        headers={"Authorization": "Bearer bogus-agent-id.bogus-key"},
    )
    assert res.status_code == 401


def test_checkin_succeeds_with_real_agent_token(tmp_path, monkeypatch):
    client, token = _client_and_token(tmp_path, monkeypatch)
    enroll = client.post("/api/agents/enroll", json={"name": "srv-01"}, headers=_auth(token))
    agent_token = enroll.json()["agent_token"]

    res = client.post(
        "/api/agents/checkin",
        json={"hostname": "srv-01.internal", "ip": "10.0.0.5", "os": "linux"},
        headers={"Authorization": f"Bearer {agent_token}"},
    )
    assert res.status_code == 200, res.text
    assert res.json()["ok"] is True

    # reflected on the user-authed agent list
    listing = client.get("/api/agents", headers=_auth(token)).json()["agents"]
    assert listing[0]["hostname"] == "srv-01.internal"
    assert listing[0]["checkin_count"] >= 1


def test_checkin_rejects_revoked_agent(tmp_path, monkeypatch):
    client, token = _client_and_token(tmp_path, monkeypatch)
    enroll = client.post("/api/agents/enroll", json={"name": "srv-02"}, headers=_auth(token))
    agent_id = enroll.json()["agent_id"]
    agent_token = enroll.json()["agent_token"]

    revoke = client.post(f"/api/agents/{agent_id}/revoke", headers=_auth(token))
    assert revoke.status_code == 200

    res = client.post(
        "/api/agents/checkin",
        json={"hostname": "srv-02"},
        headers={"Authorization": f"Bearer {agent_token}"},
    )
    assert res.status_code == 401


# --- agent-authed threat reporting -------------------------------------------


def test_threat_report_rejects_missing_token(tmp_path, monkeypatch):
    client, _token = _client_and_token(tmp_path, monkeypatch)
    res = client.post("/api/agents/threat", json={"detections": []})
    assert res.status_code == 401


def test_threat_report_creates_finding_and_is_listed(tmp_path, monkeypatch):
    client, token = _client_and_token(tmp_path, monkeypatch)
    enroll = client.post("/api/agents/enroll", json={"name": "srv-03"}, headers=_auth(token))
    agent_id = enroll.json()["agent_id"]
    agent_token = enroll.json()["agent_token"]

    # check in first so the threat has a hostname/asset context
    client.post(
        "/api/agents/checkin",
        json={"hostname": "srv-03.internal"},
        headers={"Authorization": f"Bearer {agent_token}"},
    )

    res = client.post(
        "/api/agents/threat",
        json={
            "detections": [
                {
                    "severity": "critical",
                    "category": "ransomware",
                    "title": "Ransomware indicator detected",
                    "detail": "Mass file rename with known ransom-note filename",
                    "target": "/var/www/uploads",
                }
            ]
        },
        headers={"Authorization": f"Bearer {agent_token}"},
    )
    assert res.status_code == 200, res.text
    body = res.json()
    assert body["ok"] is True
    assert body["created"] == 1
    assert body["detections"][0]["incident_id"]  # critical -> incident opened
    assert body["detections"][0]["vuln_id"]  # always -> finding created

    # visible via the user-authed threats endpoints
    all_threats = client.get("/api/agents/threats", headers=_auth(token)).json()["threats"]
    assert len(all_threats) == 1
    assert all_threats[0]["severity"] == "critical"

    scoped = client.get(f"/api/agents/{agent_id}/threats", headers=_auth(token)).json()["threats"]
    assert len(scoped) == 1


def test_threats_route_not_shadowed_by_agent_id_route(tmp_path, monkeypatch):
    """`/threats` is registered ahead of `/{agent_id}` — confirm the literal
    list-all endpoint isn't swallowed as an agent_id lookup for the literal
    string "threats"."""
    client, token = _client_and_token(tmp_path, monkeypatch)
    res = client.get("/api/agents/threats", headers=_auth(token))
    assert res.status_code == 200
    assert res.json() == {"threats": []}


def test_agent_threats_scoped_to_owning_user(tmp_path, monkeypatch):
    client, token_a = _client_and_token(tmp_path, monkeypatch, username="threat_owner_a")
    from app.auth import login, register_user

    register_user("threat_owner_b", "password123", role="admin")
    _u, token_b = login("threat_owner_b", "password123")

    enroll = client.post("/api/agents/enroll", json={"name": "srv-04"}, headers=_auth(token_a))
    agent_id = enroll.json()["agent_id"]

    res = client.get(f"/api/agents/{agent_id}/threats", headers=_auth(token_b))
    assert res.status_code == 404


# --- revoke / delete ----------------------------------------------------------


def test_revoke_agent_404_for_unknown(tmp_path, monkeypatch):
    client, token = _client_and_token(tmp_path, monkeypatch)
    res = client.post("/api/agents/does-not-exist/revoke", headers=_auth(token))
    assert res.status_code == 404


def test_delete_agent_removes_it(tmp_path, monkeypatch):
    client, token = _client_and_token(tmp_path, monkeypatch)
    enroll = client.post("/api/agents/enroll", json={"name": "to-delete"}, headers=_auth(token))
    agent_id = enroll.json()["agent_id"]

    res = client.delete(f"/api/agents/{agent_id}", headers=_auth(token))
    assert res.status_code == 200
    assert res.json()["ok"] is True

    res2 = client.get(f"/api/agents/{agent_id}", headers=_auth(token))
    assert res2.status_code == 404

    # deleting again is a genuine 404, not a silent success
    res3 = client.delete(f"/api/agents/{agent_id}", headers=_auth(token))
    assert res3.status_code == 404


def test_delete_agent_requires_auth(tmp_path, monkeypatch):
    client, token = _client_and_token(tmp_path, monkeypatch)
    enroll = client.post("/api/agents/enroll", json={"name": "needs-auth"}, headers=_auth(token))
    agent_id = enroll.json()["agent_id"]

    res = client.delete(f"/api/agents/{agent_id}")
    assert res.status_code == 401


# --- command channel (patch execution + verification loop) ------------------


def test_queue_command_requires_auth(tmp_path, monkeypatch):
    client, token = _client_and_token(tmp_path, monkeypatch)
    enroll = client.post("/api/agents/enroll", json={"name": "srv-05"}, headers=_auth(token))
    agent_id = enroll.json()["agent_id"]
    res = client.post(f"/api/agents/{agent_id}/commands", json={"kind": "patch_package", "payload": {}})
    assert res.status_code == 401


def test_queue_command_rejects_unsupported_kind(tmp_path, monkeypatch):
    client, token = _client_and_token(tmp_path, monkeypatch)
    enroll = client.post("/api/agents/enroll", json={"name": "srv-06"}, headers=_auth(token))
    agent_id = enroll.json()["agent_id"]
    res = client.post(
        f"/api/agents/{agent_id}/commands",
        json={"kind": "run_arbitrary_shell", "payload": {"cmd": "rm -rf /"}},
        headers=_auth(token),
    )
    assert res.status_code == 400


def test_queue_command_rejects_unknown_agent(tmp_path, monkeypatch):
    client, token = _client_and_token(tmp_path, monkeypatch)
    res = client.post(
        "/api/agents/does-not-exist/commands",
        json={"kind": "patch_package", "payload": {"manager": "apt", "package": "nginx"}},
        headers=_auth(token),
    )
    assert res.status_code == 400


def test_queued_command_not_delivered_until_approved(tmp_path, monkeypatch):
    """A freshly requested command sits in 'pending_approval' and is NOT
    handed to the agent on check-in — only after an explicit approve call."""
    client, token = _client_and_token(tmp_path, monkeypatch)
    enroll = client.post("/api/agents/enroll", json={"name": "srv-11"}, headers=_auth(token))
    agent_id = enroll.json()["agent_id"]
    agent_token = enroll.json()["agent_token"]

    requested = client.post(
        f"/api/agents/{agent_id}/commands",
        json={"kind": "patch_package", "payload": {"manager": "apt", "package": "nginx"}},
        headers=_auth(token),
    )
    assert requested.status_code == 200, requested.text
    assert requested.json()["status"] == "pending_approval"

    checkin = client.post(
        "/api/agents/checkin",
        json={"hostname": "srv-11.internal", "os": "linux"},
        headers={"Authorization": f"Bearer {agent_token}"},
    )
    assert checkin.json()["commands"] == []

    pending = client.get("/api/agents/commands/pending", headers=_auth(token)).json()["commands"]
    assert len(pending) == 1
    assert pending[0]["id"] == requested.json()["id"]


def test_approve_command_requires_auth(tmp_path, monkeypatch):
    client, token = _client_and_token(tmp_path, monkeypatch)
    enroll = client.post("/api/agents/enroll", json={"name": "srv-12"}, headers=_auth(token))
    agent_id = enroll.json()["agent_id"]
    requested = client.post(
        f"/api/agents/{agent_id}/commands",
        json={"kind": "patch_package", "payload": {"manager": "apt", "package": "curl"}},
        headers=_auth(token),
    )
    command_id = requested.json()["id"]
    res = client.post(f"/api/agents/{agent_id}/commands/{command_id}/approve")
    assert res.status_code == 401


def test_approve_command_requires_admin_role_when_auth_enabled(tmp_path, monkeypatch):
    client, admin_token = _client_and_token(tmp_path, monkeypatch, username="approver_admin")
    from app.auth import login, register_user

    register_user("approver_viewer", "password123", role="user")
    _u, viewer_token = login("approver_viewer", "password123")

    enroll = client.post("/api/agents/enroll", json={"name": "srv-13"}, headers=_auth(admin_token))
    agent_id = enroll.json()["agent_id"]
    requested = client.post(
        f"/api/agents/{agent_id}/commands",
        json={"kind": "patch_package", "payload": {"manager": "apt", "package": "curl"}},
        headers=_auth(admin_token),
    )
    command_id = requested.json()["id"]

    # a non-admin cannot approve
    res = client.post(
        f"/api/agents/{agent_id}/commands/{command_id}/approve", headers=_auth(viewer_token)
    )
    assert res.status_code == 403

    # the admin can
    res2 = client.post(
        f"/api/agents/{agent_id}/commands/{command_id}/approve", headers=_auth(admin_token)
    )
    assert res2.status_code == 200, res2.text
    assert res2.json()["status"] == "queued"


def test_reject_command_marks_rejected_and_never_delivered(tmp_path, monkeypatch):
    client, token = _client_and_token(tmp_path, monkeypatch)
    enroll = client.post("/api/agents/enroll", json={"name": "srv-14"}, headers=_auth(token))
    agent_id = enroll.json()["agent_id"]
    agent_token = enroll.json()["agent_token"]
    requested = client.post(
        f"/api/agents/{agent_id}/commands",
        json={"kind": "patch_package", "payload": {"manager": "apt", "package": "curl"}},
        headers=_auth(token),
    )
    command_id = requested.json()["id"]

    res = client.post(
        f"/api/agents/{agent_id}/commands/{command_id}/reject",
        json={"reason": "not needed"},
        headers=_auth(token),
    )
    assert res.status_code == 200, res.text
    assert res.json()["status"] == "rejected"

    checkin = client.post(
        "/api/agents/checkin",
        json={"hostname": "srv-14.internal", "os": "linux"},
        headers={"Authorization": f"Bearer {agent_token}"},
    )
    assert checkin.json()["commands"] == []

    # approving an already-rejected command is rejected (not pending anymore)
    res2 = client.post(f"/api/agents/{agent_id}/commands/{command_id}/approve", headers=_auth(token))
    assert res2.status_code == 400


def test_command_delivered_on_next_checkin_and_result_reported(tmp_path, monkeypatch):
    """The full loop through the HTTP layer: request (user-authed) -> approve
    (user-authed, admin) -> the next check-in response carries it
    (agent-authed) -> the agent posts a result (agent-authed) -> it shows up
    done in the user-authed history, with the same command never
    re-delivered on a third check-in."""
    client, token = _client_and_token(tmp_path, monkeypatch)
    enroll = client.post("/api/agents/enroll", json={"name": "srv-07"}, headers=_auth(token))
    agent_id = enroll.json()["agent_id"]
    agent_token = enroll.json()["agent_token"]

    # first check-in: nothing queued yet
    first = client.post(
        "/api/agents/checkin",
        json={"hostname": "srv-07.internal", "os": "linux"},
        headers={"Authorization": f"Bearer {agent_token}"},
    )
    assert first.json()["commands"] == []

    requested = client.post(
        f"/api/agents/{agent_id}/commands",
        json={"kind": "patch_package", "payload": {"manager": "apt", "package": "openssl"}},
        headers=_auth(token),
    )
    assert requested.status_code == 200, requested.text
    command_id = requested.json()["id"]
    assert requested.json()["status"] == "pending_approval"

    approved = client.post(f"/api/agents/{agent_id}/commands/{command_id}/approve", headers=_auth(token))
    assert approved.status_code == 200, approved.text
    assert approved.json()["status"] == "queued"

    # second check-in: the command is delivered
    second = client.post(
        "/api/agents/checkin",
        json={"hostname": "srv-07.internal", "os": "linux"},
        headers={"Authorization": f"Bearer {agent_token}"},
    )
    delivered = second.json()["commands"]
    assert len(delivered) == 1
    assert delivered[0]["id"] == command_id
    assert delivered[0]["kind"] == "patch_package"
    assert delivered[0]["payload"]["package"] == "openssl"

    # third check-in: not redelivered — it's "sent", not "queued" anymore
    third = client.post(
        "/api/agents/checkin",
        json={"hostname": "srv-07.internal", "os": "linux"},
        headers={"Authorization": f"Bearer {agent_token}"},
    )
    assert third.json()["commands"] == []

    # agent reports the outcome
    result = client.post(
        f"/api/agents/commands/{command_id}/result",
        json={"status": "done", "result": {"ok": True, "old_version": "1.1.1", "new_version": "3.0.2"}},
        headers={"Authorization": f"Bearer {agent_token}"},
    )
    assert result.status_code == 200, result.text
    assert result.json()["status"] == "done"

    history = client.get(f"/api/agents/{agent_id}/commands", headers=_auth(token)).json()["commands"]
    assert len(history) == 1
    assert history[0]["status"] == "done"
    assert history[0]["result"]["new_version"] == "3.0.2"


def test_command_result_requires_agent_token_not_user_token(tmp_path, monkeypatch):
    client, token = _client_and_token(tmp_path, monkeypatch)
    enroll = client.post("/api/agents/enroll", json={"name": "srv-08"}, headers=_auth(token))
    agent_id = enroll.json()["agent_id"]
    agent_token = enroll.json()["agent_token"]
    client.post(
        "/api/agents/checkin", json={"hostname": "srv-08"}, headers={"Authorization": f"Bearer {agent_token}"}
    )
    queued = client.post(
        f"/api/agents/{agent_id}/commands",
        json={"kind": "patch_package", "payload": {"manager": "apt", "package": "curl"}},
        headers=_auth(token),
    )
    command_id = queued.json()["id"]

    # a user bearer token is not a valid agent token
    res = client.post(
        f"/api/agents/commands/{command_id}/result",
        json={"status": "done", "result": {}},
        headers=_auth(token),
    )
    assert res.status_code == 401


def test_command_result_unknown_command_404(tmp_path, monkeypatch):
    client, token = _client_and_token(tmp_path, monkeypatch)
    enroll = client.post("/api/agents/enroll", json={"name": "srv-09"}, headers=_auth(token))
    agent_token = enroll.json()["agent_token"]
    res = client.post(
        "/api/agents/commands/does-not-exist/result",
        json={"status": "done", "result": {}},
        headers={"Authorization": f"Bearer {agent_token}"},
    )
    assert res.status_code == 404


def test_commands_list_scoped_to_owning_user(tmp_path, monkeypatch):
    client, token_a = _client_and_token(tmp_path, monkeypatch, username="cmd_owner_a")
    from app.auth import login, register_user

    register_user("cmd_owner_b", "password123", role="admin")
    _u, token_b = login("cmd_owner_b", "password123")

    enroll = client.post("/api/agents/enroll", json={"name": "srv-10"}, headers=_auth(token_a))
    agent_id = enroll.json()["agent_id"]

    res = client.get(f"/api/agents/{agent_id}/commands", headers=_auth(token_b))
    assert res.status_code == 404
