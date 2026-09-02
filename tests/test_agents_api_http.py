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


# --- patch campaigns ----------------------------------------------------------


def test_create_campaign_requires_auth(tmp_path, monkeypatch):
    client, token = _client_and_token(tmp_path, monkeypatch)
    enroll = client.post("/api/agents/enroll", json={"name": "camp-01"}, headers=_auth(token))
    agent_id = enroll.json()["agent_id"]
    res = client.post(
        "/api/agents/campaigns",
        json={"manager": "apt", "package": "nginx", "agent_ids": [agent_id]},
    )
    assert res.status_code == 401


def test_create_campaign_rejects_no_valid_targets(tmp_path, monkeypatch):
    client, token = _client_and_token(tmp_path, monkeypatch)
    res = client.post(
        "/api/agents/campaigns",
        json={"manager": "apt", "package": "nginx", "agent_ids": ["does-not-exist"]},
        headers=_auth(token),
    )
    assert res.status_code == 400


def test_campaign_creates_one_pending_command_per_target(tmp_path, monkeypatch):
    client, token = _client_and_token(tmp_path, monkeypatch)
    a1 = client.post("/api/agents/enroll", json={"name": "camp-a1"}, headers=_auth(token)).json()["agent_id"]
    a2 = client.post("/api/agents/enroll", json={"name": "camp-a2"}, headers=_auth(token)).json()["agent_id"]
    a3 = client.post("/api/agents/enroll", json={"name": "camp-a3"}, headers=_auth(token)).json()["agent_id"]

    res = client.post(
        "/api/agents/campaigns",
        json={
            "name": "Q3 OpenSSL rollout",
            "manager": "apt",
            "package": "openssl",
            "target_version": "3.0.2",
            "agent_ids": [a1, a2, a3],
        },
        headers=_auth(token),
    )
    assert res.status_code == 200, res.text
    body = res.json()
    campaign_id = body["id"]
    assert body["requested"] == 3
    assert body["failed_targets"] == []

    # each agent has exactly one pending command
    for aid in (a1, a2, a3):
        cmds = client.get(f"/api/agents/{aid}/commands", headers=_auth(token)).json()["commands"]
        assert len(cmds) == 1
        assert cmds[0]["status"] == "pending_approval"
        assert cmds[0]["campaign_id"] == campaign_id

    listing = client.get("/api/agents/campaigns", headers=_auth(token)).json()["campaigns"]
    assert len(listing) == 1
    assert listing[0]["summary"]["total"] == 3
    assert listing[0]["summary"]["pending_approval"] == 3

    detail = client.get(f"/api/agents/campaigns/{campaign_id}", headers=_auth(token)).json()
    assert detail["name"] == "Q3 OpenSSL rollout"
    assert len(detail["items"]) == 3


def test_campaign_partial_targets_reported_and_created(tmp_path, monkeypatch):
    client, token = _client_and_token(tmp_path, monkeypatch)
    a1 = client.post("/api/agents/enroll", json={"name": "camp-p1"}, headers=_auth(token)).json()["agent_id"]

    res = client.post(
        "/api/agents/campaigns",
        json={"manager": "apt", "package": "curl", "agent_ids": [a1, "bogus-agent"]},
        headers=_auth(token),
    )
    assert res.status_code == 200, res.text
    body = res.json()
    assert body["requested"] == 1
    assert len(body["failed_targets"]) == 1
    assert body["failed_targets"][0]["agent_id"] == "bogus-agent"


def test_campaign_approve_queues_all_pending_items(tmp_path, monkeypatch):
    client, token = _client_and_token(tmp_path, monkeypatch)
    a1 = client.post("/api/agents/enroll", json={"name": "camp-q1"}, headers=_auth(token)).json()["agent_id"]
    a2 = client.post("/api/agents/enroll", json={"name": "camp-q2"}, headers=_auth(token)).json()["agent_id"]

    created = client.post(
        "/api/agents/campaigns",
        json={"manager": "winget", "package": "7zip", "agent_ids": [a1, a2]},
        headers=_auth(token),
    )
    campaign_id = created.json()["id"]

    res = client.post(f"/api/agents/campaigns/{campaign_id}/approve", headers=_auth(token))
    assert res.status_code == 200, res.text
    assert res.json()["approved"] == 2

    detail = client.get(f"/api/agents/campaigns/{campaign_id}", headers=_auth(token)).json()
    statuses = {item["status"] for item in detail["items"]}
    assert statuses == {"queued"}
    assert detail["summary"]["queued"] == 2
    assert detail["summary"]["pending_approval"] == 0


def test_campaign_approve_requires_admin_role_when_auth_enabled(tmp_path, monkeypatch):
    client, admin_token = _client_and_token(tmp_path, monkeypatch, username="camp_admin")
    from app.auth import login, register_user

    register_user("camp_viewer", "password123", role="user")
    _u, viewer_token = login("camp_viewer", "password123")

    a1 = client.post("/api/agents/enroll", json={"name": "camp-r1"}, headers=_auth(admin_token)).json()["agent_id"]
    created = client.post(
        "/api/agents/campaigns",
        json={"manager": "apt", "package": "vim", "agent_ids": [a1]},
        headers=_auth(admin_token),
    )
    campaign_id = created.json()["id"]

    res = client.post(f"/api/agents/campaigns/{campaign_id}/approve", headers=_auth(viewer_token))
    assert res.status_code == 403


def test_campaign_reject_marks_items_rejected_and_campaign_canceled(tmp_path, monkeypatch):
    client, token = _client_and_token(tmp_path, monkeypatch)
    a1 = client.post("/api/agents/enroll", json={"name": "camp-x1"}, headers=_auth(token)).json()["agent_id"]

    created = client.post(
        "/api/agents/campaigns",
        json={"manager": "apt", "package": "curl", "agent_ids": [a1]},
        headers=_auth(token),
    )
    campaign_id = created.json()["id"]

    res = client.post(
        f"/api/agents/campaigns/{campaign_id}/reject",
        json={"reason": "not this quarter"},
        headers=_auth(token),
    )
    assert res.status_code == 200, res.text
    assert res.json()["rejected"] == 1

    detail = client.get(f"/api/agents/campaigns/{campaign_id}", headers=_auth(token)).json()
    assert detail["status"] == "canceled"
    assert detail["items"][0]["status"] == "rejected"


def test_campaign_get_404_for_unknown_or_other_user(tmp_path, monkeypatch):
    client, token_a = _client_and_token(tmp_path, monkeypatch, username="camp_owner_a")
    from app.auth import login, register_user

    register_user("camp_owner_b", "password123", role="admin")
    _u, token_b = login("camp_owner_b", "password123")

    a1 = client.post("/api/agents/enroll", json={"name": "camp-y1"}, headers=_auth(token_a)).json()["agent_id"]
    created = client.post(
        "/api/agents/campaigns",
        json={"manager": "apt", "package": "curl", "agent_ids": [a1]},
        headers=_auth(token_a),
    )
    campaign_id = created.json()["id"]

    res_unknown = client.get("/api/agents/campaigns/does-not-exist", headers=_auth(token_a))
    assert res_unknown.status_code == 404

    res_cross_user = client.get(f"/api/agents/campaigns/{campaign_id}", headers=_auth(token_b))
    assert res_cross_user.status_code == 404


# --- patch rings + maintenance windows ---------------------------------------


def _run_command_to_done(client, token, agent_id, agent_token, command_id, *, status="done"):
    """Approve a command, deliver it via check-in, and report its result —
    the same sequence a real ring item goes through."""
    approved = client.post(f"/api/agents/{agent_id}/commands/{command_id}/approve", headers=_auth(token))
    assert approved.status_code == 200, approved.text
    checkin = client.post(
        "/api/agents/checkin",
        json={"hostname": "ring-host", "os": "linux"},
        headers={"Authorization": f"Bearer {agent_token}"},
    )
    delivered = checkin.json()["commands"]
    assert any(c["id"] == command_id for c in delivered), f"command {command_id} not delivered: {delivered}"
    result = client.post(
        f"/api/agents/commands/{command_id}/result",
        json={"status": status, "result": {"ok": status == "done"}},
        headers={"Authorization": f"Bearer {agent_token}"},
    )
    assert result.status_code == 200, result.text


def test_campaign_rings_created_only_one_at_a_time(tmp_path, monkeypatch):
    """A ringed campaign only creates ring 0's commands up front — ring 1
    doesn't exist as a command until ring 0 resolves."""
    client, token = _client_and_token(tmp_path, monkeypatch)
    enroll1 = client.post("/api/agents/enroll", json={"name": "ring-a1"}, headers=_auth(token))
    a1, a1_tok = enroll1.json()["agent_id"], enroll1.json()["agent_token"]
    enroll2 = client.post("/api/agents/enroll", json={"name": "ring-a2"}, headers=_auth(token))
    a2 = enroll2.json()["agent_id"]

    created = client.post(
        "/api/agents/campaigns",
        json={"manager": "apt", "package": "nginx", "rings": [[a1], [a2]]},
        headers=_auth(token),
    )
    assert created.status_code == 200, created.text
    assert created.json()["rings"] == 2
    assert created.json()["requested"] == 1  # only ring 0

    ring1_cmds = client.get(f"/api/agents/{a2}/commands", headers=_auth(token)).json()["commands"]
    assert ring1_cmds == []  # ring 1 not created yet


def test_campaign_ring_advances_on_success(tmp_path, monkeypatch):
    client, token = _client_and_token(tmp_path, monkeypatch)
    enroll1 = client.post("/api/agents/enroll", json={"name": "ring-b1"}, headers=_auth(token))
    a1, a1_tok = enroll1.json()["agent_id"], enroll1.json()["agent_token"]
    enroll2 = client.post("/api/agents/enroll", json={"name": "ring-b2"}, headers=_auth(token))
    a2, a2_tok = enroll2.json()["agent_id"], enroll2.json()["agent_token"]

    created = client.post(
        "/api/agents/campaigns",
        json={"manager": "apt", "package": "curl", "rings": [[a1], [a2]], "ring_threshold_pct": 100},
        headers=_auth(token),
    )
    campaign_id = created.json()["id"]
    ring0_cmd = client.get(f"/api/agents/{a1}/commands", headers=_auth(token)).json()["commands"][0]

    _run_command_to_done(client, token, a1, a1_tok, ring0_cmd["id"], status="done")

    # ring 1 should now exist, pending approval
    ring1_cmds = client.get(f"/api/agents/{a2}/commands", headers=_auth(token)).json()["commands"]
    assert len(ring1_cmds) == 1
    assert ring1_cmds[0]["status"] == "pending_approval"
    assert ring1_cmds[0]["campaign_id"] == campaign_id

    _run_command_to_done(client, token, a2, a2_tok, ring1_cmds[0]["id"], status="done")

    detail = client.get(f"/api/agents/campaigns/{campaign_id}", headers=_auth(token)).json()
    assert detail["status"] == "completed"
    assert len(detail["items"]) == 2


def test_campaign_ring_halts_on_failure_below_threshold(tmp_path, monkeypatch):
    client, token = _client_and_token(tmp_path, monkeypatch)
    enroll1 = client.post("/api/agents/enroll", json={"name": "ring-c1"}, headers=_auth(token))
    a1, a1_tok = enroll1.json()["agent_id"], enroll1.json()["agent_token"]
    enroll2 = client.post("/api/agents/enroll", json={"name": "ring-c2"}, headers=_auth(token))
    a2 = enroll2.json()["agent_id"]

    created = client.post(
        "/api/agents/campaigns",
        json={"manager": "apt", "package": "curl", "rings": [[a1], [a2]], "ring_threshold_pct": 100},
        headers=_auth(token),
    )
    campaign_id = created.json()["id"]
    ring0_cmd = client.get(f"/api/agents/{a1}/commands", headers=_auth(token)).json()["commands"][0]

    _run_command_to_done(client, token, a1, a1_tok, ring0_cmd["id"], status="error")

    detail = client.get(f"/api/agents/campaigns/{campaign_id}", headers=_auth(token)).json()
    assert detail["status"] == "halted"
    # ring 1 was never created
    ring1_cmds = client.get(f"/api/agents/{a2}/commands", headers=_auth(token)).json()["commands"]
    assert ring1_cmds == []


def test_campaign_maintenance_window_holds_delivery(tmp_path, monkeypatch):
    """A command that's approved and queued is still not handed to the agent
    outside the campaign's maintenance window — it stays queued."""
    import datetime as _dt

    client, token = _client_and_token(tmp_path, monkeypatch)
    enroll = client.post("/api/agents/enroll", json={"name": "window-a1"}, headers=_auth(token))
    agent_id, agent_token = enroll.json()["agent_id"], enroll.json()["agent_token"]

    now_h = _dt.datetime.now(_dt.timezone.utc).hour
    excluded_start = (now_h + 2) % 24
    excluded_end = (now_h + 3) % 24

    created = client.post(
        "/api/agents/campaigns",
        json={
            "manager": "apt",
            "package": "curl",
            "agent_ids": [agent_id],
            "window_start_hour": excluded_start,
            "window_end_hour": excluded_end,
        },
        headers=_auth(token),
    )
    campaign_id = created.json()["id"]
    cmd = client.get(f"/api/agents/{agent_id}/commands", headers=_auth(token)).json()["commands"][0]

    approved = client.post(f"/api/agents/{agent_id}/commands/{cmd['id']}/approve", headers=_auth(token))
    assert approved.status_code == 200
    assert approved.json()["status"] == "queued"

    checkin = client.post(
        "/api/agents/checkin",
        json={"hostname": "window-a1"},
        headers={"Authorization": f"Bearer {agent_token}"},
    )
    assert checkin.json()["commands"] == []  # held — outside the window

    # still queued, not lost
    cmds = client.get(f"/api/agents/{agent_id}/commands", headers=_auth(token)).json()["commands"]
    assert cmds[0]["status"] == "queued"
    detail = client.get(f"/api/agents/campaigns/{campaign_id}", headers=_auth(token)).json()
    assert detail["window_start_hour"] == excluded_start
    assert detail["window_end_hour"] == excluded_end


def test_campaign_maintenance_window_allows_delivery_when_inside(tmp_path, monkeypatch):
    import datetime as _dt

    client, token = _client_and_token(tmp_path, monkeypatch)
    enroll = client.post("/api/agents/enroll", json={"name": "window-b1"}, headers=_auth(token))
    agent_id, agent_token = enroll.json()["agent_id"], enroll.json()["agent_token"]

    now_h = _dt.datetime.now(_dt.timezone.utc).hour

    created = client.post(
        "/api/agents/campaigns",
        json={
            "manager": "apt",
            "package": "curl",
            "agent_ids": [agent_id],
            "window_start_hour": now_h,
            "window_end_hour": now_h,  # equal start/end == all day, always inside
        },
        headers=_auth(token),
    )
    cmd = client.get(f"/api/agents/{agent_id}/commands", headers=_auth(token)).json()["commands"][0]
    client.post(f"/api/agents/{agent_id}/commands/{cmd['id']}/approve", headers=_auth(token))

    checkin = client.post(
        "/api/agents/checkin",
        json={"hostname": "window-b1"},
        headers={"Authorization": f"Bearer {agent_token}"},
    )
    assert len(checkin.json()["commands"]) == 1
    _ = created


# --- ring-advancement hardening: idempotency + partial-success status -------


def test_ring_advance_is_idempotent_against_duplicate_calls(tmp_path, monkeypatch):
    """Two agents in the same ring resolving near-simultaneously must not
    create the next ring's commands twice. We can't force a real thread
    race deterministically, so this calls the internal advance function an
    extra time after the natural one (triggered by report_command_result)
    already ran — the resolved_ring compare-and-swap guard must make the
    second call a no-op either way."""
    client, token = _client_and_token(tmp_path, monkeypatch)
    enroll1 = client.post("/api/agents/enroll", json={"name": "idem-a1"}, headers=_auth(token))
    a1, a1_tok = enroll1.json()["agent_id"], enroll1.json()["agent_token"]
    enroll2 = client.post("/api/agents/enroll", json={"name": "idem-a2"}, headers=_auth(token))
    a2 = enroll2.json()["agent_id"]

    created = client.post(
        "/api/agents/campaigns",
        json={"manager": "apt", "package": "curl", "rings": [[a1], [a2]], "ring_threshold_pct": 100},
        headers=_auth(token),
    )
    campaign_id = created.json()["id"]
    ring0_cmd = client.get(f"/api/agents/{a1}/commands", headers=_auth(token)).json()["commands"][0]

    _run_command_to_done(client, token, a1, a1_tok, ring0_cmd["id"], status="done")

    ring1_cmds_before = client.get(f"/api/agents/{a2}/commands", headers=_auth(token)).json()["commands"]
    assert len(ring1_cmds_before) == 1

    # simulate a second, racing call trying to advance the same ring again
    from app.agents import _maybe_advance_campaign_ring

    _maybe_advance_campaign_ring(campaign_id, "local")
    _maybe_advance_campaign_ring(campaign_id, "local")

    ring1_cmds_after = client.get(f"/api/agents/{a2}/commands", headers=_auth(token)).json()["commands"]
    assert len(ring1_cmds_after) == 1  # still exactly one — no duplicate


def test_campaign_completed_with_failures_when_partial_success_clears_threshold(tmp_path, monkeypatch):
    """A ring can clear a <100% threshold while still having failed items —
    the campaign must land on 'completed_with_failures', not a clean
    'completed', so partial success stays visible."""
    client, token = _client_and_token(tmp_path, monkeypatch)
    enroll1 = client.post("/api/agents/enroll", json={"name": "partial-a1"}, headers=_auth(token))
    a1, a1_tok = enroll1.json()["agent_id"], enroll1.json()["agent_token"]
    enroll2 = client.post("/api/agents/enroll", json={"name": "partial-a2"}, headers=_auth(token))
    a2, a2_tok = enroll2.json()["agent_id"], enroll2.json()["agent_token"]

    created = client.post(
        "/api/agents/campaigns",
        json={"manager": "apt", "package": "curl", "agent_ids": [a1, a2], "ring_threshold_pct": 50},
        headers=_auth(token),
    )
    campaign_id = created.json()["id"]
    cmds = client.get(f"/api/agents/{a1}/commands", headers=_auth(token)).json()["commands"]
    cmd1 = cmds[0]
    cmd2 = client.get(f"/api/agents/{a2}/commands", headers=_auth(token)).json()["commands"][0]

    _run_command_to_done(client, token, a1, a1_tok, cmd1["id"], status="done")
    _run_command_to_done(client, token, a2, a2_tok, cmd2["id"], status="error")

    detail = client.get(f"/api/agents/campaigns/{campaign_id}", headers=_auth(token)).json()
    assert detail["status"] == "completed_with_failures"
    assert detail["summary"]["done"] == 1
    assert detail["summary"]["error"] == 1


def test_campaign_completed_cleanly_when_all_items_succeed(tmp_path, monkeypatch):
    client, token = _client_and_token(tmp_path, monkeypatch)
    enroll = client.post("/api/agents/enroll", json={"name": "clean-a1"}, headers=_auth(token))
    a1, a1_tok = enroll.json()["agent_id"], enroll.json()["agent_token"]

    created = client.post(
        "/api/agents/campaigns",
        json={"manager": "apt", "package": "curl", "agent_ids": [a1]},
        headers=_auth(token),
    )
    campaign_id = created.json()["id"]
    cmd = client.get(f"/api/agents/{a1}/commands", headers=_auth(token)).json()["commands"][0]
    _run_command_to_done(client, token, a1, a1_tok, cmd["id"], status="done")

    detail = client.get(f"/api/agents/campaigns/{campaign_id}", headers=_auth(token)).json()
    assert detail["status"] == "completed"


# --- waiting_for_agent (offline-agent visibility) ----------------------------


def test_queued_command_flagged_waiting_for_agent_when_agent_offline(tmp_path, monkeypatch):
    """A command that's approved and queued but never delivered because its
    agent has gone offline must be visibly flagged, not silently sit there
    looking like ordinary in-progress work."""
    client, token = _client_and_token(tmp_path, monkeypatch)
    enroll = client.post("/api/agents/enroll", json={"name": "offline-a1"}, headers=_auth(token))
    agent_id = enroll.json()["agent_id"]

    requested = client.post(
        f"/api/agents/{agent_id}/commands",
        json={"kind": "patch_package", "payload": {"manager": "apt", "package": "curl"}},
        headers=_auth(token),
    )
    command_id = requested.json()["id"]
    approved = client.post(f"/api/agents/{agent_id}/commands/{command_id}/approve", headers=_auth(token))
    assert approved.json()["status"] == "queued"

    # simulate the agent having gone offline (a stale last_checkin older
    # than app.agents.OFFLINE_AFTER_SEC)
    from app.agents import OFFLINE_AFTER_SEC
    from app.db import get_conn, now

    c = get_conn()
    c.execute("UPDATE securaiq_agents SET last_checkin = ? WHERE id = ?", (now() - OFFLINE_AFTER_SEC - 60, agent_id))
    c.commit()

    cmds = client.get(f"/api/agents/{agent_id}/commands", headers=_auth(token)).json()["commands"]
    assert cmds[0]["status"] == "queued"  # never silently marked done/anything else
    assert cmds[0]["waiting_for_agent"] is True


def test_queued_command_not_flagged_when_agent_recently_checked_in(tmp_path, monkeypatch):
    client, token = _client_and_token(tmp_path, monkeypatch)
    enroll = client.post("/api/agents/enroll", json={"name": "online-a1"}, headers=_auth(token))
    agent_id, agent_token = enroll.json()["agent_id"], enroll.json()["agent_token"]

    requested = client.post(
        f"/api/agents/{agent_id}/commands",
        json={"kind": "patch_package", "payload": {"manager": "apt", "package": "curl"}},
        headers=_auth(token),
    )
    command_id = requested.json()["id"]
    client.post(f"/api/agents/{agent_id}/commands/{command_id}/approve", headers=_auth(token))

    # a fresh check-in delivers the command (status flips to 'sent'), and
    # the agent is recently seen — should NOT be flagged waiting_for_agent
    client.post(
        "/api/agents/checkin",
        json={"hostname": "online-a1"},
        headers={"Authorization": f"Bearer {agent_token}"},
    )
    cmds = client.get(f"/api/agents/{agent_id}/commands", headers=_auth(token)).json()["commands"]
    assert cmds[0]["status"] == "sent"
    assert not cmds[0].get("waiting_for_agent")


# --- patch verification (executed != verified) -------------------------------


def _seed_installation(user_id, asset_id, *, product_name, installed_version, patch_status):
    """Directly seed a minimal software_installations/products/patch_status
    row set, bypassing the real inventory sync pipeline — this test only
    cares about app.jobs._verify_patch_command's read side."""
    from app.db import get_conn, new_id, now
    from app.software.models import ensure_schema as ensure_software_schema

    ensure_software_schema()
    c = get_conn()
    ts = now()
    product_id = new_id()
    c.execute(
        "INSERT INTO software_products (id, user_id, name, normalized_name, canonical_id, created_at, updated_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?)",
        (product_id, user_id, product_name, product_name.lower(), product_name.lower(), ts, ts),
    )
    installation_id = new_id()
    c.execute(
        "INSERT INTO software_installations "
        "(id, user_id, asset_id, asset_name, software_product_id, version, first_seen, last_seen, updated_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (installation_id, user_id, asset_id, "seeded-host", product_id, installed_version, ts, ts, ts),
    )
    patch_status_id = new_id()
    c.execute(
        "INSERT INTO patch_status (id, user_id, asset_id, software_installation_id, current_version, status, checked_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?)",
        (patch_status_id, user_id, asset_id, installation_id, installed_version, patch_status, ts),
    )
    c.commit()
    return installation_id


def _prepare_done_command_with_asset(client, token, name):
    """Enroll + check in an agent (so it gets a real asset_id), request +
    approve + deliver + report a 'done' patch_package command, and return
    (command_id, asset_id, user_id)."""
    enroll = client.post("/api/agents/enroll", json={"name": name}, headers=_auth(token))
    agent_id, agent_token = enroll.json()["agent_id"], enroll.json()["agent_token"]
    checkin = client.post(
        "/api/agents/checkin",
        json={"hostname": name, "os": "linux"},
        headers={"Authorization": f"Bearer {agent_token}"},
    )
    asset_id = checkin.json()["asset_id"]
    requested = client.post(
        f"/api/agents/{agent_id}/commands",
        json={"kind": "patch_package", "payload": {"manager": "apt", "package": "curl", "target_version": "8.5.0"}},
        headers=_auth(token),
    )
    command_id = requested.json()["id"]
    client.post(f"/api/agents/{agent_id}/commands/{command_id}/approve", headers=_auth(token))
    client.post(
        "/api/agents/checkin",
        json={"hostname": name, "os": "linux"},
        headers={"Authorization": f"Bearer {agent_token}"},
    )
    client.post(
        f"/api/agents/commands/{command_id}/result",
        json={"status": "done", "result": {"old_version": "7.0.0", "new_version": "8.5.0"}},
        headers={"Authorization": f"Bearer {agent_token}"},
    )
    return command_id, asset_id, agent_id


def test_done_command_starts_verification_pending_not_verified(tmp_path, monkeypatch):
    """'done' must never read as 'verified' — they're different claims."""
    client, token = _client_and_token(tmp_path, monkeypatch)
    command_id, asset_id, agent_id = _prepare_done_command_with_asset(client, token, "verify-pending-1")
    cmds = client.get(f"/api/agents/{agent_id}/commands", headers=_auth(token)).json()["commands"]
    done_cmd = next(c for c in cmds if c["id"] == command_id)
    assert done_cmd["status"] == "done"
    assert done_cmd["verification_status"] == "pending"


def test_verify_patch_command_confirms_up_to_date(tmp_path, monkeypatch):
    client, token = _client_and_token(tmp_path, monkeypatch)
    command_id, asset_id, agent_id = _prepare_done_command_with_asset(client, token, "verify-utd-1")

    from app.agents import get_agent

    agent = get_agent(agent_id)
    _seed_installation(agent["user_id"], asset_id, product_name="curl", installed_version="8.5.0", patch_status="up_to_date")

    from app.jobs import _verify_patch_command

    _verify_patch_command(command_id)

    cmds = client.get(f"/api/agents/{agent_id}/commands", headers=_auth(token)).json()["commands"]
    done_cmd = next(c for c in cmds if c["id"] == command_id)
    assert done_cmd["verification_status"] == "verified"
    assert "up to date" in done_cmd["verification_detail"].lower()


def test_verify_patch_command_flags_failure_when_still_outdated(tmp_path, monkeypatch):
    client, token = _client_and_token(tmp_path, monkeypatch)
    command_id, asset_id, agent_id = _prepare_done_command_with_asset(client, token, "verify-fail-1")

    from app.agents import get_agent

    agent = get_agent(agent_id)
    # patch reported "done" (old 7.0.0 -> new 8.5.0) but the re-synced
    # inventory shows the installed version never actually moved and
    # advisories still flag it — the patch didn't really take.
    _seed_installation(agent["user_id"], asset_id, product_name="curl", installed_version="7.0.0", patch_status="security_update")

    from app.jobs import _verify_patch_command

    _verify_patch_command(command_id)

    cmds = client.get(f"/api/agents/{agent_id}/commands", headers=_auth(token)).json()["commands"]
    done_cmd = next(c for c in cmds if c["id"] == command_id)
    assert done_cmd["verification_status"] == "verification_failed"


def test_verify_patch_command_unknown_when_package_not_in_inventory(tmp_path, monkeypatch):
    client, token = _client_and_token(tmp_path, monkeypatch)
    command_id, asset_id, agent_id = _prepare_done_command_with_asset(client, token, "verify-unknown-1")

    from app.jobs import _verify_patch_command

    _verify_patch_command(command_id)  # no software_installations row seeded at all

    cmds = client.get(f"/api/agents/{agent_id}/commands", headers=_auth(token)).json()["commands"]
    done_cmd = next(c for c in cmds if c["id"] == command_id)
    assert done_cmd["verification_status"] == "unknown"


def test_campaign_summary_reports_verification_breakdown(tmp_path, monkeypatch):
    client, token = _client_and_token(tmp_path, monkeypatch)
    enroll = client.post("/api/agents/enroll", json={"name": "verify-campaign-1"}, headers=_auth(token))
    agent_id, agent_token = enroll.json()["agent_id"], enroll.json()["agent_token"]

    created = client.post(
        "/api/agents/campaigns",
        json={"manager": "apt", "package": "curl", "agent_ids": [agent_id]},
        headers=_auth(token),
    )
    campaign_id = created.json()["id"]
    cmd = client.get(f"/api/agents/{agent_id}/commands", headers=_auth(token)).json()["commands"][0]
    # _run_command_to_done's check-in (hostname "ring-host") is what links
    # this agent to its real asset — fetch asset_id AFTER that, not before,
    # since checkin() (re)links the agent's asset by hostname.
    _run_command_to_done(client, token, agent_id, agent_token, cmd["id"], status="done")
    asset_id = client.get(f"/api/agents/{agent_id}", headers=_auth(token)).json()["asset_id"]

    detail = client.get(f"/api/agents/campaigns/{campaign_id}", headers=_auth(token)).json()
    assert detail["summary"]["done"] == 1
    assert detail["summary"]["verification_pending"] == 1
    assert detail["summary"]["verified"] == 0

    from app.agents import get_agent

    agent = get_agent(agent_id)
    _seed_installation(agent["user_id"], asset_id, product_name="curl", installed_version="9.9.9", patch_status="up_to_date")
    from app.jobs import _verify_patch_command

    _verify_patch_command(cmd["id"])

    detail2 = client.get(f"/api/agents/campaigns/{campaign_id}", headers=_auth(token)).json()
    assert detail2["summary"]["verified"] == 1
    assert detail2["summary"]["verification_pending"] == 0


# --- risk snapshots + campaign risk delta (feedback loop) --------------------


def _seed_advisory(user_id, product_id, *, cve_id, fixed_version):
    """Directly seed a software_advisories row — the exact-CVE link that
    _resolve_vulnerabilities_for_verified_patch reads to auto-close findings."""
    from app.db import get_conn, new_id, now

    c = get_conn()
    ts = now()
    c.execute(
        "INSERT INTO software_advisories "
        "(id, user_id, software_product_id, cve_id, fixed_version, severity, updated_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?)",
        (new_id(), user_id, product_id, cve_id, fixed_version, "high", ts),
    )
    c.commit()


def _seed_installation_with_product_id(user_id, asset_id, *, product_name, installed_version, patch_status):
    """Like _seed_installation but also returns the product_id, needed to
    link a software_advisories row to the same product."""
    from app.db import get_conn, new_id, now
    from app.software.models import ensure_schema as ensure_software_schema

    ensure_software_schema()
    c = get_conn()
    ts = now()
    product_id = new_id()
    c.execute(
        "INSERT INTO software_products (id, user_id, name, normalized_name, canonical_id, created_at, updated_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?)",
        (product_id, user_id, product_name, product_name.lower(), product_name.lower(), ts, ts),
    )
    installation_id = new_id()
    c.execute(
        "INSERT INTO software_installations "
        "(id, user_id, asset_id, asset_name, software_product_id, version, first_seen, last_seen, updated_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (installation_id, user_id, asset_id, "seeded-host", product_id, installed_version, ts, ts, ts),
    )
    patch_status_id = new_id()
    c.execute(
        "INSERT INTO patch_status (id, user_id, asset_id, software_installation_id, current_version, status, checked_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?)",
        (patch_status_id, user_id, asset_id, installation_id, installed_version, patch_status, ts),
    )
    c.commit()
    return installation_id, product_id


def test_campaign_create_snapshots_before_risk(tmp_path, monkeypatch):
    """Creating a campaign should take a 'before' risk snapshot immediately —
    the baseline half of the before/after remediation feedback loop."""
    client, token = _client_and_token(tmp_path, monkeypatch)
    enroll = client.post("/api/agents/enroll", json={"name": "snap-before-1"}, headers=_auth(token))
    agent_id = enroll.json()["agent_id"]

    from app.agents import get_agent
    from app.enterprise import create_asset, create_vulnerability

    agent = get_agent(agent_id)
    uid = agent["user_id"]
    asset = create_asset(uid, "snap-asset-1", asset_type="server", criticality="high")
    create_vulnerability(
        uid,
        {"asset_id": asset["id"], "asset_name": "snap-asset-1", "title": "Pre-existing risk", "severity": "high", "cvss": 7.0, "status": "open"},
    )

    created = client.post(
        "/api/agents/campaigns",
        json={"manager": "apt", "package": "curl", "agent_ids": [agent_id]},
        headers=_auth(token),
    )
    campaign_id = created.json()["id"]

    detail = client.get(f"/api/agents/campaigns/{campaign_id}", headers=_auth(token)).json()
    assert detail.get("risk_before") is not None
    assert detail["risk_before"] > 0
    # campaign is still active — no 'after' snapshot should exist yet
    assert detail.get("risk_after") is None
    assert detail.get("risk_reduction_pct") is None

    listing = client.get("/api/agents/campaigns", headers=_auth(token)).json()["campaigns"]
    row = next(c for c in listing if c["id"] == campaign_id)
    assert row.get("risk_before") == detail["risk_before"]


def test_campaign_after_snapshot_waits_for_verification_to_settle(tmp_path, monkeypatch):
    """A campaign reaching 'completed' with an unresolved (pending) patch
    verification must NOT get an 'after' snapshot yet — only once every
    'done' command's verification has settled does the risk delta appear."""
    client, token = _client_and_token(tmp_path, monkeypatch)
    enroll = client.post("/api/agents/enroll", json={"name": "snap-after-1"}, headers=_auth(token))
    agent_id, agent_token = enroll.json()["agent_id"], enroll.json()["agent_token"]

    from app.agents import get_agent
    from app.enterprise import create_asset, create_vulnerability

    agent = get_agent(agent_id)
    uid = agent["user_id"]
    asset = create_asset(uid, "snap-asset-2", asset_type="server", criticality="high")
    create_vulnerability(
        uid,
        {"asset_id": asset["id"], "asset_name": "snap-asset-2", "title": "Pre-existing risk 2", "severity": "high", "cvss": 7.0, "status": "open"},
    )

    created = client.post(
        "/api/agents/campaigns",
        json={"manager": "apt", "package": "curl", "agent_ids": [agent_id]},
        headers=_auth(token),
    )
    campaign_id = created.json()["id"]
    cmd = client.get(f"/api/agents/{agent_id}/commands", headers=_auth(token)).json()["commands"][0]

    _run_command_to_done(client, token, agent_id, agent_token, cmd["id"], status="done")

    # campaign is now 'completed' (single ring, single item, done) but
    # verification is still 'pending' — after-snapshot must be withheld
    detail = client.get(f"/api/agents/campaigns/{campaign_id}", headers=_auth(token)).json()
    assert detail["status"] == "completed"
    assert detail.get("risk_after") is None
    assert detail.get("risk_reduction_pct") is None

    real_asset_id = client.get(f"/api/agents/{agent_id}", headers=_auth(token)).json()["asset_id"]
    _seed_installation_with_product_id(uid, real_asset_id, product_name="curl", installed_version="9.9.9", patch_status="up_to_date")

    from app.jobs import _verify_patch_command

    _verify_patch_command(cmd["id"])

    detail2 = client.get(f"/api/agents/campaigns/{campaign_id}", headers=_auth(token)).json()
    assert detail2.get("risk_after") is not None
    assert detail2.get("risk_reduction_pct") is not None


def test_verified_patch_auto_resolves_matching_cve_vulnerability(tmp_path, monkeypatch):
    """The exact-CVE auto-resolve loop: a verified patch that satisfies an
    advisory's fixed_version must close any open vulnerability sharing that
    exact CVE on the same asset."""
    client, token = _client_and_token(tmp_path, monkeypatch)
    command_id, asset_id, agent_id = _prepare_done_command_with_asset(client, token, "autoresolve-pos-1")

    from app.agents import get_agent
    from app.enterprise import create_vulnerability, list_vulnerabilities

    agent = get_agent(agent_id)
    uid = agent["user_id"]

    _installation_id, product_id = _seed_installation_with_product_id(
        uid, asset_id, product_name="curl", installed_version="9.9.9", patch_status="up_to_date"
    )
    _seed_advisory(uid, product_id, cve_id="CVE-2024-5555", fixed_version="9.0.0")

    open_vuln = create_vulnerability(
        uid,
        {"asset_id": asset_id, "asset_name": "seeded-host", "title": "Old curl CVE", "cve": "CVE-2024-5555", "severity": "high", "status": "open"},
    )

    from app.jobs import _verify_patch_command

    _verify_patch_command(command_id)

    remaining_open = [v["id"] for v in list_vulnerabilities(uid, status="open")]
    assert open_vuln["id"] not in remaining_open

    resolved = [v for v in list_vulnerabilities(uid, status="resolved") if v["id"] == open_vuln["id"]]
    assert len(resolved) == 1


def test_verified_patch_does_not_resolve_vulnerability_without_cve_match(tmp_path, monkeypatch):
    """Negative case for the auto-resolve loop: no exact-CVE advisory link
    means the finding must stay open — never fuzzy-matched by title."""
    client, token = _client_and_token(tmp_path, monkeypatch)
    command_id, asset_id, agent_id = _prepare_done_command_with_asset(client, token, "autoresolve-neg-1")

    from app.agents import get_agent
    from app.enterprise import create_vulnerability, list_vulnerabilities

    agent = get_agent(agent_id)
    uid = agent["user_id"]

    # installation verified up to date, but no software_advisories row at
    # all — there is no CVE-level linkage for _resolve_vulnerabilities_for_verified_patch to use
    _seed_installation_with_product_id(uid, asset_id, product_name="curl", installed_version="9.9.9", patch_status="up_to_date")

    open_vuln = create_vulnerability(
        uid,
        {"asset_id": asset_id, "asset_name": "seeded-host", "title": "Unrelated curl CVE", "cve": "CVE-2099-0001", "severity": "high", "status": "open"},
    )

    from app.jobs import _verify_patch_command

    _verify_patch_command(command_id)

    remaining_open = [v["id"] for v in list_vulnerabilities(uid, status="open")]
    assert open_vuln["id"] in remaining_open
