"""Agent Platform v1 — tenancy, signing, gateway long-poll."""

from __future__ import annotations

import threading
import time

from tests._http_test_utils import configure_isolated_settings


def _reload(monkeypatch, data_dir):
    return configure_isolated_settings(monkeypatch, data_dir)


def _app_client(tmp_path, monkeypatch):
    _reload(monkeypatch, tmp_path)
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    from app.agent_gateway import router as gateway_router
    from app.agents_api import router as agents_router
    from app.auth import login, register_user
    from app.tenancy import ensure_tenant_schema

    ensure_tenant_schema()
    register_user("plat_admin", "password123", role="admin")
    _u, token = login("plat_admin", "password123")

    app = FastAPI()
    app.include_router(gateway_router)
    app.include_router(agents_router)
    return TestClient(app), token


def _auth(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


def test_command_seal_has_signature(tmp_path, monkeypatch):
    _reload(monkeypatch, tmp_path)
    from app.agent_security import verify_sealed_command
    from app.agents import (
        _dispatch_queued_commands,
        approve_command,
        enroll_agent,
        ensure_schema,
        request_command,
    )

    ensure_schema()
    enrolled = enroll_agent("u1", name="host-a", org_id=None)
    aid = enrolled["agent_id"]
    req = request_command(
        "u1",
        aid,
        kind="patch_package",
        payload={"manager": "pip", "package": "requests"},
    )
    approve_command("u1", aid, req["id"], approver_id="u1")
    cmds = _dispatch_queued_commands(aid)
    assert len(cmds) == 1
    cmd = cmds[0]
    assert cmd.get("signature")
    assert cmd.get("nonce")
    assert cmd.get("event_id")
    assert cmd.get("issued_at") is not None
    assert cmd.get("expires_at") is not None
    assert verify_sealed_command(cmd) is True


def test_tenant_isolation_lists(tmp_path, monkeypatch):
    _reload(monkeypatch, tmp_path)
    from app.agents import enroll_agent, ensure_schema, list_agents
    from app.commercial_ext import ensure_org_schema
    from app.db import get_conn, new_id, now

    ensure_schema()
    ensure_org_schema()
    oid_a = new_id()
    oid_b = new_id()
    c = get_conn()
    c.execute(
        "INSERT INTO organizations (id, name, slug, owner_user_id, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)",
        (oid_a, "Org A", f"org-a-{oid_a[:8]}", "alice", now(), now()),
    )
    c.execute(
        "INSERT INTO organizations (id, name, slug, owner_user_id, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)",
        (oid_b, "Org B", f"org-b-{oid_b[:8]}", "bob", now(), now()),
    )
    c.execute(
        "INSERT INTO org_members (id, org_id, user_id, role, created_at) VALUES (?, ?, ?, ?, ?)",
        (new_id(), oid_a, "alice", "admin", now()),
    )
    c.execute(
        "INSERT INTO org_members (id, org_id, user_id, role, created_at) VALUES (?, ?, ?, ?, ?)",
        (new_id(), oid_b, "bob", "admin", now()),
    )
    c.commit()

    enroll_agent("alice", name="alice-agent", org_id=oid_a)
    enroll_agent("bob", name="bob-agent", org_id=oid_b)

    alice_agents = list_agents("alice", org_id=oid_a)
    bob_agents = list_agents("bob", org_id=oid_b)
    assert len(alice_agents) == 1
    assert alice_agents[0]["name"] == "alice-agent"
    assert len(bob_agents) == 1
    assert bob_agents[0]["name"] == "bob-agent"
    # Alice must not see Bob's agent when listing her own tenant scope
    assert all(a.get("org_id") == oid_a for a in alice_agents)
    assert all(a["id"] != bob_agents[0]["id"] for a in list_agents("alice"))


def test_gateway_wait_immediate_and_notify(tmp_path, monkeypatch):
    client, token = _app_client(tmp_path, monkeypatch)
    enroll = client.post("/api/agents/enroll", json={"name": "gw-1"}, headers=_auth(token))
    assert enroll.status_code == 200, enroll.text
    agent_token = enroll.json()["agent_token"]
    agent_id = enroll.json()["agent_id"]

    # Request + approve a command so it is queued
    create = client.post(
        f"/api/agents/{agent_id}/commands",
        json={"kind": "patch_package", "payload": {"manager": "pip", "package": "pip"}},
        headers=_auth(token),
    )
    assert create.status_code == 200, create.text
    cid = create.json()["id"]
    appr = client.post(
        f"/api/agents/{agent_id}/commands/{cid}/approve",
        headers=_auth(token),
    )
    assert appr.status_code == 200, appr.text

    wait = client.post(
        "/api/agents/gateway/wait",
        json={"timeout_sec": 2.0, "limit": 5},
        headers={"Authorization": f"Bearer {agent_token}"},
    )
    assert wait.status_code == 200, wait.text
    body = wait.json()
    assert body["via"] == "immediate"
    assert len(body["commands"]) == 1
    assert body["commands"][0]["id"] == cid
    assert body["commands"][0].get("signature")


def test_gateway_long_poll_wakes_on_approve(tmp_path, monkeypatch):
    client, token = _app_client(tmp_path, monkeypatch)
    enroll = client.post("/api/agents/enroll", json={"name": "gw-2"}, headers=_auth(token))
    agent_token = enroll.json()["agent_token"]
    agent_id = enroll.json()["agent_id"]

    create = client.post(
        f"/api/agents/{agent_id}/commands",
        json={"kind": "patch_package", "payload": {"manager": "pip", "package": "urllib3"}},
        headers=_auth(token),
    )
    cid = create.json()["id"]

    result: dict = {}

    def _waiter():
        res = client.post(
            "/api/agents/gateway/wait",
            json={"timeout_sec": 8.0, "limit": 5},
            headers={"Authorization": f"Bearer {agent_token}"},
        )
        result["status"] = res.status_code
        result["body"] = res.json() if res.status_code == 200 else res.text

    t = threading.Thread(target=_waiter, daemon=True)
    t.start()
    time.sleep(0.4)
    appr = client.post(
        f"/api/agents/{agent_id}/commands/{cid}/approve",
        headers=_auth(token),
    )
    assert appr.status_code == 200, appr.text
    t.join(timeout=12)
    assert result.get("status") == 200, result
    body = result["body"]
    assert any(c.get("id") == cid for c in body.get("commands") or [])


def test_gateway_status_endpoint(tmp_path, monkeypatch):
    client, _token = _app_client(tmp_path, monkeypatch)
    res = client.get("/api/agents/gateway/status")
    assert res.status_code == 200
    assert res.json().get("mode") == "long_poll+websocket"
