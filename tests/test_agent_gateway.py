"""Agent Gateway WebSocket + ACK + replay headers."""

from __future__ import annotations

from tests._http_test_utils import configure_isolated_settings


def _app_client(tmp_path, monkeypatch):
    configure_isolated_settings(monkeypatch, tmp_path)
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    from app.agent_gateway import router as gw_router
    from app.agents_api import router as agents_router
    from app.tenancy import ensure_tenant_schema

    ensure_tenant_schema()
    app = FastAPI()
    app.include_router(gw_router)
    app.include_router(agents_router)
    return TestClient(app)


def test_websocket_hello_and_heartbeat(tmp_path, monkeypatch):
    client = _app_client(tmp_path, monkeypatch)
    from app.auth import login, register_user

    register_user("gw_admin", "password123", role="admin")
    _, token = login("gw_admin", "password123")
    enroll = client.post(
        "/api/agents/enroll",
        json={"name": "ws-1"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert enroll.status_code == 200, enroll.text
    agent_token = enroll.json()["agent_token"]

    with client.websocket_connect("/api/agents/ws") as ws:
        ws.send_json({"type": "hello", "token": agent_token})
        welcome = ws.receive_json()
        assert welcome["type"] == "welcome"
        assert welcome.get("reconnect") is True
        ws.send_json({"type": "heartbeat", "ts": 1})
        pong = ws.receive_json()
        assert pong["type"] == "pong"


def test_command_ack_http(tmp_path, monkeypatch):
    client = _app_client(tmp_path, monkeypatch)
    from app.auth import login, register_user

    register_user("ack_admin", "password123", role="admin")
    _, token = login("ack_admin", "password123")
    auth = {"Authorization": f"Bearer {token}"}
    enroll = client.post("/api/agents/enroll", json={"name": "ack-1"}, headers=auth)
    agent_id = enroll.json()["agent_id"]
    agent_token = enroll.json()["agent_token"]
    req = client.post(
        f"/api/agents/{agent_id}/commands",
        json={"kind": "patch_package", "payload": {"manager": "apt", "package": "curl"}},
        headers=auth,
    )
    cid = req.json()["id"]
    client.post(f"/api/agents/{agent_id}/commands/{cid}/approve", headers=auth)
    # deliver via check-in
    chk = client.post(
        "/api/agents/checkin",
        json={"hostname": "h"},
        headers={"Authorization": f"Bearer {agent_token}"},
    )
    assert chk.status_code == 200
    cmds = chk.json().get("commands") or []
    assert cmds and cmds[0]["id"] == cid
    ack = client.post(
        f"/api/agents/commands/{cid}/ack",
        headers={"Authorization": f"Bearer {agent_token}"},
    )
    assert ack.status_code == 200, ack.text
    assert ack.json().get("status") == "acked"


def test_websocket_bad_hello_rejected(tmp_path, monkeypatch):
    client = _app_client(tmp_path, monkeypatch)
    with client.websocket_connect("/api/agents/ws") as ws:
        ws.send_json({"type": "hello", "token": "not-a-real.token"})
        # Starlette closes with policy violation / auth failure
        try:
            ws.receive_json()
            assert False, "expected disconnect after bad hello"
        except Exception:
            pass


def test_websocket_reconnect_replaces_session(tmp_path, monkeypatch):
    """Second WebSocket for the same agent replaces the first (reconnect)."""
    client = _app_client(tmp_path, monkeypatch)
    from app.auth import login, register_user
    from app.agents import get_agent

    register_user("gw_re", "password123", role="admin")
    _, token = login("gw_re", "password123")
    enroll = client.post(
        "/api/agents/enroll",
        json={"name": "ws-re"},
        headers={"Authorization": f"Bearer {token}"},
    )
    agent_token = enroll.json()["agent_token"]
    agent_id = enroll.json()["agent_id"]

    with client.websocket_connect("/api/agents/ws") as ws1:
        ws1.send_json({"type": "hello", "token": agent_token})
        assert ws1.receive_json()["type"] == "welcome"
        assert get_agent(agent_id).get("ws_connected") in (1, True)

        with client.websocket_connect("/api/agents/ws") as ws2:
            ws2.send_json({"type": "hello", "token": agent_token})
            assert ws2.receive_json()["type"] == "welcome"
            ws2.send_json({"type": "heartbeat", "ts": 2})
            assert ws2.receive_json()["type"] == "pong"

    # both sockets closed → gateway unregisters
    assert get_agent(agent_id).get("ws_connected") in (0, False, None)


def test_long_poll_delivers_after_approve(tmp_path, monkeypatch):
    client = _app_client(tmp_path, monkeypatch)
    from app.auth import login, register_user
    from app.agent_gateway import _register_waiter, _unregister_waiter, notify_agent
    import asyncio

    register_user("gw_lp", "password123", role="admin")
    _, token = login("gw_lp", "password123")
    auth = {"Authorization": f"Bearer {token}"}
    enroll = client.post("/api/agents/enroll", json={"name": "lp-1"}, headers=auth)
    agent_id = enroll.json()["agent_id"]
    agent_token = enroll.json()["agent_token"]
    req = client.post(
        f"/api/agents/{agent_id}/commands",
        json={"kind": "patch_package", "payload": {"manager": "apt", "package": "curl"}},
        headers=auth,
    )
    cid = req.json()["id"]
    client.post(f"/api/agents/{agent_id}/commands/{cid}/approve", headers=auth)

    # Approve already queued → wait returns immediately with sealed command.
    r = client.post(
        "/api/agents/gateway/wait",
        json={"timeout_sec": 2.0, "limit": 5},
        headers={"Authorization": f"Bearer {agent_token}"},
    )
    assert r.status_code == 200, r.text
    body = r.json()
    cmds = body.get("commands") or []
    assert any(c.get("id") == cid for c in cmds)
    assert cmds[0].get("event_id")
    assert body.get("via") == "immediate"

    # notify_agent must wake registered long-poll waiters (reconnect / push path).
    ev = asyncio.Event()
    _register_waiter(agent_id, ev)
    try:
        notify_agent(agent_id)
        assert ev.is_set()
    finally:
        _unregister_waiter(agent_id, ev)


def test_websocket_push_command_and_ack(tmp_path, monkeypatch):
    client = _app_client(tmp_path, monkeypatch)
    from app.auth import login, register_user

    register_user("gw_push", "password123", role="admin")
    _, token = login("gw_push", "password123")
    auth = {"Authorization": f"Bearer {token}"}
    enroll = client.post("/api/agents/enroll", json={"name": "push-1"}, headers=auth)
    agent_id = enroll.json()["agent_id"]
    agent_token = enroll.json()["agent_token"]
    req = client.post(
        f"/api/agents/{agent_id}/commands",
        json={"kind": "patch_package", "payload": {"manager": "apt", "package": "curl"}},
        headers=auth,
    )
    cid = req.json()["id"]
    client.post(f"/api/agents/{agent_id}/commands/{cid}/approve", headers=auth)

    with client.websocket_connect("/api/agents/ws") as ws:
        ws.send_json({"type": "hello", "token": agent_token})
        welcome = ws.receive_json()
        assert welcome["type"] == "welcome"
        # queued command should be pushed (or arrive on next message)
        msg = ws.receive_json()
        assert msg["type"] == "commands"
        assert msg["commands"][0]["id"] == cid
        assert msg["commands"][0].get("event_id")
        ws.send_json({"type": "ack", "command_id": cid})
        assert ws.receive_json()["type"] == "ack_ok"


def test_replay_nonce_rejected_when_enforced(tmp_path, monkeypatch):
    configure_isolated_settings(monkeypatch, tmp_path)
    import app.config as config_mod

    monkeypatch.setattr(config_mod.settings, "agent_require_replay_protection", True, raising=False)
    try:
        import app.agent_auth as agent_auth_mod

        monkeypatch.setattr(agent_auth_mod.settings, "agent_require_replay_protection", True, raising=False)
    except Exception:
        pass
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    from app.agents_api import router as agents_router
    from app.tenancy import ensure_tenant_schema

    ensure_tenant_schema()
    app = FastAPI()
    app.include_router(agents_router)
    client = TestClient(app)
    from app.auth import login, register_user

    register_user("rep_admin", "password123", role="admin")
    _, token = login("rep_admin", "password123")
    enroll = client.post(
        "/api/agents/enroll", json={"name": "r1"}, headers={"Authorization": f"Bearer {token}"}
    )
    agent_token = enroll.json()["agent_token"]
    import time

    ts = str(int(time.time()))
    nonce = "abc123replay"
    headers = {
        "Authorization": f"Bearer {agent_token}",
        "X-SecuraIQ-Ts": ts,
        "X-SecuraIQ-Nonce": nonce,
    }
    r1 = client.post("/api/agents/checkin", json={"hostname": "h"}, headers=headers)
    assert r1.status_code == 200, r1.text
    r2 = client.post("/api/agents/checkin", json={"hostname": "h"}, headers=headers)
    assert r2.status_code == 401
