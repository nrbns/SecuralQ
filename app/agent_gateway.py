"""Persistent WebSocket + long-poll Agent Gateway (v1).

Dashboard clients keep using SSE (`GET /api/realtime`). Agents connect here
for heartbeat + pushed commands. HTTP check-in remains the fallback.

Authorized labs / owned hosts only — this is not a malware C2 channel:
commands are an allowlisted kind (`patch_package`, `agent_upgrade`) that
already require human approval.
"""

from __future__ import annotations

import asyncio
import json
import logging
import threading
from typing import Any

from fastapi import APIRouter, Header, HTTPException, WebSocket, WebSocketDisconnect
from pydantic import BaseModel, Field

from app.agents import (
    _dispatch_queued_commands,
    ack_command,
    authenticate_agent,
    checkin,
    expire_timed_out_commands,
    mark_agent_ws,
    record_threat_detections,
    report_command_result,
)
from app.agent_auth import parse_agent_bearer, verify_replay_and_signature
from app.config import settings
from app.db import now

log = logging.getLogger("securaiq.agent_gateway")

router = APIRouter(prefix="/api/agents", tags=["securaiq-agent-gateway"])

_HEARTBEAT_SEC = 30
_connections: dict[str, WebSocket] = {}
_lock = asyncio.Lock()
_wait_lock = threading.Lock()
_waiters: dict[str, list[asyncio.Event]] = {}
_loop: asyncio.AbstractEventLoop | None = None


def bind_loop(loop: asyncio.AbstractEventLoop | None = None) -> None:
    global _loop
    try:
        _loop = loop or asyncio.get_running_loop()
    except RuntimeError:
        _loop = loop


def connected_agent_ids() -> list[str]:
    return list(_connections.keys())


def _register_waiter(agent_id: str, ev: asyncio.Event) -> None:
    with _wait_lock:
        _waiters.setdefault(agent_id, []).append(ev)


def _unregister_waiter(agent_id: str, ev: asyncio.Event) -> None:
    with _wait_lock:
        lst = _waiters.get(agent_id) or []
        if ev in lst:
            lst.remove(ev)
        if not lst:
            _waiters.pop(agent_id, None)


def notify_agent(agent_id: str) -> None:
    """Wake long-poll waiters and schedule a WebSocket push."""
    aid = (agent_id or "").strip()
    if not aid:
        return
    with _wait_lock:
        events = list(_waiters.get(aid) or [])
    for ev in events:
        try:
            ev.set()
        except Exception:
            pass
    notify_commands_ready(aid)


def notify_commands_ready(agent_id: str) -> None:
    """Called from sync approve/check-in paths to push queued commands."""
    loop = _loop
    if loop is None or not loop.is_running():
        try:
            loop = asyncio.get_running_loop()
            bind_loop(loop)
        except RuntimeError:
            return
    try:
        asyncio.run_coroutine_threadsafe(_push_queued(agent_id), loop)
    except Exception:
        pass


async def _register(agent_id: str, ws: WebSocket) -> None:
    async with _lock:
        old = _connections.get(agent_id)
        _connections[agent_id] = ws
    if old is not None and old is not ws:
        try:
            await old.close(code=4000)
        except Exception:
            pass
    mark_agent_ws(agent_id, connected=True)


async def _unregister(agent_id: str, ws: WebSocket) -> None:
    async with _lock:
        if _connections.get(agent_id) is ws:
            _connections.pop(agent_id, None)
            mark_agent_ws(agent_id, connected=False)


async def _push_queued(agent_id: str) -> None:
    expire_timed_out_commands()
    ws = _connections.get(agent_id)
    if ws is None:
        return
    cmds = _dispatch_queued_commands(agent_id)
    if not cmds:
        return
    try:
        await ws.send_json({"type": "commands", "commands": cmds})
    except Exception:
        log.debug("push failed for agent %s", agent_id[:8])


def _auth_agent(authorization: str | None) -> dict[str, Any]:
    agent_id, raw_key = parse_agent_bearer(authorization)
    if not agent_id or not raw_key:
        raise HTTPException(status_code=401, detail="Missing or malformed agent token")
    agent = authenticate_agent(agent_id, raw_key)
    if not agent:
        raise HTTPException(status_code=401, detail="Invalid or revoked agent token")
    return agent


class GatewayWaitRequest(BaseModel):
    timeout_sec: float = Field(default=25.0, ge=1.0, le=55.0)
    limit: int = Field(default=5, ge=1, le=20)


@router.post("/gateway/wait")
async def gateway_wait(
    req: GatewayWaitRequest,
    authorization: str | None = Header(default=None, alias="Authorization"),
):
    """Long-poll for queued commands — near-instant when notify_agent fires."""
    if not settings.agent_gateway_enabled:
        raise HTTPException(status_code=503, detail="Agent gateway disabled")
    bind_loop()
    agent = _auth_agent(authorization)
    aid = str(agent["id"])
    cmds = _dispatch_queued_commands(aid, limit=req.limit)
    if cmds:
        return {"commands": cmds, "waited_ms": 0, "via": "immediate"}

    ev = asyncio.Event()
    _register_waiter(aid, ev)
    loop = asyncio.get_running_loop()
    started = loop.time()
    try:
        try:
            await asyncio.wait_for(ev.wait(), timeout=float(req.timeout_sec))
        except asyncio.TimeoutError:
            pass
        waited_ms = int(max(0.0, (loop.time() - started) * 1000))
        cmds = _dispatch_queued_commands(aid, limit=req.limit)
        return {"commands": cmds, "waited_ms": waited_ms, "via": "long_poll"}
    finally:
        _unregister_waiter(aid, ev)


@router.get("/gateway/status")
async def gateway_status():
    with _wait_lock:
        waiters = {k: len(v) for k, v in _waiters.items()}
    return {
        "waiters": waiters,
        "websockets": {k: 1 for k in _connections},
        "mode": "long_poll+websocket",
        "enabled": bool(settings.agent_gateway_enabled),
        "ts": now(),
    }


async def _auth_from_hello(websocket: WebSocket, hello: dict[str, Any]) -> dict[str, Any] | None:
    token = str(hello.get("token") or "")
    aid, key = parse_agent_bearer(token)
    if not aid:
        auth = websocket.headers.get("authorization") or websocket.query_params.get("token") or ""
        aid, key = parse_agent_bearer(auth)
    if not aid or not key:
        return None
    agent = authenticate_agent(aid, key)
    if not agent:
        return None
    body = json.dumps({k: hello.get(k) for k in ("type", "nonce") if k in hello}, sort_keys=True).encode()
    err = verify_replay_and_signature(
        agent,
        ts_header=str(hello.get("ts") or websocket.headers.get("x-securaiq-ts") or ""),
        nonce=str(hello.get("nonce") or websocket.headers.get("x-securaiq-nonce") or ""),
        sig=str(hello.get("sig") or websocket.headers.get("x-securaiq-sig") or ""),
        body=body if hello.get("nonce") else b"",
        require=False if not hello.get("nonce") else None,
    )
    if err and settings.agent_require_replay_protection:
        return None
    if err and hello.get("sig"):
        return None
    return agent


@router.websocket("/ws")
async def agent_websocket(websocket: WebSocket) -> None:
    await agent_gateway(websocket)


async def agent_gateway(websocket: WebSocket) -> None:
    if not settings.agent_gateway_enabled:
        await websocket.close(code=1013)
        return
    bind_loop()
    await websocket.accept()
    agent_id = ""
    try:
        raw = await asyncio.wait_for(websocket.receive_text(), timeout=15.0)
        try:
            hello = json.loads(raw)
        except json.JSONDecodeError:
            await websocket.close(code=4400)
            return
        if (hello.get("type") or "") != "hello":
            await websocket.close(code=4400)
            return
        agent = await _auth_from_hello(websocket, hello)
        if not agent:
            await websocket.close(code=4401)
            return
        agent_id = str(agent["id"])
        await _register(agent_id, websocket)
        await websocket.send_json(
            {
                "type": "welcome",
                "agent_id": agent_id,
                "heartbeat_sec": _HEARTBEAT_SEC,
                "reconnect": True,
            }
        )
        await _push_queued(agent_id)
        while True:
            try:
                msg = await asyncio.wait_for(websocket.receive_text(), timeout=_HEARTBEAT_SEC * 3)
            except asyncio.TimeoutError:
                await websocket.close(code=4002)
                return
            try:
                data = json.loads(msg)
            except json.JSONDecodeError:
                await websocket.send_json({"type": "error", "error": "invalid json"})
                continue
            kind = str(data.get("type") or "")
            if kind == "heartbeat":
                mark_agent_ws(agent_id, connected=True, heartbeat=True)
                expire_timed_out_commands()
                await websocket.send_json({"type": "pong", "ts": data.get("ts")})
                await _push_queued(agent_id)
            elif kind == "checkin":
                result = checkin(agent_id, data.get("payload") or {})
                await websocket.send_json(
                    {"type": "checkin_ok", **{k: result[k] for k in result if k != "commands"}}
                )
                cmds = result.get("commands") or []
                if cmds:
                    await websocket.send_json({"type": "commands", "commands": cmds})
            elif kind == "ack":
                ack_command(agent_id, str(data.get("command_id") or ""))
                await websocket.send_json({"type": "ack_ok", "command_id": data.get("command_id")})
            elif kind == "result":
                report_command_result(
                    agent_id,
                    str(data.get("command_id") or ""),
                    status=str(data.get("status") or "done"),
                    result=data.get("result") or {},
                )
                await websocket.send_json({"type": "result_ok", "command_id": data.get("command_id")})
            elif kind == "threat":
                record_threat_detections(agent_id, data.get("detections") or [])
                await websocket.send_json({"type": "threat_ok"})
            else:
                await websocket.send_json({"type": "error", "error": f"unknown type {kind}"})
    except WebSocketDisconnect:
        pass
    except Exception:
        log.debug("gateway session ended", exc_info=True)
    finally:
        if agent_id:
            await _unregister(agent_id, websocket)
