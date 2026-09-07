"""In-process realtime pub/sub for SSE clients, with optional Redis fan-out.

Call `publish({...})` from any module after a meaningful write. The `/api/realtime`
SSE loop wakes immediately instead of waiting on a timer.

When ``REDIS_URL`` is set, events are published to a Redis channel so
**multi-worker** uvicorn processes share live updates. A background task on
each worker bridges Redis → local SSE queues. Same-process echoes are skipped
via PID tagging.

Without Redis: single-process only (honest alpha default).
"""

from __future__ import annotations

import asyncio
import json
import os
import threading
import time
import uuid
from collections import OrderedDict
from typing import Any

_lock = threading.Lock()
_subscribers: set[asyncio.Queue] = set()
_loop: asyncio.AbstractEventLoop | None = None
_redis_task: asyncio.Task | None = None
_CHANNEL = "securaiq:realtime"
_PID = os.getpid()
_RECENT_EVENT_IDS: OrderedDict[str, bool] = OrderedDict()
_RECENT_EVENT_MAX = 2048


def bind_loop(loop: asyncio.AbstractEventLoop | None = None) -> None:
    """Remember the running event loop so sync callers can wake subscribers."""
    global _loop, _redis_task
    _loop = loop or asyncio.get_running_loop()
    if _redis_task is None or _redis_task.done():
        try:
            _redis_task = _loop.create_task(_redis_listener())
        except Exception:
            _redis_task = None


def subscribe(maxsize: int = 64) -> asyncio.Queue:
    q: asyncio.Queue = asyncio.Queue(maxsize=maxsize)
    with _lock:
        _subscribers.add(q)
    return q


def unsubscribe(q: asyncio.Queue) -> None:
    with _lock:
        _subscribers.discard(q)


def _safe_put(q: asyncio.Queue, event: dict[str, Any]) -> None:
    try:
        q.put_nowait(event)
    except asyncio.QueueFull:
        try:
            q.get_nowait()
        except Exception:
            pass
        try:
            q.put_nowait(event)
        except Exception:
            pass


def _fanout_local(payload: dict[str, Any]) -> None:
    with _lock:
        subs = list(_subscribers)
    loop = _loop
    for q in subs:
        try:
            if loop is not None and loop.is_running():
                loop.call_soon_threadsafe(_safe_put, q, payload)
            else:
                _safe_put(q, payload)
        except Exception:
            pass


def _redis_url() -> str:
    try:
        from app.config import settings

        return (getattr(settings, "redis_url", "") or "").strip()
    except Exception:
        return ""


def publish(event: dict[str, Any] | None = None, **kwargs: Any) -> None:
    """Broadcast an event to local SSE subscribers (+ Redis when configured)."""
    payload = dict(event or {})
    payload.update(kwargs)
    payload.setdefault("ts", time.time())
    payload.setdefault("seq", int(payload["ts"] * 1000))
    eid = str(payload.get("event_id") or uuid.uuid4().hex)
    payload["event_id"] = eid
    payload["_pid"] = _PID

    with _lock:
        if eid in _RECENT_EVENT_IDS:
            return
        _RECENT_EVENT_IDS[eid] = True
        while len(_RECENT_EVENT_IDS) > _RECENT_EVENT_MAX:
            _RECENT_EVENT_IDS.popitem(last=False)

    _fanout_local(payload)

    url = _redis_url()
    if not url:
        return
    try:
        import redis

        r = redis.from_url(url, decode_responses=True, socket_connect_timeout=0.5)
        r.publish(_CHANNEL, json.dumps(payload, default=str))
        r.close()
    except Exception:
        pass  # Redis optional — never break writers


async def _redis_listener() -> None:
    """Subscribe to Redis channel and fan out remote workers' events locally."""
    url = _redis_url()
    if not url:
        return
    try:
        import redis.asyncio as aioredis
    except Exception:
        return

    backoff = 2.0
    while True:
        try:
            client = aioredis.from_url(url, decode_responses=True)
            pubsub = client.pubsub()
            await pubsub.subscribe(_CHANNEL)
            backoff = 2.0
            async for message in pubsub.listen():
                if message is None or message.get("type") != "message":
                    continue
                raw = message.get("data")
                try:
                    payload = json.loads(raw) if isinstance(raw, str) else {}
                except Exception:
                    continue
                if not isinstance(payload, dict):
                    continue
                # Skip echo of our own publish (already delivered locally)
                if payload.get("_pid") == _PID:
                    continue
                _fanout_local(payload)
        except asyncio.CancelledError:
            raise
        except Exception:
            await asyncio.sleep(backoff)
            backoff = min(60.0, backoff * 2)


def subscriber_count() -> int:
    with _lock:
        return len(_subscribers)


def backend_status() -> dict[str, Any]:
    url = _redis_url()
    return {
        "mode": "redis" if url else "in_process",
        "redis_configured": bool(url),
        "channel": _CHANNEL if url else None,
        "local_subscribers": subscriber_count(),
        "pid": _PID,
        "hint": (
            "Multi-worker safe when REDIS_URL is set (pip install redis)."
            if url
            else "Single-process only — set REDIS_URL for multi-worker fan-out."
        ),
    }
