"""In-process realtime pub/sub for SSE clients, with optional Redis fan-out + Streams.

Call `publish({...})` from any module after a meaningful write. The `/api/realtime`
SSE loop wakes immediately instead of waiting on a timer.

Every ``publish`` is normalized through the REALTIME v1 event contract
(``app.realtime_events.normalize_event`` / ``app.event_schema``) before fan-out.
Legacy ``type`` is dual-written with ``event_type`` so existing SSE/UI clients
keep working.

When ``REDIS_URL`` is set:
  - **pub/sub** (`securaiq:realtime`) fans live events across uvicorn workers for SSE
  - **Streams** (`REDIS_STREAM_KEY`, default ``securaiq:events``) durable ``XADD``
    for consumer groups / replay (REALTIME Task B)

Without Redis: single-process lab default — in-memory ring buffer supports
``replay_since`` for Last-Event-ID catch-up (SSE wiring is a separate task).
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import threading
import time
import uuid
from collections import OrderedDict
from typing import Any

_log = logging.getLogger("securaiq.realtime_bus")

_lock = threading.Lock()
_subscribers: set[asyncio.Queue] = set()
_loop: asyncio.AbstractEventLoop | None = None
_redis_task: asyncio.Task | None = None
_CHANNEL = "securaiq:realtime"
_DEFAULT_STREAM_KEY = "securaiq:events"
_DEFAULT_STREAM_MAXLEN = 10000
_DEFAULT_REPLAY_BUFFER = 2000
_PID = os.getpid()
# event_id → payload; also serves as publish-path LRU dedupe
_REPLAY_BUFFER: OrderedDict[str, dict[str, Any]] = OrderedDict()


def bind_loop(loop: asyncio.AbstractEventLoop | None = None) -> None:
    """Remember the running event loop so sync callers can wake subscribers.

    Also starts the Redis pub/sub listener (when configured) and the Task C
    Streams event processor — both are best-effort background tasks.
    """
    global _loop, _redis_task
    _loop = loop or asyncio.get_running_loop()
    if _redis_task is None or _redis_task.done():
        try:
            _redis_task = _loop.create_task(_redis_listener())
        except Exception:
            _redis_task = None
    try:
        from app.event_processor import start_processor

        start_processor(_loop)
    except Exception:
        pass


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


def _stream_key() -> str:
    try:
        from app.config import settings

        return (getattr(settings, "redis_stream_key", "") or _DEFAULT_STREAM_KEY).strip() or _DEFAULT_STREAM_KEY
    except Exception:
        return _DEFAULT_STREAM_KEY


def _stream_maxlen() -> int:
    try:
        from app.config import settings

        n = int(getattr(settings, "redis_stream_maxlen", _DEFAULT_STREAM_MAXLEN) or _DEFAULT_STREAM_MAXLEN)
        return max(100, n)
    except Exception:
        return _DEFAULT_STREAM_MAXLEN


def _replay_buffer_max() -> int:
    try:
        from app.config import settings

        n = int(getattr(settings, "realtime_replay_buffer", _DEFAULT_REPLAY_BUFFER) or _DEFAULT_REPLAY_BUFFER)
        return max(16, n)
    except Exception:
        return _DEFAULT_REPLAY_BUFFER


def _remember_event(payload: dict[str, Any]) -> bool:
    """Store in the ring buffer / dedupe set. Returns False if duplicate event_id."""
    eid = str(payload.get("event_id") or "").strip()
    if not eid:
        eid = uuid.uuid4().hex
        payload["event_id"] = eid
    max_n = _replay_buffer_max()
    with _lock:
        if eid in _REPLAY_BUFFER:
            return False
        _REPLAY_BUFFER[eid] = dict(payload)
        while len(_REPLAY_BUFFER) > max_n:
            _REPLAY_BUFFER.popitem(last=False)
    return True


def _xadd_stream(payload: dict[str, Any], url: str) -> None:
    """Best-effort durable append. Never raises to callers of publish()."""
    try:
        import redis

        r = redis.from_url(url, decode_responses=True, socket_connect_timeout=0.5)
        try:
            r.xadd(
                _stream_key(),
                {"payload": json.dumps(payload, default=str)},
                maxlen=_stream_maxlen(),
                approximate=True,
            )
        finally:
            r.close()
    except Exception as exc:
        _log.debug("stream XADD skipped: %s", exc)


def _pubsub_publish(payload: dict[str, Any], url: str) -> None:
    try:
        import redis

        r = redis.from_url(url, decode_responses=True, socket_connect_timeout=0.5)
        try:
            r.publish(_CHANNEL, json.dumps(payload, default=str))
        finally:
            r.close()
    except Exception as exc:
        _log.debug("pubsub publish skipped: %s", exc)


def publish(event: dict[str, Any] | None = None, **kwargs: Any) -> None:
    """Broadcast an event to local SSE subscribers (+ Redis when configured).

    Payloads are normalized to the REALTIME v1 contract (event_id, event_type,
    sequence, timestamps, data, …) while preserving legacy ``type`` / ``seq`` /
    ``org_id`` and top-level domain fields for existing SSE consumers.
    """
    payload = dict(event or {})
    payload.update(kwargs)
    try:
        from app.realtime_events import normalize_event

        payload = normalize_event(payload)
    except Exception:
        # Contract normalize must never break writers — fall back to minimal stamp.
        payload.setdefault("ts", time.time())
        payload.setdefault("seq", int(float(payload["ts"]) * 1000))
        payload.setdefault("event_id", uuid.uuid4().hex)
        if payload.get("type") and not payload.get("event_type"):
            payload["event_type"] = payload["type"]
        elif payload.get("event_type") and not payload.get("type"):
            payload["type"] = payload["event_type"]

    eid = str(payload.get("event_id") or uuid.uuid4().hex)
    payload["event_id"] = eid
    payload["_pid"] = _PID

    if not _remember_event(payload):
        return

    _fanout_local(payload)

    # Lab path: sync processor hooks when Redis Streams consumer is not running.
    try:
        from app.event_processor import on_local_publish

        on_local_publish(payload)
    except Exception:
        pass

    url = _redis_url()
    if not url:
        return
    # Durable log first, then live fan-out — failures never break writers.
    _xadd_stream(payload, url)
    _pubsub_publish(payload, url)


def replay_since(last_event_id: str | None, *, limit: int = 200) -> list[dict[str, Any]]:
    """Return buffered events after ``last_event_id`` (in-process ring buffer).

    Used for Last-Event-ID catch-up without Redis. If ``last_event_id`` is
    missing or unknown, returns the most recent ``limit`` events (oldest first).
    Does not include Redis Stream history — that path is Task E / consumer read.
    """
    lim = max(1, min(int(limit or 200), 2000))
    with _lock:
        items = list(_REPLAY_BUFFER.items())
    if not items:
        return []
    if last_event_id:
        needle = str(last_event_id).strip()
        idx = next((i for i, (eid, _) in enumerate(items) if eid == needle), None)
        if idx is not None:
            return [dict(ev) for _, ev in items[idx + 1 : idx + 1 + lim]]
    # Unknown / None cursor → recent window (oldest first)
    return [dict(ev) for _, ev in items[-lim:]]


def stream_status() -> dict[str, Any]:
    """Health snapshot for Streams + in-process replay buffer."""
    url = _redis_url()
    with _lock:
        buf_len = len(_REPLAY_BUFFER)
    return {
        "stream_key": _stream_key() if url else None,
        "maxlen": _stream_maxlen() if url else None,
        "mode": "redis_streams" if url else "in_process",
        "redis_configured": bool(url),
        "pubsub_channel": _CHANNEL if url else None,
        "replay_buffer_size": buf_len,
        "replay_buffer_max": _replay_buffer_max(),
        "consumer_group": "securaiq-workers" if url else None,
    }


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
                if not _remember_event(payload):
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


def clear_replay_buffer_for_tests() -> None:
    """Test helper — wipe in-process buffer / dedupe state."""
    with _lock:
        _REPLAY_BUFFER.clear()


def backend_status() -> dict[str, Any]:
    url = _redis_url()
    stream = stream_status()
    if url:
        mode = "redis_streams+pubsub"
        hint = (
            "REDIS_URL set: durable XADD to Streams "
            f"({stream.get('stream_key')}) + pub/sub fan-out for multi-worker SSE."
        )
    else:
        mode = "in_process"
        hint = (
            "Single-process only — in-memory replay buffer for Last-Event-ID. "
            "Set REDIS_URL for Streams durability + multi-worker pub/sub."
        )
    return {
        "mode": mode,
        "redis_configured": bool(url),
        "channel": _CHANNEL if url else None,
        "stream": stream,
        "local_subscribers": subscriber_count(),
        "pid": _PID,
        "hint": hint,
    }
