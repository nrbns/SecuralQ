"""In-process realtime pub/sub for SSE clients, with optional Redis fan-out + Streams.

Call `publish({...})` from any module after a meaningful write. The `/api/realtime`
SSE loop wakes immediately instead of waiting on a timer.

Every ``publish`` is normalized through the REALTIME v1 event contract
(``app.realtime_events.normalize_event`` / ``app.event_schema``) before fan-out.
Legacy ``type`` is dual-written with ``event_type`` so existing SSE/UI clients
keep working.

When ``REDIS_URL`` is set:
  - **Streams** (`REDIS_STREAM_KEY`, default ``securaiq:events``) durable ``XADD``
    — authoritative durable log (REALTIME Task B / RT-02).
  - **Streams fan-out** (default) — each process runs a per-process
    ``securaiq-realtime-*`` consumer and fans to local SSE after ``XREADGROUP``.
  - **pub/sub** (`securaiq:realtime`) — *transitional* multi-worker SSE notify.
    Opt in via ``REALTIME_STREAMS_FANOUT=false`` if you need the older path.

Without Redis: single-process lab default — in-memory ring buffer supports
``replay_since`` for Last-Event-ID catch-up.
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
_streams_fanout_task: asyncio.Task | None = None
_CHANNEL = "securaiq:realtime"
_DEFAULT_STREAM_KEY = "securaiq:events"
_DEFAULT_STREAM_MAXLEN = 10000
_DEFAULT_REPLAY_BUFFER = 2000
_DEFAULT_STREAM_REPLAY_SCAN = 500
_PID = os.getpid()
# event_id → payload; also serves as publish-path LRU dedupe
_REPLAY_BUFFER: OrderedDict[str, dict[str, Any]] = OrderedDict()


def bind_loop(loop: asyncio.AbstractEventLoop | None = None) -> None:
    """Remember the running event loop so sync callers can wake subscribers.

    Also starts Redis listeners (pub/sub and/or Streams fanout) and the Task C
    Streams event processor — both are best-effort background tasks.
    """
    global _loop, _redis_task, _streams_fanout_task
    _loop = loop or asyncio.get_running_loop()
    url = _redis_url()
    if url and not _streams_fanout_enabled():
        if _redis_task is None or _redis_task.done():
            try:
                _redis_task = _loop.create_task(_redis_listener())
            except Exception:
                _redis_task = None
    else:
        _redis_task = None
    if url and _streams_fanout_enabled():
        if _streams_fanout_task is None or _streams_fanout_task.done():
            try:
                _streams_fanout_task = _loop.create_task(_streams_fanout_listener())
            except Exception:
                _streams_fanout_task = None
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


def _streams_fanout_enabled() -> bool:
    """Opt-in RT-02: Streams consumer fans out SSE; skip pub/sub publish."""
    try:
        from app.config import settings

        return bool(getattr(settings, "realtime_streams_fanout", False))
    except Exception:
        return False


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
    # Durable log first — Streams are the SoT when REDIS_URL is set.
    _xadd_stream(payload, url)
    # Default: Streams fan-out consumers deliver to local SSE (no pub/sub).
    # Transitional: REALTIME_STREAMS_FANOUT=false keeps Redis pub/sub notify.
    if not _streams_fanout_enabled():
        _pubsub_publish(payload, url)


def _payload_from_stream_fields(fields: Any) -> dict[str, Any] | None:
    if not isinstance(fields, dict):
        return None
    raw = fields.get("payload")
    if isinstance(raw, str):
        try:
            loaded = json.loads(raw)
            if isinstance(loaded, dict):
                return loaded
        except Exception:
            return None
    return None


def _replay_from_stream(last_event_id: str | None, *, limit: int) -> list[dict[str, Any]]:
    """Best-effort scan of recent Stream entries after ``last_event_id``.

    Limited count — not a full HA replay API. Failures return [].
    """
    url = _redis_url()
    if not url:
        return []
    lim = max(1, min(int(limit or 200), 2000))
    scan = max(lim, min(_DEFAULT_STREAM_REPLAY_SCAN, 2000))
    try:
        import redis

        r = redis.from_url(url, decode_responses=True, socket_connect_timeout=0.5)
        try:
            # Newest-first window, then reverse to oldest-first for catch-up.
            rows = r.xrevrange(_stream_key(), max="+", min="-", count=scan)
        finally:
            r.close()
    except Exception as exc:
        _log.debug("stream replay scan skipped: %s", exc)
        return []

    events: list[dict[str, Any]] = []
    for _msg_id, fields in reversed(rows or []):
        payload = _payload_from_stream_fields(fields)
        if not payload:
            continue
        events.append(payload)

    if not events:
        return []
    if last_event_id:
        needle = str(last_event_id).strip()
        idx = next(
            (i for i, ev in enumerate(events) if str(ev.get("event_id") or "") == needle),
            None,
        )
        if idx is not None:
            return [dict(ev) for ev in events[idx + 1 : idx + 1 + lim]]
        # Unknown cursor on stream — do not dump the whole window (ring buffer
        # path already handled "unknown → recent"). Return [] from stream side.
        return []
    return [dict(ev) for ev in events[-lim:]]


def replay_since(last_event_id: str | None, *, limit: int = 200) -> list[dict[str, Any]]:
    """Return events after ``last_event_id`` (ring buffer + best-effort Streams).

    Lab / same-process: in-memory ring buffer. When Redis is available, also
    scans a limited recent Stream window and merges (dedupe by ``event_id``,
    oldest first). Does not claim full HA catch-up.
    """
    lim = max(1, min(int(limit or 200), 2000))
    with _lock:
        items = list(_REPLAY_BUFFER.items())

    ring: list[dict[str, Any]] = []
    if items:
        if last_event_id:
            needle = str(last_event_id).strip()
            idx = next((i for i, (eid, _) in enumerate(items) if eid == needle), None)
            if idx is not None:
                ring = [dict(ev) for _, ev in items[idx + 1 : idx + 1 + lim]]
            else:
                # Unknown cursor → recent window (oldest first)
                ring = [dict(ev) for _, ev in items[-lim:]]
        else:
            ring = [dict(ev) for _, ev in items[-lim:]]

    stream_events = _replay_from_stream(last_event_id, limit=lim)
    if not stream_events:
        return ring

    # Merge: prefer chronological order by sequence/ts when both present; dedupe.
    seen: set[str] = set()
    merged: list[dict[str, Any]] = []

    def _key(ev: dict[str, Any]) -> tuple:
        seq = ev.get("sequence") if ev.get("sequence") is not None else ev.get("seq")
        try:
            seq_n = int(seq) if seq is not None else 0
        except Exception:
            seq_n = 0
        try:
            ts_n = float(ev.get("ts") or 0)
        except Exception:
            ts_n = 0.0
        return (seq_n, ts_n)

    for ev in sorted(list(ring) + list(stream_events), key=_key):
        eid = str(ev.get("event_id") or "").strip()
        if not eid or eid in seen:
            continue
        if last_event_id and eid == str(last_event_id).strip():
            continue
        seen.add(eid)
        merged.append(dict(ev))
        if len(merged) >= lim:
            break
    return merged


def stream_status() -> dict[str, Any]:
    """Health snapshot for Streams + in-process replay buffer.

    Best-effort XLEN / DLQ / pending metrics when Redis is configured.
    Never raises.
    """
    url = _redis_url()
    fanout = _streams_fanout_enabled()
    with _lock:
        buf_len = len(_REPLAY_BUFFER)
    status: dict[str, Any] = {
        "stream_key": _stream_key() if url else None,
        "maxlen": _stream_maxlen() if url else None,
        "mode": "redis_streams" if url else "in_process",
        "redis_configured": bool(url),
        "pubsub_channel": (_CHANNEL if url and not fanout else None),
        "streams_fanout": bool(url and fanout),
        "replay_buffer_size": buf_len,
        "replay_buffer_max": _replay_buffer_max(),
        "consumer_group": "securaiq-workers" if url else None,
        "realtime_fanout_group": (f"securaiq-realtime-{_PID}" if url and fanout else None),
        "stream_length": None,
        "dlq_length": None,
        "pending_count": None,
        "consumer_group_lag": None,
        "dlq_key": None,
    }
    if url:
        try:
            from app.event_processor import stream_monitor_snapshot

            mon = stream_monitor_snapshot()
            for key in (
                "stream_length",
                "dlq_length",
                "pending_count",
                "consumer_group_lag",
                "dlq_key",
                "max_deliveries",
                "claim_idle_ms",
            ):
                if key in mon:
                    status[key] = mon[key]
        except Exception:
            pass
    return status


async def _redis_listener() -> None:
    """Subscribe to Redis channel and fan out remote workers' events locally."""
    url = _redis_url()
    if not url or _streams_fanout_enabled():
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


async def _ensure_realtime_fanout_group(client: Any, stream: str, group: str) -> None:
    try:
        # id="$" — only new messages after group creation (avoid replay storms).
        await client.xgroup_create(name=stream, groupname=group, id="$", mkstream=True)
        _log.info("created Streams fanout group %s on %s", group, stream)
    except Exception as exc:
        if "BUSYGROUP" not in str(exc).upper():
            _log.debug("xgroup_create fanout: %s", exc)


async def _streams_fanout_listener() -> None:
    """Per-process Streams consumer → local SSE (RT-02 opt-in).

    Uses group ``securaiq-realtime-{pid}`` so *each* worker receives a copy
    (shared single group would not multi-worker fan out). Publishing workers
    already ``_fanout_local``; ``_remember_event`` drops echo duplicates.
    """
    url = _redis_url()
    if not url or not _streams_fanout_enabled():
        return
    try:
        import redis.asyncio as aioredis
    except Exception:
        return

    stream = _stream_key()
    group = f"securaiq-realtime-{_PID}"
    consumer = f"sse-{_PID}"
    backoff = 2.0
    while True:
        client = None
        try:
            client = aioredis.from_url(url, decode_responses=True)
            await _ensure_realtime_fanout_group(client, stream, group)
            backoff = 2.0
            while True:
                if not _streams_fanout_enabled():
                    return
                rows = await client.xreadgroup(
                    groupname=group,
                    consumername=consumer,
                    streams={stream: ">"},
                    count=50,
                    block=5000,
                )
                if not rows:
                    continue
                for _stream_name, messages in rows:
                    for msg_id, fields in messages:
                        payload = _payload_from_stream_fields(fields) or {}
                        try:
                            if payload and _remember_event(payload):
                                _fanout_local(payload)
                        except Exception:
                            pass
                        try:
                            await client.xack(stream, group, msg_id)
                        except Exception:
                            pass
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            _log.debug("streams fanout reconnect: %s", exc)
            await asyncio.sleep(backoff)
            backoff = min(60.0, backoff * 2)
        finally:
            if client is not None:
                try:
                    await client.aclose()
                except Exception:
                    try:
                        await client.close()
                    except Exception:
                        pass


def sse_push_allowed_for_client(
    push: dict[str, Any] | None,
    *,
    auth_enabled: bool,
    client_user_id: str | None,
    client_org_ids: list[str] | None = None,
) -> bool:
    """Tenant filter for SSE *push* payloads (not heartbeat snapshots).

    - ``AUTH_ENABLED=false``: deliver everything (lab / open local).
    - ``AUTH_ENABLED=true``: deliver only when push ``user_id`` matches the
      client, or ``org_id`` / ``organization_id`` is in the client's memberships.
      Unscoped pushes (no user/org fields) are **dropped** when auth is on.
    """
    if not isinstance(push, dict):
        return False
    if not auth_enabled:
        return True

    uid = str(client_user_id or "").strip()
    if not uid:
        return False

    push_uid = str(push.get("user_id") or "").strip()
    push_org = str(
        push.get("org_id") or push.get("organization_id") or ""
    ).strip()

    if not push_uid and not push_org:
        # System/lab unscoped — only when auth is off (handled above).
        return False

    if push_uid and push_uid == uid:
        return True

    if push_org:
        orgs = list(client_org_ids) if client_org_ids is not None else []
        if not orgs:
            try:
                from app.tenancy import user_org_ids

                orgs = user_org_ids(uid)
            except Exception:
                orgs = []
        if push_org in orgs:
            return True

    return False


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
    fanout = bool(url and _streams_fanout_enabled())
    if url and fanout:
        mode = "redis_streams_fanout"
        hint = (
            "REDIS_URL set: durable XADD to Streams "
            f"({stream.get('stream_key')}); default Streams fan-out via "
            "per-process securaiq-realtime-* consumers (pub/sub skipped)."
        )
    elif url:
        mode = "redis_streams+pubsub"
        hint = (
            "REDIS_URL set: durable XADD to Streams "
            f"({stream.get('stream_key')}) + transitional pub/sub SSE fan-out "
            "(REALTIME_STREAMS_FANOUT=false). Default is Streams fan-out."
        )
    else:
        mode = "in_process"
        hint = (
            "Single-process only — in-memory replay buffer for Last-Event-ID. "
            "Set REDIS_URL for Streams durability + Streams SSE fan-out."
        )
    processor: dict[str, Any] = {}
    try:
        from app.event_processor import processor_status

        processor = processor_status()
    except Exception:
        processor = {"mode": "unknown"}
    return {
        "mode": mode,
        "redis_configured": bool(url),
        "channel": (_CHANNEL if url and not fanout else None),
        "streams_fanout": fanout,
        "stream": stream,
        "processor": processor,
        "local_subscribers": subscriber_count(),
        "pid": _PID,
        "hint": hint,
    }
