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
# Soft throughput / backpressure meters (process-local; never raises)
_PUBLISH_TOTAL = 0
_DUP_DROPPED = 0
_BACKPRESSURE_HITS = 0
_BACKPRESSURE_SHED = 0
_BACKPRESSURE_ACTIVE = False
_PUBLISH_WINDOW: list[float] = []  # recent publish timestamps for events/sec
_PUBLISH_WINDOW_SEC = 60.0
_DEFAULT_BACKPRESSURE_LEN = 8000
# When soft backpressure is active, shed these noisy types from durable path.
_SHEDDABLE_PREFIXES = (
    "software.",
    "inventory",
    "software_inventory",
    "agent.telemetry",
    "telemetry",
    "heartbeat",
)
_CRITICAL_PREFIXES = (
    "control.",
    "risk",
    "command.",
    "remediation",
    "verification.",
    "agent_command",
    "incident",
    "compliance",
    "sequence_gap",
    "recovery",
    "agent.offline",
    "agent.disconnected",
)
_BATCHABLE_TYPES = frozenset(
    {
        "vuln",
        "vulnerability",
        "finding",
        "vuln_batch",
        "software.inventory.updated",
        "software.vulnerability.changed",
        "software.installed",
        "software.removed",
        "software.updated",
    }
)
_THROTTLE_TYPES = frozenset({"scan"})
_batch_lock = threading.Lock()
_batch_buf: list[dict[str, Any]] = []
_throttle_last: dict[str, dict[str, Any]] = {}
_batch_timer: threading.Timer | None = None
_BATCH_BUFFERED = 0
_BATCH_FLUSHED = 0
_BATCH_EMITTED = 0


def bind_loop(loop: asyncio.AbstractEventLoop | None = None) -> None:
    """Remember the running event loop so sync callers can wake subscribers.

    Also starts Redis listeners (pub/sub and/or Streams fanout) and the Task C
    Streams event processor — both are best-effort background tasks.
    """
    global _loop, _redis_task, _streams_fanout_task
    _loop = loop or asyncio.get_running_loop()
    ready = _redis_ready()
    if ready and not _streams_fanout_enabled():
        if _redis_task is None or _redis_task.done():
            try:
                _redis_task = _loop.create_task(_redis_listener())
            except Exception:
                _redis_task = None
    else:
        _redis_task = None
    if ready and _streams_fanout_enabled():
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
    t0 = time.perf_counter()
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
    if subs:
        try:
            from app.metrics import observe_stage

            observe_stage("sse", (time.perf_counter() - t0) * 1000.0)
        except Exception:
            pass


def _event_type_of(payload: dict[str, Any]) -> str:
    return str(payload.get("event_type") or payload.get("type") or "").strip().lower()


def _is_critical_event(payload: dict[str, Any]) -> bool:
    et = _event_type_of(payload)
    if not et:
        return True
    if any(et == p or et.startswith(p) for p in _CRITICAL_PREFIXES):
        return True
    return False


def _is_sheddable_event(payload: dict[str, Any]) -> bool:
    if _is_critical_event(payload):
        return False
    et = _event_type_of(payload)
    return any(et == p or et.startswith(p) for p in _SHEDDABLE_PREFIXES)


def _event_severity(payload: dict[str, Any]) -> str:
    sev = str(payload.get("severity") or "").strip().lower()
    if sev:
        return sev
    data = payload.get("data")
    if isinstance(data, dict):
        return str(data.get("severity") or "").strip().lower()
    return ""


def _is_immediate_event(payload: dict[str, Any]) -> bool:
    if _is_critical_event(payload):
        return True
    if _event_severity(payload) in {"critical", "high"}:
        return True
    return False


def _sse_batch_ms() -> int:
    raw = (os.environ.get("SSE_BATCH_MS") or "").strip()
    if raw == "0":
        return 0
    if not raw and os.environ.get("PYTEST_CURRENT_TEST"):
        return 0
    try:
        return max(50, min(int(raw or "350"), 2000))
    except ValueError:
        return 350


def _is_batchable_event(payload: dict[str, Any]) -> bool:
    if _sse_batch_ms() <= 0:
        return False
    if _is_immediate_event(payload):
        return False
    et = _event_type_of(payload)
    if et in _BATCHABLE_TYPES or et.startswith("software."):
        return True
    return False


def _is_throttled_event(payload: dict[str, Any]) -> bool:
    if _sse_batch_ms() <= 0:
        return False
    if _is_immediate_event(payload):
        return False
    return _event_type_of(payload) in _THROTTLE_TYPES


def sse_batch_stats() -> dict[str, Any]:
    with _batch_lock:
        return {
            "buffered": _BATCH_BUFFERED,
            "flushed": _BATCH_FLUSHED,
            "emitted": _BATCH_EMITTED,
            "pending": len(_batch_buf) + len(_throttle_last),
            "window_ms": _sse_batch_ms(),
        }


def flush_sse_batches() -> int:
    """Test/ops helper — flush the findings batch window now."""
    return _flush_batches()


def _note_shed() -> None:
    global _BACKPRESSURE_SHED
    with _lock:
        _BACKPRESSURE_SHED += 1


def set_backpressure_for_tests(active: bool) -> None:
    """Test helper — force soft-backpressure active state."""
    global _BACKPRESSURE_ACTIVE
    with _lock:
        _BACKPRESSURE_ACTIVE = bool(active)


def _redis_url() -> str:
    """Legacy helper — URL string when using direct Redis (empty under Sentinel-only)."""
    try:
        from app.redis_client import redis_url, redis_enabled, connection_mode

        if connection_mode() == "sentinel":
            # Sentinel path does not need REDIS_URL; signal "configured" via sentinel.
            return redis_url() or ("sentinel://" if redis_enabled() else "")
        return redis_url()
    except Exception:
        try:
            from app.config import settings

            return (getattr(settings, "redis_url", "") or "").strip()
        except Exception:
            return ""


def _redis_ready() -> bool:
    try:
        from app.redis_client import redis_enabled

        return redis_enabled()
    except Exception:
        return bool(_redis_url())


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


def tenant_stream_key(org_id: str | None = None) -> str:
    """Tenant-suffixed stream key. Empty org keeps the global lab stream."""
    base = _stream_key()
    oid = "".join(ch for ch in str(org_id or "").strip() if ch.isalnum() or ch in "-_")[:64]
    return f"{base}:{oid}" if oid else base


def _stream_maxlen() -> int:
    try:
        from app.config import settings

        n = int(getattr(settings, "redis_stream_maxlen", _DEFAULT_STREAM_MAXLEN) or _DEFAULT_STREAM_MAXLEN)
        return max(100, n)
    except Exception:
        return _DEFAULT_STREAM_MAXLEN


def _backpressure_len() -> int:
    try:
        from app.config import settings

        n = int(
            getattr(settings, "redis_stream_backpressure_len", _DEFAULT_BACKPRESSURE_LEN)
            or _DEFAULT_BACKPRESSURE_LEN
        )
        return max(50, min(n, _stream_maxlen()))
    except Exception:
        return min(_DEFAULT_BACKPRESSURE_LEN, _DEFAULT_STREAM_MAXLEN)


def _note_publish(*, duplicate: bool = False) -> None:
    """Update process-local publish meters. Never raises."""
    global _PUBLISH_TOTAL, _DUP_DROPPED
    now = time.time()
    with _lock:
        if duplicate:
            _DUP_DROPPED += 1
            return
        _PUBLISH_TOTAL += 1
        _PUBLISH_WINDOW.append(now)
        cutoff = now - _PUBLISH_WINDOW_SEC
        while _PUBLISH_WINDOW and _PUBLISH_WINDOW[0] < cutoff:
            _PUBLISH_WINDOW.pop(0)


def _note_backpressure(active: bool) -> None:
    """Set soft-backpressure flag; count transitions into the active state."""
    global _BACKPRESSURE_ACTIVE, _BACKPRESSURE_HITS
    with _lock:
        was = _BACKPRESSURE_ACTIVE
        _BACKPRESSURE_ACTIVE = bool(active)
        if active and not was:
            _BACKPRESSURE_HITS += 1


def publish_throughput() -> dict[str, Any]:
    """Process-local publish / dedupe / soft-backpressure meters."""
    now = time.time()
    with _lock:
        cutoff = now - _PUBLISH_WINDOW_SEC
        while _PUBLISH_WINDOW and _PUBLISH_WINDOW[0] < cutoff:
            _PUBLISH_WINDOW.pop(0)
        window_n = len(_PUBLISH_WINDOW)
        return {
            "published_total": _PUBLISH_TOTAL,
            "duplicates_dropped": _DUP_DROPPED,
            "events_per_sec": round(window_n / _PUBLISH_WINDOW_SEC, 3) if window_n else 0.0,
            "window_sec": int(_PUBLISH_WINDOW_SEC),
            "window_publishes": window_n,
            "backpressure_active": _BACKPRESSURE_ACTIVE,
            "backpressure_hits": _BACKPRESSURE_HITS,
            "backpressure_shed_total": _BACKPRESSURE_SHED,
            "backpressure_len": _backpressure_len() if _redis_ready() else None,
        }


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
    if not _redis_ready():
        return
    try:
        from app.redis_client import get_sync_redis

        r = get_sync_redis(decode_responses=True, socket_connect_timeout=0.5, socket_timeout=0.5)
        if r is None:
            return
        try:
            key = _stream_key()
            # Soft backpressure signal: still XADD (maxlen trims), but flag operators.
            try:
                xlen = int(r.xlen(key))
                bp = _backpressure_len()
                if xlen >= bp:
                    _note_backpressure(True)
                elif _BACKPRESSURE_ACTIVE and xlen < int(bp * 0.85):
                    _note_backpressure(False)
            except Exception:
                pass
            r.xadd(
                key,
                {"payload": json.dumps(payload, default=str)},
                maxlen=_stream_maxlen(),
                approximate=True,
            )
            org = str(payload.get("org_id") or payload.get("organization_id") or "").strip()
            tenant_key = tenant_stream_key(org) if org else ""
            if tenant_key and tenant_key != key:
                try:
                    r.xadd(
                        tenant_key,
                        {"payload": json.dumps(payload, default=str)},
                        maxlen=_stream_maxlen(),
                        approximate=True,
                    )
                except Exception:
                    pass
        finally:
            try:
                r.close()
            except Exception:
                pass
    except Exception as exc:
        _log.debug("stream XADD skipped: %s", exc)


def _pubsub_publish(payload: dict[str, Any], url: str) -> None:
    if not _redis_ready():
        return
    try:
        from app.redis_client import get_sync_redis

        r = get_sync_redis(decode_responses=True, socket_connect_timeout=0.5, socket_timeout=0.5)
        if r is None:
            return
        try:
            r.publish(_CHANNEL, json.dumps(payload, default=str))
        finally:
            try:
                r.close()
            except Exception:
                pass
    except Exception as exc:
        _log.debug("pubsub publish skipped: %s", exc)


def _deliver_event(payload: dict[str, Any]) -> None:
    """Fan-out a already-normalized event (local SSE + optional Redis)."""
    if not _remember_event(payload):
        _note_publish(duplicate=True)
        return
    _note_publish(duplicate=False)
    _fanout_local(payload)
    try:
        from app.event_processor import on_local_publish

        on_local_publish(payload)
    except Exception:
        pass
    url = _redis_url()
    if not _redis_ready():
        return
    _xadd_stream(payload, url)
    if not _streams_fanout_enabled():
        _pubsub_publish(payload, url)


def _schedule_flush() -> None:
    global _batch_timer
    with _batch_lock:
        if _batch_timer is not None:
            return
        _batch_timer = threading.Timer(_sse_batch_ms() / 1000.0, _flush_batches)
        _batch_timer.daemon = True
        _batch_timer.start()


def _flush_batches() -> int:
    global _batch_timer, _BATCH_FLUSHED, _BATCH_EMITTED
    with _batch_lock:
        _batch_timer = None
        items = list(_batch_buf)
        _batch_buf.clear()
        throttled = list(_throttle_last.values())
        _throttle_last.clear()
        _BATCH_FLUSHED += 1
    n = 0
    if items:
        try:
            from app.realtime_events import normalize_event

            batch = normalize_event(
                {
                    "type": "findings.batch",
                    "event_type": "findings.batch",
                    "count": len(items),
                    "findings": [
                        {
                            "id": ev.get("id"),
                            "type": ev.get("type") or ev.get("event_type"),
                            "severity": ev.get("severity"),
                        }
                        for ev in items[:200]
                    ],
                    "batched": True,
                }
            )
        except Exception:
            batch = {
                "type": "findings.batch",
                "event_type": "findings.batch",
                "count": len(items),
                "findings": items[:200],
                "batched": True,
                "ts": time.time(),
                "event_id": uuid.uuid4().hex,
            }
        batch["_pid"] = _PID
        _deliver_event(batch)
        n += 1
        with _batch_lock:
            _BATCH_EMITTED += 1
    for payload in throttled:
        _deliver_event(payload)
        n += 1
    return n


def publish(event: dict[str, Any] | None = None, **kwargs: Any) -> None:
    """Broadcast an event to local SSE subscribers (+ Redis when configured).

    Payloads are normalized to the REALTIME v1 contract (event_id, event_type,
    sequence, timestamps, data, …) while preserving legacy ``type`` / ``seq`` /
    ``org_id`` and top-level domain fields for existing SSE consumers.
    Normal findings are buffered (SSE_BATCH_MS) into ``findings.batch``.
    Critical / agent-offline / remediation events stay immediate.
    """
    t0 = time.perf_counter()
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

    # Soft backpressure: shed noisy non-critical events (still keep control/risk/command).
    if _BACKPRESSURE_ACTIVE and _is_sheddable_event(payload):
        _note_shed()
        _note_publish(duplicate=False)
        try:
            from app.metrics import observe_stage

            observe_stage("ingest", (time.perf_counter() - t0) * 1000.0)
        except Exception:
            pass
        return

    try:
        from app.metrics import observe_stage

        observe_stage("ingest", (time.perf_counter() - t0) * 1000.0)
    except Exception:
        pass

    if _is_batchable_event(payload):
        global _BATCH_BUFFERED
        with _batch_lock:
            _batch_buf.append(payload)
            _BATCH_BUFFERED += 1
        _schedule_flush()
        return
    if _is_throttled_event(payload):
        key = f"{_event_type_of(payload)}:{payload.get('id') or payload.get('scan_id') or '_'}"
        with _batch_lock:
            _throttle_last[key] = payload
        _schedule_flush()
        return

    _deliver_event(payload)


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
    if not _redis_ready():
        return []
    lim = max(1, min(int(limit or 200), 2000))
    scan = max(lim, min(_DEFAULT_STREAM_REPLAY_SCAN, 2000))
    try:
        from app.redis_client import get_sync_redis

        r = get_sync_redis(decode_responses=True, socket_connect_timeout=0.5, socket_timeout=0.5)
        if r is None:
            return []
        try:
            # Newest-first window, then reverse to oldest-first for catch-up.
            rows = r.xrevrange(_stream_key(), max="+", min="-", count=scan)
        finally:
            try:
                r.close()
            except Exception:
                pass
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


def detect_sequence_gaps(events: list[dict[str, Any]]) -> dict[str, Any]:
    """Detect missing sequence numbers in a replay window.

    Returns gap metadata for clients to request recovery. Does not invent events.
    Caps span so unrelated sequence namespaces cannot OOM the process.
    """
    seqs: list[int] = []
    for ev in events:
        raw = ev.get("sequence") if ev.get("sequence") is not None else ev.get("seq")
        try:
            seqs.append(int(raw))
        except Exception:
            continue
    if len(seqs) < 2:
        return {"gap_detected": False, "missing": [], "checked": len(seqs)}
    seqs_sorted = sorted(set(seqs))
    missing: list[int] = []
    max_span = 64  # only report small contiguous holes inside a window
    for a, b in zip(seqs_sorted, seqs_sorted[1:]):
        span = b - a
        if 1 < span <= max_span:
            missing.extend(range(a + 1, b))
            if len(missing) > 100:
                break
    return {
        "gap_detected": bool(missing),
        "missing": missing[:100],
        "missing_from": missing[0] if missing else None,
        "missing_to": missing[-1] if missing else None,
        "checked": len(seqs_sorted),
        "first_seq": seqs_sorted[0],
        "last_seq": seqs_sorted[-1],
        "max_span_checked": max_span,
    }


def replay_with_state(
    last_event_id: str | None,
    *,
    limit: int = 200,
) -> dict[str, Any]:
    """Authoritative catch-up pack: events + gap detection + buffer version.

    EVENTS → STATE hints for reconnect. Not full HA multi-AZ proof.
    """
    lim = max(1, min(int(limit or 200), 2000))
    cursor_known = False
    truncated = False
    with _lock:
        items = list(_REPLAY_BUFFER.items())
        buf_len = len(_REPLAY_BUFFER)
        last_eid = next(reversed(_REPLAY_BUFFER)) if _REPLAY_BUFFER else ""
    if last_event_id and items:
        needle = str(last_event_id).strip()
        cursor_known = any(eid == needle for eid, _ in items)
        if not cursor_known:
            truncated = True  # cursor outside retention window — recent dump only
    events = replay_since(last_event_id, limit=lim)
    gaps = detect_sequence_gaps(events)
    recovery: dict[str, Any] = {
        "type": "recovery",
        "event_type": "recovery",
        "cursor": last_event_id or "",
        "cursor_known": cursor_known if last_event_id else True,
        "truncated": truncated,
        "replay_count": len(events),
        "gap_detected": bool(gaps.get("gap_detected")),
        "missing_from": gaps.get("missing_from"),
        "missing": (gaps.get("missing") or [])[:20],
        "disclaimer": "Lab catch-up — not full HA multi-AZ replay",
    }
    return {
        "ok": True,
        "events": events,
        "count": len(events),
        "gaps": gaps,
        "recovery": recovery,
        "replay_buffer_size": buf_len,
        "latest_event_id": last_eid or (events[-1].get("event_id") if events else None),
        "cursor": last_event_id,
        "truncated": truncated,
        "note": (
            "In-process + best-effort Streams replay. "
            "Gap recovery requests missing sequences when detected; "
            "full persistent multi-AZ queue remains a Release gate."
        ),
    }


def stream_status() -> dict[str, Any]:
    """Health snapshot for Streams + in-process replay buffer.

    Best-effort XLEN / DLQ / pending metrics when Redis is configured.
    Never raises.
    """
    ready = _redis_ready()
    fanout = _streams_fanout_enabled()
    with _lock:
        buf_len = len(_REPLAY_BUFFER)
    status: dict[str, Any] = {
        "stream_key": _stream_key() if ready else None,
        "maxlen": _stream_maxlen() if ready else None,
        "mode": "redis_streams" if ready else "in_process",
        "redis_configured": ready,
        "pubsub_channel": (_CHANNEL if ready and not fanout else None),
        "streams_fanout": bool(ready and fanout),
        "replay_buffer_size": buf_len,
        "replay_buffer_max": _replay_buffer_max(),
        "consumer_group": "securaiq-workers" if ready else None,
        "realtime_fanout_group": (f"securaiq-realtime-{_PID}" if ready and fanout else None),
        "stream_length": None,
        "dlq_length": None,
        "pending_count": None,
        "consumer_group_lag": None,
        "dlq_key": None,
        "throughput": publish_throughput(),
    }
    if ready:
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
        try:
            from app.redis_client import describe_backend

            status["redis_backend"] = describe_backend()
        except Exception:
            pass
    return status


async def _redis_listener() -> None:
    """Subscribe to Redis channel and fan out remote workers' events locally."""
    if not _redis_ready() or _streams_fanout_enabled():
        return

    backoff = 2.0
    while True:
        client = None
        try:
            from app.redis_client import get_async_redis

            client = await get_async_redis(decode_responses=True)
            if client is None:
                return
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
        finally:
            if client is not None:
                try:
                    await client.aclose()
                except Exception:
                    try:
                        await client.close()
                    except Exception:
                        pass


async def _ensure_realtime_fanout_group(client: Any, stream: str, group: str) -> None:
    try:
        # id="$" — only new messages after group creation (avoid replay storms).
        await client.xgroup_create(name=stream, groupname=group, id="$", mkstream=True)
        _log.info("created Streams fanout group %s on %s", group, stream)
    except Exception as exc:
        if "BUSYGROUP" not in str(exc).upper():
            _log.debug("xgroup_create fanout: %s", exc)


async def _reclaim_fanout_pending(client: Any, stream: str, group: str, consumer: str) -> int:
    """XAUTOCLAIM idle pending for this process fan-out group; fan to SSE + ACK."""
    claimed = 0
    try:
        from app.config import settings

        idle = max(1000, int(getattr(settings, "redis_stream_claim_idle_ms", 60000) or 60000))
    except Exception:
        idle = 60000
    try:
        result = await client.xautoclaim(
            name=stream,
            groupname=group,
            consumername=consumer,
            min_idle_time=idle,
            start_id="0-0",
            count=20,
        )
    except Exception as exc:
        _log.debug("fanout xautoclaim skipped: %s", exc)
        return 0
    messages: list[Any] = []
    if isinstance(result, (list, tuple)) and len(result) >= 2 and isinstance(result[1], (list, tuple)):
        messages = list(result[1])
    for item in messages:
        try:
            if not isinstance(item, (list, tuple)) or len(item) < 2:
                continue
            msg_id, fields = item[0], item[1]
            payload = _payload_from_stream_fields(fields) or {}
            if payload and _remember_event(payload):
                _fanout_local(payload)
            await client.xack(stream, group, msg_id)
            claimed += 1
        except Exception:
            pass
    return claimed


async def _streams_fanout_listener() -> None:
    """Per-process Streams consumer → local SSE (RT-02 default when Redis set).

    Uses group ``securaiq-realtime-{pid}`` so *each* worker receives a copy
    (shared single group would not multi-worker fan out). Publishing workers
    already ``_fanout_local``; ``_remember_event`` drops echo duplicates.
    Idle pending are reclaimed via periodic ``XAUTOCLAIM`` for this group.
    """
    if not _redis_ready() or not _streams_fanout_enabled():
        return

    stream = _stream_key()
    group = f"securaiq-realtime-{_PID}"
    consumer = f"sse-{_PID}"
    backoff = 2.0
    while True:
        client = None
        try:
            from app.redis_client import get_async_redis

            client = await get_async_redis(decode_responses=True)
            if client is None:
                return
            await _ensure_realtime_fanout_group(client, stream, group)
            backoff = 2.0
            last_reclaim = 0.0
            while True:
                if not _streams_fanout_enabled():
                    return
                now = time.monotonic()
                if now - last_reclaim >= 30.0:
                    try:
                        await _reclaim_fanout_pending(client, stream, group, consumer)
                    except Exception as exc:
                        _log.debug("fanout reclaim: %s", exc)
                    last_reclaim = now
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
    global _PUBLISH_TOTAL, _DUP_DROPPED, _BACKPRESSURE_HITS, _BACKPRESSURE_ACTIVE
    with _lock:
        _REPLAY_BUFFER.clear()
        _PUBLISH_TOTAL = 0
        _DUP_DROPPED = 0
        _BACKPRESSURE_HITS = 0
        _BACKPRESSURE_ACTIVE = False
        _PUBLISH_WINDOW.clear()


def backend_status() -> dict[str, Any]:
    ready = _redis_ready()
    stream = stream_status()
    fanout = bool(ready and _streams_fanout_enabled())
    redis_backend: dict[str, Any] = {}
    try:
        from app.redis_client import describe_backend

        redis_backend = describe_backend()
    except Exception:
        redis_backend = {}
    if ready and fanout:
        mode = "redis_streams_fanout"
        hint = (
            "Redis configured: durable XADD to Streams "
            f"({stream.get('stream_key')}); default Streams fan-out via "
            "per-process securaiq-realtime-* consumers (pub/sub skipped)."
        )
    elif ready:
        mode = "redis_streams+pubsub"
        hint = (
            "Redis configured: durable XADD to Streams "
            f"({stream.get('stream_key')}) + transitional pub/sub SSE fan-out "
            "(REALTIME_STREAMS_FANOUT=false). Default is Streams fan-out."
        )
    else:
        mode = "in_process"
        hint = (
            "Single-process only — in-memory replay buffer for Last-Event-ID. "
            "Set REDIS_URL (or REDIS_SENTINEL_HOSTS) for Streams durability + fan-out."
        )
    processor: dict[str, Any] = {}
    try:
        from app.event_processor import processor_status

        processor = processor_status()
    except Exception:
        processor = {"mode": "unknown"}
    return {
        "mode": mode,
        "redis_configured": ready,
        "redis_backend": redis_backend,
        "channel": (_CHANNEL if ready and not fanout else None),
        "streams_fanout": fanout,
        "stream": stream,
        "processor": processor,
        "throughput": publish_throughput(),
        "local_subscribers": subscriber_count(),
        "pid": _PID,
        "hint": hint,
    }
