"""Real behavioral tests for the in-process pub/sub that backs /api/realtime.

Covers what actually matters for correctness: a subscriber receives what's
published after it subscribes, an unsubscribed queue is not written to, and
publish() is safe to call with zero subscribers (the common case at startup).
"""

from __future__ import annotations

import asyncio

import pytest

from app import realtime_bus


@pytest.fixture(autouse=True)
def _reset_bus():
    """The module holds subscriber + replay state in globals — don't leak it
    between tests."""
    for q in list(realtime_bus._subscribers):
        realtime_bus.unsubscribe(q)
    realtime_bus.clear_replay_buffer_for_tests()
    yield
    for q in list(realtime_bus._subscribers):
        realtime_bus.unsubscribe(q)
    realtime_bus.clear_replay_buffer_for_tests()


@pytest.mark.asyncio
async def test_subscribe_receives_published_event():
    realtime_bus.bind_loop()
    q = realtime_bus.subscribe()
    realtime_bus.publish(type="vuln", id="v1", severity="critical")

    event = await asyncio.wait_for(q.get(), timeout=1.0)
    assert event["type"] == "vuln"
    assert event["id"] == "v1"
    assert event["severity"] == "critical"
    assert "ts" in event  # auto-stamped


@pytest.mark.asyncio
async def test_publish_fans_out_to_all_subscribers():
    realtime_bus.bind_loop()
    q1 = realtime_bus.subscribe()
    q2 = realtime_bus.subscribe()
    realtime_bus.publish(type="incident", id="i1")

    e1 = await asyncio.wait_for(q1.get(), timeout=1.0)
    e2 = await asyncio.wait_for(q2.get(), timeout=1.0)
    assert e1["id"] == "i1"
    assert e2["id"] == "i1"


@pytest.mark.asyncio
async def test_unsubscribe_stops_delivery():
    realtime_bus.bind_loop()
    q = realtime_bus.subscribe()
    realtime_bus.unsubscribe(q)
    realtime_bus.publish(type="job", id="j1")

    assert q.empty()
    with pytest.raises(asyncio.TimeoutError):
        await asyncio.wait_for(q.get(), timeout=0.2)


def test_publish_with_no_subscribers_does_not_raise():
    # This is the steady state right after process start, before any SSE
    # client has connected — must be a silent no-op, not an exception.
    realtime_bus.publish(type="xdr", id="x1")


@pytest.mark.asyncio
async def test_subscriber_count_reflects_active_subscriptions():
    assert realtime_bus.subscriber_count() == 0
    q = realtime_bus.subscribe()
    assert realtime_bus.subscriber_count() == 1
    realtime_bus.unsubscribe(q)
    assert realtime_bus.subscriber_count() == 0


@pytest.mark.asyncio
async def test_publish_accepts_dict_and_kwargs_forms():
    realtime_bus.bind_loop()
    q = realtime_bus.subscribe()
    realtime_bus.publish({"type": "risk"}, id="r1", score=42)
    event = await asyncio.wait_for(q.get(), timeout=1.0)
    assert event["type"] == "risk"
    assert event["id"] == "r1"
    assert event["score"] == 42


@pytest.mark.asyncio
async def test_full_queue_drops_oldest_not_newest():
    realtime_bus.bind_loop()
    q = realtime_bus.subscribe(maxsize=2)
    realtime_bus.publish(type="job", id="first")
    realtime_bus.publish(type="job", id="second")
    realtime_bus.publish(type="job", id="third")  # queue was full at 2 -> oldest dropped
    # publish() hands off via loop.call_soon_threadsafe — give the loop one
    # tick to actually run the three scheduled _safe_put callbacks before we
    # inspect the queue.
    await asyncio.sleep(0)

    seen = []
    while not q.empty():
        seen.append((await q.get())["id"])
    assert "third" in seen  # newest must survive
    assert len(seen) <= 2


@pytest.mark.asyncio
async def test_publish_normalizes_and_dedupes_by_event_id():
    realtime_bus.bind_loop()
    q = realtime_bus.subscribe()
    realtime_bus.publish(type="vuln", id="dup1", event_id="fixed-eid-aaa")
    realtime_bus.publish(type="vuln", id="dup2", event_id="fixed-eid-aaa")  # duplicate

    first = await asyncio.wait_for(q.get(), timeout=1.0)
    assert first["event_id"] == "fixed-eid-aaa"
    assert first["event_type"] == "vuln"
    assert first["type"] == "vuln"
    await asyncio.sleep(0)
    assert q.empty()


def test_replay_since_returns_events_after_id():
    realtime_bus.publish(type="vuln", id="a", event_id="eid-a")
    realtime_bus.publish(type="vuln", id="b", event_id="eid-b")
    realtime_bus.publish(type="vuln", id="c", event_id="eid-c")

    after = realtime_bus.replay_since("eid-a", limit=10)
    assert [e["event_id"] for e in after] == ["eid-b", "eid-c"]
    assert after[0]["id"] == "b"

    empty = realtime_bus.replay_since("eid-c", limit=10)
    assert empty == []


def test_replay_since_none_returns_recent_window():
    realtime_bus.publish(type="job", id="1", event_id="r1")
    realtime_bus.publish(type="job", id="2", event_id="r2")
    recent = realtime_bus.replay_since(None, limit=1)
    assert len(recent) == 1
    assert recent[0]["event_id"] == "r2"


def test_stream_status_and_backend_status_in_process():
    st = realtime_bus.stream_status()
    assert st["mode"] == "in_process"
    assert st["redis_configured"] is False
    assert st["replay_buffer_max"] >= 16
    assert "throughput" in st
    assert "events_per_sec" in st["throughput"]

    bs = realtime_bus.backend_status()
    assert bs["mode"] == "in_process"
    assert bs["redis_configured"] is False
    assert isinstance(bs["stream"], dict)
    assert bs["stream"]["mode"] == "in_process"
    assert "throughput" in bs
    assert bs["throughput"]["published_total"] >= 0


def test_publish_throughput_counts_and_dedupes():
    realtime_bus.clear_replay_buffer_for_tests()
    thr0 = realtime_bus.publish_throughput()
    assert thr0["published_total"] == 0
    realtime_bus.publish(type="job", id="t1", event_id="thr-a")
    realtime_bus.publish(type="job", id="t2", event_id="thr-a")  # dup
    realtime_bus.publish(type="job", id="t3", event_id="thr-b")
    thr = realtime_bus.publish_throughput()
    assert thr["published_total"] == 2
    assert thr["duplicates_dropped"] == 1
    assert thr["window_publishes"] == 2
    assert thr["backpressure_active"] is False
