"""Phase 1 Redis Streams durability — DLQ helpers + reclaim (mocked Redis)."""

from __future__ import annotations

import json
from unittest.mock import AsyncMock

import pytest

from app import event_idempotency, event_processor, realtime_bus


@pytest.fixture(autouse=True)
def _reset():
    realtime_bus.clear_replay_buffer_for_tests()
    event_processor.reset_processor_for_tests()
    yield
    realtime_bus.clear_replay_buffer_for_tests()
    event_processor.reset_processor_for_tests()


def test_build_dlq_fields_shape():
    fields = event_processor.build_dlq_fields(
        {"type": "vuln", "event_id": "e1", "severity": "high"},
        error="handler_failed",
        delivery_count=5,
        stream_id="1700000000000-0",
        source_stream="securaiq:events",
    )
    assert fields["error"] == "handler_failed"
    assert fields["delivery_count"] == "5"
    assert fields["stream_id"] == "1700000000000-0"
    assert fields["source_stream"] == "securaiq:events"
    assert "ts" in fields
    loaded = json.loads(fields["payload"])
    assert loaded["event_id"] == "e1"
    assert loaded["type"] == "vuln"


def test_build_dlq_fields_handles_bad_payload():
    fields = event_processor.build_dlq_fields(
        None,  # type: ignore[arg-type]
        error="x",
        delivery_count=1,
        stream_id="1-0",
    )
    assert json.loads(fields["payload"]) == {}


def test_should_dead_letter_threshold():
    assert not event_processor.should_dead_letter(delivery_count=1, max_deliveries=5)
    assert not event_processor.should_dead_letter(delivery_count=4, max_deliveries=5)
    assert event_processor.should_dead_letter(delivery_count=5, max_deliveries=5)
    assert event_processor.should_dead_letter(delivery_count=9, max_deliveries=5)


def test_parse_stream_payload():
    raw = {"payload": json.dumps({"type": "gap", "event_id": "g1"})}
    assert event_processor._parse_stream_payload(raw)["event_id"] == "g1"
    assert event_processor._parse_stream_payload({"payload": "not-json"}) == {}
    assert event_processor._parse_stream_payload(None) == {}


def test_process_event_returns_false_on_handler_failure(monkeypatch):
    original = event_processor.HANDLERS.get("gap")

    def _boom(_ev):
        raise RuntimeError("boom")

    monkeypatch.setitem(event_processor.HANDLERS, "gap", _boom)
    try:
        ok = event_processor.process_event(
            {"type": "gap", "event_type": "gap", "event_id": "fail-ret", "user_id": "u1"}
        )
        assert ok is False
    finally:
        if original is not None:
            event_processor.HANDLERS["gap"] = original


def test_process_event_returns_true_on_success_and_skip():
    assert event_processor.process_event(None) is True
    assert event_processor.process_event({"severity": "high"}) is True
    assert (
        event_processor.process_event(
            {"type": "unknown_xyz", "event_id": "u1"}
        )
        is True
    )


@pytest.mark.asyncio
async def test_handle_stream_message_acks_on_success(monkeypatch):
    client = AsyncMock()
    client.xpending_range = AsyncMock(return_value=[{"times_delivered": 1}])
    client.xack = AsyncMock()
    client.xadd = AsyncMock()

    monkeypatch.setattr(
        event_processor,
        "process_event",
        lambda _e: True,
    )
    payload = {"type": "vuln", "event_id": "ok-1"}
    fields = {"payload": json.dumps(payload)}
    await event_processor._handle_stream_message(
        client, "securaiq:events", "1-0", fields
    )
    client.xack.assert_awaited()
    client.xadd.assert_not_awaited()


@pytest.mark.asyncio
async def test_handle_stream_message_leaves_pending_before_max(monkeypatch):
    client = AsyncMock()
    client.xpending_range = AsyncMock(return_value=[{"times_delivered": 2}])
    client.xack = AsyncMock()
    client.xadd = AsyncMock()
    monkeypatch.setattr(event_processor, "_max_deliveries", lambda: 5)
    monkeypatch.setattr(event_processor, "process_event", lambda _e: False)

    await event_processor._handle_stream_message(
        client,
        "securaiq:events",
        "2-0",
        {"payload": json.dumps({"type": "gap", "event_id": "retry-1"})},
    )
    client.xack.assert_not_awaited()
    client.xadd.assert_not_awaited()


@pytest.mark.asyncio
async def test_handle_stream_message_dlq_and_ack_at_max(monkeypatch):
    client = AsyncMock()
    client.xpending_range = AsyncMock(return_value=[{"times_delivered": 5}])
    client.xack = AsyncMock()
    client.xadd = AsyncMock(return_value="dlq-1")
    monkeypatch.setattr(event_processor, "_max_deliveries", lambda: 5)
    monkeypatch.setattr(event_processor, "_dlq_key", lambda: "securaiq:events:dlq")
    monkeypatch.setattr(event_processor, "process_event", lambda _e: False)

    await event_processor._handle_stream_message(
        client,
        "securaiq:events",
        "3-0",
        {"payload": json.dumps({"type": "gap", "event_id": "dlq-1"})},
    )
    client.xadd.assert_awaited()
    args, kwargs = client.xadd.await_args
    assert args[0] == "securaiq:events:dlq"
    fields = args[1]
    assert fields["stream_id"] == "3-0"
    assert fields["delivery_count"] == "5"
    assert "handler_failed" in fields["error"]
    client.xack.assert_awaited()


@pytest.mark.asyncio
async def test_reclaim_pending_reprocesses(monkeypatch):
    client = AsyncMock()
    client.xautoclaim = AsyncMock(
        return_value=(
            "0-0",
            [
                (
                    "9-0",
                    {"payload": json.dumps({"type": "vuln", "event_id": "reclaim-1"})},
                )
            ],
        )
    )
    handled: list[str] = []

    async def _handle(_client, _stream, msg_id, _fields):
        handled.append(msg_id)

    monkeypatch.setattr(event_processor, "_handle_stream_message", _handle)
    monkeypatch.setattr(event_processor, "_claim_idle_ms", lambda: 60000)

    n = await event_processor._reclaim_pending(client, "securaiq:events")
    assert n == 1
    assert handled == ["9-0"]
    client.xautoclaim.assert_awaited()


def test_stream_monitor_snapshot_no_redis_safe(monkeypatch):
    monkeypatch.setattr(event_processor, "_redis_configured", lambda: False)
    snap = event_processor.stream_monitor_snapshot()
    assert snap["stream_length"] is None
    assert snap["dlq_length"] is None
    assert snap["pending_count"] is None


def test_processor_status_includes_durability_keys():
    st = event_processor.processor_status()
    assert "stream_length" in st
    assert "dlq_length" in st
    assert "pending_count" in st
    assert st["mode"] in {"local_publish_hooks", "redis_streams"}


def test_stream_status_never_raises_without_redis():
    st = realtime_bus.stream_status()
    assert st["mode"] == "in_process"
    assert "stream_length" in st
    assert "dlq_length" in st
    bs = realtime_bus.backend_status()
    assert "processor" in bs
    assert isinstance(bs["processor"], dict)


def test_idempotency_still_skips_after_durability_helpers(tmp_path, monkeypatch):
    """RT-06 ledger still gates duplicate side-effects."""
    import importlib

    data_dir = tmp_path / "dur"
    data_dir.mkdir(exist_ok=True)
    monkeypatch.setenv("DATA_DIR", str(data_dir))
    monkeypatch.setenv("DATABASE_URL", "")
    monkeypatch.setenv("WORKSPACE_ZERO_START", "false")
    import app.config as config_mod
    import app.db as db_mod

    importlib.reload(config_mod)
    db_mod.reset_conn_for_tests()
    importlib.reload(db_mod)
    event_idempotency.clear_processed_for_tests()
    event_idempotency.ensure_processed_events_schema()

    calls: list[str] = []
    original = event_processor.HANDLERS.get("vuln")

    def _handler(ev):
        calls.append(str(ev.get("event_id")))

    monkeypatch.setitem(event_processor.HANDLERS, "vuln", _handler)
    try:
        assert (
            event_processor.process_event(
                {
                    "type": "vuln",
                    "event_type": "vuln",
                    "event_id": "dur-idem-1",
                    "user_id": "u1",
                }
            )
            is True
        )
        assert (
            event_processor.process_event(
                {
                    "type": "vuln",
                    "event_type": "vuln",
                    "event_id": "dur-idem-1",
                    "user_id": "u1",
                }
            )
            is True
        )
        assert calls == ["dur-idem-1"]
    finally:
        if original is not None:
            event_processor.HANDLERS["vuln"] = original


def test_dotted_event_type_aliases_registered():
    from app.event_schema import is_registered_event_type

    for et in (
        "agent.connected",
        "agent.disconnected",
        "agent.health_changed",
        "threat.created",
        "threat.updated",
        "incident.created",
        "incident.updated",
        "risk.changed",
        "compliance.control_failed",
        "compliance.control_passed",
        "evidence.created",
        "remediation.created",
        "remediation.completed",
        "verification.completed",
        "scan.started",
        "scan.progress",
        "scan.completed",
    ):
        assert is_registered_event_type(et), et


def test_streams_fanout_default_true():
    from app.config import settings

    assert settings.realtime_streams_fanout is True
