"""Phase 1 realtime release-gate proofs (once-only + reclaim + SSE replay).

These tests make the Sprint 1 contract CI-provable without claiming Redis
Sentinel failover certification. Ops measurement remains:

  docker compose --profile redis-ha up -d
  python scripts/realtime_phase1_proof.py --document
"""

from __future__ import annotations

import json
from unittest.mock import AsyncMock

import pytest

from tests._http_test_utils import configure_isolated_settings


@pytest.mark.asyncio
async def test_consumer_death_xautoclaim_processes_once(tmp_path, monkeypatch):
    """Consumer A dies → B XAUTOCLAIMs → one security side-effect; duplicate skipped."""
    configure_isolated_settings(monkeypatch, tmp_path)
    from app import event_idempotency, event_processor
    from app.realtime.once_only import prove_consumer_failover_once_only
    from app.tenancy import ensure_tenant_schema

    ensure_tenant_schema()
    event_idempotency.clear_processed_for_tests()
    event_idempotency.ensure_processed_events_schema()

    side_effects: list[str] = []
    eid = "phase1-reclaim-once-1"
    event = {
        "type": "vuln",
        "event_id": eid,
        "user_id": "u-phase1",
        "_from_processor": False,
    }

    def _counting_handler(ev: dict) -> None:
        side_effects.append(str(ev.get("event_id") or ""))

    monkeypatch.setitem(event_processor.HANDLERS, "vuln", _counting_handler)

    client = AsyncMock()
    client.xautoclaim = AsyncMock(
        return_value=(
            "0-0",
            [("42-0", {"payload": json.dumps(event)})],
        )
    )
    client.xpending_range = AsyncMock(return_value=[{"times_delivered": 1}])
    client.xack = AsyncMock()
    client.xadd = AsyncMock()

    result = await prove_consumer_failover_once_only(
        reclaim_pending=event_processor._reclaim_pending,
        process_event=event_processor.process_event,
        client=client,
        stream="securaiq:events",
        event=event,
        side_effects=side_effects,
    )
    assert result.ok is True, result.detail
    assert result.side_effect_count == 1
    assert side_effects == [eid]
    client.xautoclaim.assert_awaited()
    client.xack.assert_awaited()


def test_multi_worker_duplicate_delivery_one_security_action(tmp_path, monkeypatch):
    """API workers 1..N may see the same event_id; only one security action runs."""
    configure_isolated_settings(monkeypatch, tmp_path)
    from app import event_idempotency, event_processor
    from app.tenancy import ensure_tenant_schema

    ensure_tenant_schema()
    event_idempotency.clear_processed_for_tests()
    event_idempotency.ensure_processed_events_schema()

    actions: list[str] = []

    def _security_action(ev: dict) -> None:
        actions.append("acted:" + str(ev.get("event_id")))

    monkeypatch.setitem(event_processor.HANDLERS, "control.failed", _security_action)

    event = {
        "type": "control.failed",
        "event_id": "phase1-mw-1",
        "user_id": "u-mw",
    }
    # Three workers / deliveries
    assert event_processor.process_event(event) is True
    assert event_processor.process_event(dict(event)) is True
    assert event_processor.process_event(dict(event)) is True
    assert actions == ["acted:phase1-mw-1"]


def test_sse_replay_since_last_event_id():
    """Last-Event-ID / replay window — browser reconnects without soft-polling."""
    from app import realtime_bus

    realtime_bus.clear_replay_buffer_for_tests()
    realtime_bus.publish(type="agent", id="a1", event_id="sse-a")
    realtime_bus.publish(type="agent", id="a2", event_id="sse-b")
    realtime_bus.publish(type="evidence", id="e1", event_id="sse-c")
    after = realtime_bus.replay_since("sse-a", limit=10)
    ids = [str(x.get("event_id") or "") for x in after]
    assert "sse-a" not in ids
    assert ids == ["sse-b", "sse-c"]


def test_sentinel_ops_report_without_hosts(monkeypatch):
    from app import redis_client
    from app.realtime import sentinel_ops

    monkeypatch.setattr(redis_client, "sentinel_hosts", lambda: [])
    monkeypatch.setattr(redis_client, "redis_url", lambda: "")
    redis_client.reset_clients_for_tests()
    report = sentinel_ops.sentinel_ready_report()
    assert report["sentinel_configured"] is False
    assert report["reachable"] is False
    assert "lab Sentinel" in report["disclaimer"]


def test_reconnect_after_failover_helper_exists():
    from app.redis_client import reconnect_after_failover, reset_clients_for_tests

    reset_clients_for_tests()
    # No Redis configured in default CI — returns None, must not raise.
    assert reconnect_after_failover() is None
