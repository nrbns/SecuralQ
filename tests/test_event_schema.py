"""REALTIME v1 Task A — event contract validation + publish normalize."""

from __future__ import annotations

import asyncio

import pytest

from app import realtime_bus
from app.event_schema import (
    EVENT_VERSION,
    REQUIRED_AFTER_NORMALIZE,
    validate_event,
)
from app.realtime_events import build_event, normalize_event


@pytest.fixture(autouse=True)
def _reset_bus():
    for q in list(realtime_bus._subscribers):
        realtime_bus.unsubscribe(q)
    realtime_bus.clear_replay_buffer_for_tests()
    yield
    for q in list(realtime_bus._subscribers):
        realtime_bus.unsubscribe(q)
    realtime_bus.clear_replay_buffer_for_tests()


def test_validate_good_event():
    evt = normalize_event({"type": "vuln", "id": "v1", "severity": "critical", "org_id": "o1"})
    ok, errors = validate_event(evt, require_normalized=True)
    assert ok, errors
    assert evt["event_type"] == "vuln"
    assert evt["type"] == "vuln"
    assert evt["organization_id"] == "o1"
    assert evt["org_id"] == "o1"


def test_validate_bad_missing_type():
    ok, errors = validate_event({"severity": "high"})
    assert not ok
    assert any("event_type" in e for e in errors)


def test_validate_bad_severity():
    ok, errors = validate_event({"type": "vuln", "severity": "super-bad"})
    assert not ok
    assert any("severity" in e for e in errors)


def test_validate_bad_evidence_ids_type():
    ok, errors = validate_event({"type": "scan", "evidence_ids": "not-a-list"})
    assert not ok
    assert any("evidence_ids" in e for e in errors)


def test_normalize_produces_required_fields():
    evt = normalize_event(type="job", id="j1", status="running")
    for key in REQUIRED_AFTER_NORMALIZE:
        assert key in evt, f"missing {key}"
    assert evt["event_version"] == EVENT_VERSION
    assert evt["sequence"] == evt["seq"]
    assert isinstance(evt["data"], dict)
    assert evt["data"].get("id") == "j1"
    assert evt["id"] == "j1"  # top-level domain field preserved for SSE


def test_build_event_dual_writes_type():
    evt = build_event("agent_threat", severity="high", agent_id="a1", data={"title": "x"})
    assert evt["type"] == "agent_threat"
    assert evt["event_type"] == "agent_threat"
    assert evt["agent_id"] == "a1"
    assert evt["data"].get("title") == "x"


@pytest.mark.asyncio
async def test_publish_sse_shape_keeps_type_and_adds_contract():
    realtime_bus.bind_loop()
    q = realtime_bus.subscribe()
    realtime_bus.publish(type="vuln", id="v9", severity="critical", org_id="org-lab")

    event = await asyncio.wait_for(q.get(), timeout=1.0)
    # Backward compat — existing UI keys off push.type
    assert event["type"] == "vuln"
    assert event["event_type"] == "vuln"
    assert event["id"] == "v9"
    assert event["severity"] == "critical"
    assert "ts" in event
    assert event["event_id"]
    assert event["sequence"] == event["seq"]
    assert event["organization_id"] == "org-lab"
    assert event["org_id"] == "org-lab"
    assert isinstance(event["evidence_ids"], list)
    assert isinstance(event["data"], dict)
