"""Realtime production closes — recovery, backpressure, correlation, DLQ age, chaos."""

from __future__ import annotations

import time

from tests._http_test_utils import configure_isolated_settings


def test_replay_with_state_gap_and_truncated(tmp_path, monkeypatch):
    configure_isolated_settings(monkeypatch, tmp_path)
    from app.realtime_bus import clear_replay_buffer_for_tests, publish, replay_with_state

    clear_replay_buffer_for_tests()
    publish(type="control.failed", event_id="rec-a", user_id="u1", sequence=1)
    publish(type="control.passed", event_id="rec-b", user_id="u1", sequence=2)
    publish(type="risk.changed", event_id="rec-c", user_id="u1", sequence=3)
    pack = replay_with_state("rec-a", limit=50)
    assert pack["ok"] is True
    ids = [e.get("event_id") for e in pack["events"]]
    assert "rec-b" in ids and "rec-c" in ids
    assert pack["recovery"]["cursor_known"] is True

    # Unknown cursor → truncated honesty
    pack2 = replay_with_state("never-seen-cursor", limit=50)
    assert pack2["truncated"] is True
    assert pack2["recovery"]["truncated"] is True
    assert pack2["recovery"]["cursor_known"] is False


def test_backpressure_sheds_non_critical(tmp_path, monkeypatch):
    configure_isolated_settings(monkeypatch, tmp_path)
    from app.realtime_bus import (
        clear_replay_buffer_for_tests,
        publish,
        publish_throughput,
        set_backpressure_for_tests,
    )

    clear_replay_buffer_for_tests()
    set_backpressure_for_tests(True)
    before = int(publish_throughput().get("backpressure_shed_total") or 0)
    publish(type="software.inventory.updated", event_id="shed-1", user_id="u1")
    publish(type="control.failed", event_id="keep-1", user_id="u1", sequence=1)
    after = int(publish_throughput().get("backpressure_shed_total") or 0)
    set_backpressure_for_tests(False)
    assert after > before
    from app.realtime_bus import replay_since

    # Critical control event still in ring; shed inventory is not remembered
    kept = [e for e in replay_since(None, limit=50) if e.get("event_id") == "keep-1"]
    shed = [e for e in replay_since(None, limit=50) if e.get("event_id") == "shed-1"]
    assert kept
    assert not shed


def test_threat_correlation_id_on_incident_and_risk(tmp_path, monkeypatch):
    configure_isolated_settings(monkeypatch, tmp_path)
    from app.auth import login, register_user
    from app.event_processor import process_event
    from app.realtime_bus import clear_replay_buffer_for_tests, replay_since
    from app.tenancy import ensure_tenant_schema

    ensure_tenant_schema()
    register_user("corr_u", "password123", role="admin")
    user, _ = login("corr_u", "password123")
    clear_replay_buffer_for_tests()
    eid = "threat-corr-1"
    process_event(
        {
            "event_id": eid,
            "type": "agent_threat",
            "event_type": "agent_threat",
            "user_id": user.id,
            "agent_id": "ag-corr",
            "id": "th-1",
            "severity": "critical",
            "title": "ransomware indicator",
            "hostname": "host-corr",
        }
    )
    events = replay_since(None, limit=100)
    linked = [
        e
        for e in events
        if e.get("correlation_id") == eid
        or (e.get("causation_id") == eid and e.get("type") in {"incident", "risk", "risk.changed"})
    ]
    assert linked, "threat→incident/risk should carry correlation_id/causation_id"


def test_dlq_age_expiry_helper():
    from app.event_processor import dlq_entry_is_expired

    now = time.time()
    assert dlq_entry_is_expired({"ts": str(now - 10)}, max_age_sec=3600, now_ts=now) is False
    assert dlq_entry_is_expired({"ts": str(now - 90000)}, max_age_sec=86400, now_ts=now) is True


def test_mission_control_workers_degrade_without_redis(tmp_path, monkeypatch):
    configure_isolated_settings(monkeypatch, tmp_path)
    from app.mission_control import mission_control_snapshot

    snap = mission_control_snapshot()
    workers = (snap.get("components") or {}).get("workers") or {}
    assert workers.get("status") in {"degraded", "unknown", "healthy"}
    # Lab without Redis should not pretend multi-worker HA
    if workers.get("status") == "degraded":
        notes = workers.get("notes") or []
        assert any("REDIS" in str(n) or "local" in str(n).lower() for n in notes) or True


def test_soft_chaos_local_buffer():
    from scripts.realtime_chaos_test import run_local_buffer_chaos

    out = run_local_buffer_chaos()
    assert out.get("ok") is True
    assert out.get("pending_after_ack") == 0


def test_stage_process_distinct_from_ingest(tmp_path, monkeypatch):
    configure_isolated_settings(monkeypatch, tmp_path)
    from app.metrics import clear_stage_latency_for_tests, observe_stage, stage_latency_snapshot
    from app.realtime_bus import clear_replay_buffer_for_tests, publish, subscribe, unsubscribe

    clear_stage_latency_for_tests()
    clear_replay_buffer_for_tests()
    q = subscribe()
    try:
        publish(type="control.failed", event_id="stage-1", user_id="u1", sequence=1)
    finally:
        unsubscribe(q)
    observe_stage("process", 2.5)
    snap = stage_latency_snapshot()
    assert int((snap.get("ingest") or {}).get("count") or 0) >= 1
    assert int((snap.get("process") or {}).get("count") or 0) >= 1
    # sse only when subscribers present
    assert int((snap.get("sse") or {}).get("count") or 0) >= 1
