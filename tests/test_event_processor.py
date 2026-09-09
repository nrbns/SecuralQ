"""REALTIME v1 Task C — event processor side-effects."""

from __future__ import annotations

import pytest

from app import event_processor, realtime_bus


@pytest.fixture(autouse=True)
def _reset():
    realtime_bus.clear_replay_buffer_for_tests()
    event_processor.reset_processor_for_tests()
    yield
    realtime_bus.clear_replay_buffer_for_tests()
    event_processor.reset_processor_for_tests()


def test_process_event_empty_does_not_crash():
    event_processor.process_event(None)
    event_processor.process_event({})
    event_processor.process_event({"severity": "high"})  # no type


def test_process_event_unknown_type_does_not_crash():
    event_processor.process_event({"type": "totally_unknown_xyz", "event_id": "e1"})
    event_processor.process_event({"event_type": "not_in_hooks", "event_id": "e2"})


def test_process_event_hook_types_do_not_crash():
    for et in event_processor.HOOK_EVENT_TYPES:
        event_processor.process_event(
            {
                "type": et,
                "event_type": et,
                "event_id": f"id-{et}",
                "severity": "high",
                "org_id": "lab",
            }
        )


def test_on_local_publish_lab_path_safe(monkeypatch):
    monkeypatch.setattr(event_processor, "_redis_configured", lambda: False)
    event_processor.on_local_publish(None)
    event_processor.on_local_publish({"type": "agent_threat", "event_id": "t1"})
    event_processor.on_local_publish({"type": "job", "event_id": "j1"})  # not a hook type


def test_on_local_publish_skipped_when_redis(monkeypatch):
    called: list[dict] = []

    def _capture(ev):
        called.append(ev)

    monkeypatch.setattr(event_processor, "_redis_configured", lambda: True)
    monkeypatch.setattr(event_processor, "process_event", _capture)
    event_processor.on_local_publish({"type": "vuln", "event_id": "v1"})
    assert called == []


def test_processor_status_shape():
    st = event_processor.processor_status()
    assert "mode" in st
    assert "hook_types" in st
    assert st["mode"] in {"local_publish_hooks", "redis_streams"}
    assert "agent_threat" in st["hook_types"]
    assert "incident" in st["hook_types"]
    assert "gap" in st["hook_types"]


def test_from_processor_flag_skips_handler():
    # Would recurse if stubs ever re-publish without the guard.
    event_processor.process_event(
        {"type": "vuln", "event_id": "x", "_from_processor": True}
    )


def test_agent_threat_with_user_id_notifies_and_records(monkeypatch):
    notifies: list[tuple] = []
    evidence_calls: list[dict] = []
    publishes: list[dict] = []

    def _notify(uid, kind, title, body="", link=""):
        notifies.append((uid, kind, title, link))
        return {"id": "n1"}

    def _record(uid, **kwargs):
        evidence_calls.append({"user_id": uid, **kwargs})
        return {"id": "ev-threat-1", **kwargs}

    def _publish(**kwargs):
        publishes.append(kwargs)

    monkeypatch.setattr("app.notifications.notify", _notify)
    monkeypatch.setattr("app.services.evidence.record_evidence", _record)
    monkeypatch.setattr("app.realtime_bus.publish", _publish)

    event_processor.process_event(
        {
            "type": "agent_threat",
            "event_id": "e-threat-1",
            "id": "threat-abc",
            "agent_id": "agent-1",
            "user_id": "user-42",
            "severity": "critical",
            "title": "Suspicious process",
            "hostname": "lab-host",
        }
    )

    assert len(notifies) == 1
    assert notifies[0][0] == "user-42"
    assert notifies[0][1] == "agent_threat"
    assert notifies[0][3] == "/#agents"

    assert len(evidence_calls) == 1
    assert evidence_calls[0]["user_id"] == "user-42"
    assert evidence_calls[0]["entity_type"] == "threat"
    assert evidence_calls[0]["entity_id"] == "threat-abc"
    assert evidence_calls[0]["source"] == "observed"

    assert any(p.get("type") == "evidence" and p.get("_from_processor") for p in publishes)
    assert any(p.get("type") == "risk" and p.get("_from_processor") for p in publishes)


def test_agent_threat_missing_user_id_skips_notify_no_crash(monkeypatch):
    notifies: list = []
    evidence_calls: list = []

    monkeypatch.setattr(
        "app.notifications.notify",
        lambda *a, **k: notifies.append((a, k)) or {},
    )
    monkeypatch.setattr(
        "app.services.evidence.record_evidence",
        lambda *a, **k: evidence_calls.append((a, k)) or {"id": "x"},
    )
    # No agent row → resolve returns ""
    monkeypatch.setattr(event_processor, "_resolve_user_id", lambda _e: "")

    event_processor.process_event(
        {
            "type": "agent_threat",
            "event_id": "e-orphan",
            "id": "threat-x",
            "agent_id": "missing-agent",
            "severity": "critical",
            "title": "Orphan threat",
        }
    )
    assert notifies == []
    assert evidence_calls == []


def test_agent_threat_resolves_user_via_agent_lookup(monkeypatch):
    notifies: list = []
    evidence_calls: list = []

    monkeypatch.setattr(
        event_processor,
        "_resolve_user_id",
        lambda e: "resolved-user" if e.get("agent_id") == "ag-9" else "",
    )
    monkeypatch.setattr(
        "app.notifications.notify",
        lambda uid, kind, title, body="", link="": notifies.append(uid) or {},
    )
    monkeypatch.setattr(
        "app.services.evidence.record_evidence",
        lambda uid, **kw: evidence_calls.append(uid) or {"id": "ev1"},
    )
    monkeypatch.setattr("app.realtime_bus.publish", lambda **kw: None)

    event_processor.process_event(
        {
            "type": "agent_threat",
            "event_id": "e2",
            "id": "t2",
            "agent_id": "ag-9",
            "severity": "high",
            "title": "Looked-up threat",
        }
    )
    assert notifies == ["resolved-user"]
    assert evidence_calls == ["resolved-user"]


def test_vuln_records_derived_evidence_and_risk(monkeypatch):
    evidence_calls: list[dict] = []
    publishes: list[dict] = []

    monkeypatch.setattr(
        "app.services.evidence.record_evidence",
        lambda uid, **kw: evidence_calls.append({"user_id": uid, **kw}) or {"id": "ev-v"},
    )
    monkeypatch.setattr(
        "app.services.risk_priority.compute_org_risk_score",
        lambda uid, **kw: {"score": 42.0, "band": "elevated", "total_open": 3},
    )
    monkeypatch.setattr("app.realtime_bus.publish", lambda **kw: publishes.append(kw))
    monkeypatch.setattr("app.notifications.notify", lambda *a, **k: {})

    event_processor.process_event(
        {
            "type": "vuln",
            "event_id": "e-v",
            "id": "vuln-9",
            "user_id": "u1",
            "severity": "high",
            "title": "CVE-2024-1",
        }
    )
    assert evidence_calls and evidence_calls[0]["source"] == "derived"
    assert evidence_calls[0]["entity_type"] == "vulnerability"
    assert any(p.get("type") == "risk" and p.get("score") == 42.0 for p in publishes)


def test_agent_command_verified_notifies(monkeypatch):
    notifies: list = []
    evidence_calls: list = []

    monkeypatch.setattr(
        "app.notifications.notify",
        lambda uid, kind, title, body="", link="": notifies.append((kind, title)) or {},
    )
    monkeypatch.setattr(
        "app.services.evidence.record_evidence",
        lambda uid, **kw: evidence_calls.append(kw) or {"id": "ev-c"},
    )
    monkeypatch.setattr("app.realtime_bus.publish", lambda **kw: None)

    event_processor.process_event(
        {
            "type": "agent_command",
            "event_id": "e-c",
            "id": "cmd-1",
            "user_id": "u1",
            "status": "done",
            "lifecycle": "VERIFIED",
            "verification_status": "verified",
            "title": "Patch applied",
        }
    )
    assert evidence_calls
    assert evidence_calls[0]["source"] == "observed"
    assert notifies  # verified → notify
