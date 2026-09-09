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


def test_agent_threat_critical_keyword_creates_incident(monkeypatch):
    """RT-07 — single critical + keyword → create_incident + type=incident publish."""
    creates: list[dict] = []
    publishes: list[dict] = []

    monkeypatch.setattr("app.notifications.notify", lambda *a, **k: {})
    monkeypatch.setattr(
        "app.services.evidence.record_evidence",
        lambda uid, **kw: {"id": "ev-kw", **kw},
    )
    monkeypatch.setattr("app.realtime_bus.publish", lambda **kw: publishes.append(kw))
    monkeypatch.setattr(event_processor, "_count_recent_high_threats", lambda *a, **k: 0)
    monkeypatch.setattr(event_processor, "_find_open_processor_threat_incident", lambda *a, **k: None)

    def _create(uid, **kwargs):
        row = {"id": "inc-kw-1", "org_id": kwargs.get("org_id"), **kwargs}
        creates.append({"user_id": uid, **kwargs})
        return row

    monkeypatch.setattr("app.ops.create_incident", _create)
    monkeypatch.setattr("app.ops.get_incident", lambda *a, **k: None)
    monkeypatch.setattr("app.ops.update_incident", lambda *a, **k: None)

    event_processor.process_event(
        {
            "type": "agent_threat",
            "event_id": "e-threat-kw",
            "id": "threat-kw",
            "agent_id": "agent-kw",
            "user_id": "user-kw",
            "severity": "critical",
            "title": "Suspicious PowerShell encoded command",
            "hostname": "win-lab",
            "org_id": "org-1",
        }
    )

    assert len(creates) == 1
    assert creates[0]["severity"] == "critical"
    assert creates[0]["source"] == "event_processor:agent_threat"
    assert "agent_id=agent-kw" in creates[0]["summary"]
    assert any(
        p.get("type") == "incident" and p.get("_from_processor") and p.get("id") == "inc-kw-1"
        for p in publishes
    )


def test_agent_threat_burst_creates_incident(monkeypatch):
    """RT-07 — ≥2 recent high/critical for same agent → incident (mock DB count)."""
    creates: list[dict] = []
    publishes: list[dict] = []

    monkeypatch.setattr("app.notifications.notify", lambda *a, **k: {})
    monkeypatch.setattr(
        "app.services.evidence.record_evidence",
        lambda uid, **kw: {"id": "ev-burst", **kw},
    )
    monkeypatch.setattr("app.realtime_bus.publish", lambda **kw: publishes.append(kw))
    monkeypatch.setattr(event_processor, "_count_recent_high_threats", lambda *a, **k: 2)
    monkeypatch.setattr(event_processor, "_find_open_processor_threat_incident", lambda *a, **k: None)
    monkeypatch.setattr(
        "app.ops.create_incident",
        lambda uid, **kw: creates.append(kw) or {"id": "inc-burst", **kw},
    )

    event_processor.process_event(
        {
            "type": "agent_threat",
            "event_id": "e-threat-burst",
            "id": "threat-burst",
            "agent_id": "agent-burst",
            "user_id": "user-burst",
            "severity": "high",
            "title": "Unusual process tree",
        }
    )

    assert len(creates) == 1
    assert any(p.get("type") == "incident" and p.get("_from_processor") for p in publishes)


def test_agent_threat_high_alone_no_incident(monkeypatch):
    """Single high without keyword / burst must not invent an incident."""
    creates: list = []
    monkeypatch.setattr("app.notifications.notify", lambda *a, **k: {})
    monkeypatch.setattr(
        "app.services.evidence.record_evidence",
        lambda uid, **kw: {"id": "ev-alone"},
    )
    monkeypatch.setattr("app.realtime_bus.publish", lambda **kw: None)
    monkeypatch.setattr(event_processor, "_count_recent_high_threats", lambda *a, **k: 1)
    monkeypatch.setattr(
        "app.ops.create_incident",
        lambda *a, **k: creates.append(1) or {"id": "x"},
    )

    event_processor.process_event(
        {
            "type": "agent_threat",
            "event_id": "e-threat-alone",
            "id": "threat-alone",
            "agent_id": "agent-alone",
            "user_id": "user-alone",
            "severity": "high",
            "title": "Benign-looking alert",
        }
    )
    assert creates == []


def test_inventory_recomputes_org_risk_with_previous(monkeypatch):
    """RT-08 — inventory hooks recompute risk and carry previous_score when known."""
    publishes: list[dict] = []
    scores = iter(
        [
            {"score": 10.0, "band": "low", "total_open": 1},
            {"score": 25.0, "band": "elevated", "total_open": 4},
        ]
    )

    monkeypatch.setattr(
        "app.services.risk_priority.compute_org_risk_score",
        lambda uid, **kw: next(scores),
    )
    monkeypatch.setattr("app.realtime_bus.publish", lambda **kw: publishes.append(kw))
    evidence_calls: list = []
    monkeypatch.setattr(
        "app.services.evidence.record_evidence",
        lambda *a, **k: evidence_calls.append(1) or {"id": "x"},
    )

    event_processor.process_event(
        {
            "type": "software_inventory",
            "event_id": "e-inv-1",
            "user_id": "u-inv",
            "message": "Inventory sync",
        }
    )
    event_processor.process_event(
        {
            "type": "software.inventory.updated",
            "event_id": "e-inv-2",
            "user_id": "u-inv",
            "products": 3,
        }
    )

    assert evidence_calls == []
    risk_pubs = [p for p in publishes if p.get("type") == "risk"]
    assert len(risk_pubs) == 2
    assert risk_pubs[0].get("score") == 10.0
    assert risk_pubs[0].get("event_type") == "risk.changed"
    assert "previous_score" not in risk_pubs[0]
    assert risk_pubs[1].get("score") == 25.0
    assert risk_pubs[1].get("previous_score") == 10.0
    assert risk_pubs[1].get("score_delta") == 15.0


def test_vuln_medium_skips_evidence_still_risk(monkeypatch):
    """RT-08 — medium/low must not spam derived vulnerability evidence."""
    evidence_calls: list = []
    publishes: list[dict] = []

    monkeypatch.setattr(
        "app.services.evidence.record_evidence",
        lambda uid, **kw: evidence_calls.append(kw) or {"id": "ev-m"},
    )
    monkeypatch.setattr(
        "app.services.risk_priority.compute_org_risk_score",
        lambda uid, **kw: {"score": 5.0, "band": "low", "total_open": 1},
    )
    monkeypatch.setattr("app.realtime_bus.publish", lambda **kw: publishes.append(kw))

    event_processor.process_event(
        {
            "type": "vuln",
            "event_id": "e-v-med",
            "id": "vuln-med",
            "user_id": "u-med",
            "severity": "medium",
            "title": "Low-noise finding",
        }
    )
    assert evidence_calls == []
    assert any(p.get("type") == "risk" and p.get("score") == 5.0 for p in publishes)


def test_hook_types_include_inventory():
    assert "inventory" in event_processor.HOOK_EVENT_TYPES
    assert "software_inventory" in event_processor.HOOK_EVENT_TYPES
    assert "software.inventory.updated" in event_processor.HOOK_EVENT_TYPES


def test_rt09_critical_threat_refreshes_attack_paths(monkeypatch):
    """RT-09 — critical agent_threat triggers attack-path refresh (mocked compute)."""
    refresh_calls: list[dict] = []
    publishes: list[dict] = []

    monkeypatch.setattr("app.notifications.notify", lambda *a, **k: {})
    monkeypatch.setattr(
        "app.services.evidence.record_evidence",
        lambda uid, **kw: {"id": "ev-rt09"},
    )
    monkeypatch.setattr("app.realtime_bus.publish", lambda **kw: publishes.append(kw))
    monkeypatch.setattr(event_processor, "_count_recent_high_threats", lambda *a, **k: 0)
    monkeypatch.setattr(event_processor, "_find_open_processor_threat_incident", lambda *a, **k: None)
    monkeypatch.setattr("app.ops.create_incident", lambda *a, **k: {"id": "should-not"})

    def _refresh(uid, **kwargs):
        refresh_calls.append({"user_id": uid, **kwargs})
        return {"status": "recalculated", "path_count": 2, "user_id": uid}

    monkeypatch.setattr(
        "app.services.attack_path_realtime.refresh_attack_paths_for_threat",
        _refresh,
    )

    event_processor.process_event(
        {
            "type": "agent_threat",
            "event_id": "e-rt09-crit",
            "id": "threat-rt09",
            "agent_id": "agent-rt09",
            "asset_id": "asset-99",
            "user_id": "user-rt09",
            "severity": "critical",
            "title": "Suspicious process",  # no keyword → no incident
        }
    )

    assert len(refresh_calls) == 1
    assert refresh_calls[0]["user_id"] == "user-rt09"
    assert refresh_calls[0]["agent_id"] == "agent-rt09"
    assert refresh_calls[0]["asset_id"] == "asset-99"
    assert refresh_calls[0]["reason"] == "agent_threat_critical"


def test_rt09_burst_incident_refreshes_attack_paths(monkeypatch):
    """RT-09 — RT-07 incident path also refreshes attack paths."""
    refresh_calls: list[dict] = []

    monkeypatch.setattr("app.notifications.notify", lambda *a, **k: {})
    monkeypatch.setattr(
        "app.services.evidence.record_evidence",
        lambda uid, **kw: {"id": "ev-rt09b"},
    )
    monkeypatch.setattr("app.realtime_bus.publish", lambda **kw: None)
    monkeypatch.setattr(event_processor, "_count_recent_high_threats", lambda *a, **k: 2)
    monkeypatch.setattr(event_processor, "_find_open_processor_threat_incident", lambda *a, **k: None)
    monkeypatch.setattr(
        "app.ops.create_incident",
        lambda uid, **kw: {"id": "inc-rt09", **kw},
    )
    monkeypatch.setattr(
        "app.services.attack_path_realtime.refresh_attack_paths_for_threat",
        lambda uid, **kw: refresh_calls.append({"user_id": uid, **kw}) or {"status": "recalculated", "path_count": 0},
    )

    event_processor.process_event(
        {
            "type": "agent_threat",
            "event_id": "e-rt09-burst",
            "id": "threat-rt09b",
            "agent_id": "agent-rt09b",
            "user_id": "user-rt09b",
            "severity": "high",
            "title": "Unusual process tree",
        }
    )

    assert len(refresh_calls) == 1
    assert refresh_calls[0]["reason"] == "threat_incident"
    assert refresh_calls[0]["incident_id"] == "inc-rt09"


def test_attack_path_realtime_publishes_summary(monkeypatch):
    """RT-09 module — compute_attack_paths result → attack_path bus event."""
    publishes: list[dict] = []

    monkeypatch.setattr(
        "app.services.attack_graph.compute_attack_paths",
        lambda uid, **kw: {"total_paths": 3, "paths": [{}, {}, {}], "generated_at": 1.0},
    )
    monkeypatch.setattr("app.realtime_bus.publish", lambda **kw: publishes.append(kw))
    monkeypatch.setattr("app.agents.get_agent", lambda aid: {"asset_id": "asset-from-agent"})

    from app.services.attack_path_realtime import refresh_attack_paths_for_threat

    out = refresh_attack_paths_for_threat(
        "u1",
        agent_id="ag1",
        reason="unit",
    )
    assert out is not None
    assert out["path_count"] == 3
    assert out["asset_id"] == "asset-from-agent"
    assert any(
        p.get("type") == "attack_path"
        and p.get("_from_processor")
        and p.get("path_count") == 3
        and p.get("status") == "recalculated"
        for p in publishes
    )
    assert any(p.get("type") == "risk" and p.get("reason") == "attack_path_refresh" for p in publishes)
