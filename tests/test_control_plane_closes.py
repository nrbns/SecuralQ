"""Golden-path auto-evidence + soft DLQ recover + stage latency closes."""

from __future__ import annotations

from tests._http_test_utils import configure_isolated_settings


def test_command_approve_records_lifecycle_evidence(tmp_path, monkeypatch):
    configure_isolated_settings(monkeypatch, tmp_path)
    from app.agents import approve_command, enroll_agent, request_enable_firewall_command
    from app.auth import login, register_user
    from app.services.evidence import get_evidence_for
    from app.tenancy import ensure_tenant_schema

    ensure_tenant_schema()
    register_user("ev_cmd", "password123", role="admin")
    user, _ = login("ev_cmd", "password123")
    agent = enroll_agent(user.id, name="ev-cmd-host")
    aid = agent["agent_id"]
    cmd = request_enable_firewall_command(user.id, aid, requested_by=user.id)
    approve_command(user.id, aid, cmd["id"], approver_id=user.id)
    rows = get_evidence_for(user.id, entity_type="command", entity_id=cmd["id"])
    assert rows, "command.approved should create command evidence"
    assert any((r.get("envelope") or r.get("detail")) for r in rows)


def test_remediation_plan_approve_and_execute_evidence(tmp_path, monkeypatch):
    configure_isolated_settings(monkeypatch, tmp_path)
    from app.auth import login, register_user
    from app.db import get_conn, init_schema, new_id, now
    from app.services.evidence import get_evidence_for
    from app.services.remediation import approve_plan
    from app.tenancy import ensure_tenant_schema

    ensure_tenant_schema()
    init_schema()
    register_user("ev_plan", "password123", role="admin")
    user, _ = login("ev_plan", "password123")
    pid = new_id()
    ts = now()
    get_conn().execute(
        """
        INSERT INTO remediation_plans (
            id, user_id, group_key, title, status, vulns_removed, assets_affected,
            asset_ids_json, internet_exposed_assets, business_critical_assets,
            agent_patchable_assets, kev, quick_win, critical_high_count,
            estimated_risk_reduction_pct, attack_paths_disrupted,
            business_critical_paths_disrupted, verified_attack_paths_disrupted,
            disruption_band, explanation, risk_before, created_at, updated_at
        ) VALUES (?, ?, 'lab', 'Lab plan', 'draft', 0, 0, '[]', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                  'low', 'lab', 0, ?, ?)
        """,
        (pid, user.id, ts, ts),
    )
    get_conn().commit()
    approved = approve_plan(user.id, pid)
    assert approved and approved.get("status") == "approved"
    rows = get_evidence_for(user.id, entity_type="remediation", entity_id=pid)
    assert rows, "remediation.approved should create evidence"


def test_soft_recover_dlq_idempotent(tmp_path, monkeypatch):
    configure_isolated_settings(monkeypatch, tmp_path)
    from app.agent_security import new_event_id
    from app.event_idempotency import clear_processed_for_tests, ensure_processed_events_schema
    from app.event_processor import build_dlq_fields, soft_recover_dlq_payload
    from app.services.evidence import get_evidence_for
    from app.tenancy import ensure_tenant_schema

    ensure_tenant_schema()
    ensure_processed_events_schema()
    clear_processed_for_tests()
    eid = new_event_id()
    fields = build_dlq_fields(
        {
            "event_id": eid,
            "type": "command.approved",
            "event_type": "command.approved",
            "user_id": "u-soft",
            "id": "cmd-soft-1",
            "status": "queued",
        },
        error="boom",
        delivery_count=5,
        stream_id="1-0",
    )
    out = soft_recover_dlq_payload(fields)
    assert out["ok"] is True
    assert out["processed"] is True
    assert out["skipped_idempotent"] is True
    rows = get_evidence_for("u-soft", entity_type="command", entity_id="cmd-soft-1")
    assert len(rows) >= 1


def test_stage_latency_meters_after_publish(tmp_path, monkeypatch):
    configure_isolated_settings(monkeypatch, tmp_path)
    from app.metrics import clear_stage_latency_for_tests, render_prometheus, stage_latency_snapshot
    from app.realtime_bus import clear_replay_buffer_for_tests, publish
    from app.realtime_ops import pipeline_metrics

    clear_stage_latency_for_tests()
    clear_replay_buffer_for_tests()
    publish(type="agent", event_id="lat-meter-1", user_id="u1", id="a1")
    snap = stage_latency_snapshot()
    assert int((snap.get("ingest") or {}).get("count") or 0) >= 1
    text = render_prometheus()
    assert "securaiq_stage_latency_p50_ms" in text
    m = pipeline_metrics()
    assert "stage_latency" in m
    assert m["stage_latency"].get("ingest", {}).get("count", 0) >= 1
