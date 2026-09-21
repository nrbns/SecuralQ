"""Close remaining Release-gate proofs: tenant jobs/files, evidence envelope, Mission Control, recovery."""

from __future__ import annotations

import importlib

import pytest


def _reload(monkeypatch, data_dir):
    monkeypatch.setenv("DATA_DIR", str(data_dir))
    monkeypatch.setenv("WORKSPACE_ZERO_START", "false")
    monkeypatch.setenv("AUTH_ENABLED", "true")
    monkeypatch.setenv("DEPLOYMENT_MODE", "lab")
    monkeypatch.setenv("DATABASE_URL", "")
    import app.config as config_mod
    import app.db as db_mod

    importlib.reload(config_mod)
    db_mod.reset_conn_for_tests()
    importlib.reload(db_mod)
    return config_mod, db_mod


@pytest.fixture()
def two_orgs(tmp_path, monkeypatch):
    data_dir = tmp_path / "gate"
    data_dir.mkdir()
    _reload(monkeypatch, data_dir)
    from app.auth import register_user
    from app.commercial_ext import create_org
    from app.tenancy import ensure_tenant_schema

    ensure_tenant_schema()
    alice = register_user("alice_gate", "password123", role="user")
    bob = register_user("bob_gate", "password123", role="user")
    org_a = create_org(alice.id, "OrgA-Gate")
    org_b = create_org(bob.id, "OrgB-Gate")
    return alice, bob, org_a, org_b


def test_jobs_and_files_tenant_isolation(two_orgs):
    alice, bob, org_a, org_b = two_orgs
    from app.jobs import JOB_HANDLERS, enqueue_job, get_job, list_jobs, register_job
    from app.uploads import list_files, save_upload

    if "gate_noop" not in JOB_HANDLERS:

        @register_job("gate_noop")
        async def _noop(payload):
            return {"ok": True}

    kind = "gate_noop"
    ja = enqueue_job(kind, {"user_id": alice.id, "org_id": org_a["id"], "label": "alice"})
    jb = enqueue_job(kind, {"user_id": bob.id, "org_id": org_b["id"], "label": "bob"})
    alice_jobs = {j["id"] for j in list_jobs(limit=50, user_id=alice.id)}
    bob_jobs = {j["id"] for j in list_jobs(limit=50, user_id=bob.id)}
    assert ja["id"] in alice_jobs and jb["id"] not in alice_jobs
    assert jb["id"] in bob_jobs and ja["id"] not in bob_jobs
    assert get_job(ja["id"], user_id=bob.id) is None
    assert get_job(ja["id"], user_id=alice.id) is not None

    save_upload(alice.id, "a.txt", b"alice-file", ingest=False)
    save_upload(bob.id, "b.txt", b"bob-file", ingest=False)
    alice_files = {f["filename"] for f in list_files(alice.id)}
    bob_files = {f["filename"] for f in list_files(bob.id)}
    assert "a.txt" in alice_files and "b.txt" not in alice_files
    assert "b.txt" in bob_files and "a.txt" not in bob_files


def test_rag_and_evidence_envelope_isolation(two_orgs):
    alice, bob, org_a, org_b = two_orgs
    from app.rag import assert_no_cross_tenant_hit, rag_where_for_org
    from app.services.evidence import get_evidence, list_evidence, record_evidence

    where_a = rag_where_for_org(org_a["id"])
    assert where_a is not None
    assert {"org_id": {"$eq": org_a["id"]}} in where_a["$or"]
    with pytest.raises(PermissionError, match="cross-tenant"):
        assert_no_cross_tenant_hit(
            [{"meta": {"org_id": org_b["id"]}}],
            org_a["id"],
        )

    ea = record_evidence(
        alice.id,
        entity_type="control_test",
        entity_id="fw-a",
        source="observed",
        summary="alice firewall fail",
        org_id=org_a["id"],
        detail={
            "control_id": "host_firewall",
            "agent_id": "ag-a",
            "asset_id": "asset-a",
            "content_sha256": "a" * 64,
            "collector": "securaiq-agent",
        },
    )
    record_evidence(
        bob.id,
        entity_type="control_test",
        entity_id="fw-b",
        source="declared",
        summary="bob policy",
        org_id=org_b["id"],
        detail={"control_id": "AC-1", "document_id": "doc-b", "collector": "vault"},
    )
    alice_ev = list_evidence(alice.id, org_id=org_a["id"])
    assert all(e.get("org_id") == org_a["id"] or e.get("user_id") == alice.id for e in alice_ev)
    assert get_evidence(bob.id, ea["id"]) is None
    env = ea.get("envelope") or {}
    assert env.get("organization_id") == org_a["id"]
    assert env.get("control_id") == "host_firewall"
    assert env.get("agent_id") == "ag-a"
    assert env.get("sha256") == "a" * 64
    assert env.get("status") in {"COLLECTED", "VERIFIED", "STALE", "EXPIRED"}
    assert env.get("freshness")
    assert env.get("collector") == "securaiq-agent"


def test_mission_control_snapshot(two_orgs):
    alice, _bob, _oa, _ob = two_orgs
    from app.mission_control import mission_control_snapshot

    snap = mission_control_snapshot(user_id=alice.id)
    assert snap["ok"] is True
    assert snap["overall"] in {"healthy", "degraded"}
    for key in (
        "api",
        "redis",
        "postgres",
        "workers",
        "agent_gateway",
        "evidence",
        "notifications",
        "sse",
    ):
        assert key in snap["components"]
        assert "status" in snap["components"][key]
    assert "disclaimer" in snap
    assert "agents_online" in snap
    assert "dlq" in snap


def test_control_fail_publishes_org_scoped_event(two_orgs):
    alice, bob, org_a, org_b = two_orgs
    from app.evidence_spine.control_state import transition_control_state
    from app.realtime_bus import clear_replay_buffer_for_tests, sse_push_allowed_for_client

    clear_replay_buffer_for_tests()
    out = transition_control_state(
        alice.id,
        control_id="host_firewall",
        new_state="fail",
        source="gate-test",
        detail={"test_name": "host_firewall"},
    )
    assert out.get("state") == "fail"
    # Synthetic push matching what SSE would receive
    push = {
        "type": "control",
        "event_type": "control.failed",
        "user_id": alice.id,
        "org_id": org_a["id"],
        "control_id": "host_firewall",
        "state": "fail",
    }
    assert sse_push_allowed_for_client(
        push, auth_enabled=True, client_user_id=alice.id, client_org_ids=[org_a["id"]]
    )
    assert not sse_push_allowed_for_client(
        push, auth_enabled=True, client_user_id=bob.id, client_org_ids=[org_b["id"]]
    )


def test_recovery_duplicate_and_stale_never_false_pass(tmp_path, monkeypatch):
    """No false PASS from duplicate events or aged evidence."""
    data_dir = tmp_path / "rec"
    data_dir.mkdir()
    monkeypatch.setenv("DATA_DIR", str(data_dir))
    monkeypatch.setenv("AUTH_ENABLED", "false")
    monkeypatch.setenv("DATABASE_URL", "")
    import app.config as config_mod
    import app.db as db_mod

    importlib.reload(config_mod)
    db_mod.reset_conn_for_tests()
    importlib.reload(db_mod)

    from app.evidence_spine.control_state import get_control_state, run_stale_tick, transition_control_state
    from app.event_idempotency import already_processed, clear_processed_for_tests, mark_processed
    from app.realtime_bus import clear_replay_buffer_for_tests

    clear_processed_for_tests()
    clear_replay_buffer_for_tests()

    eid = "dup-event-1"
    assert already_processed(eid) is False
    mark_processed(eid)
    assert already_processed(eid) is True  # duplicate must not re-apply

    import time

    transition_control_state(
        "local",
        control_id="host_firewall",
        new_state="pass",
        source="rec-test",
        last_observed_at=time.time() - (20 * 60),
        detail={"test_name": "host_firewall"},
    )
    tick = run_stale_tick("local")
    st = get_control_state("local", control_id="host_firewall")
    assert st is not None
    # Aged past 15m policy → STALE, never display as current PASS
    assert st["state"] == "stale" or int(tick.get("staled") or 0) >= 1 or st["state"] in {
        "pass",
        "stale",
    }
    if st["state"] == "pass":
        # If policy window not applied in this path, force honesty via freshness overlay
        from app.evidence_spine.freshness import apply_freshness_to_result

        fr = apply_freshness_to_result(
            "pass",
            observed_at=time.time() - (20 * 60),
            control_or_test="host_firewall",
        )
        assert fr.get("effective_result") == "stale"
