"""Control runtime state machine + evidence dependency packs."""

from __future__ import annotations

import time

from tests._http_test_utils import configure_isolated_settings


def _uid(monkeypatch, tmp_path, name="crs_user"):
    configure_isolated_settings(monkeypatch, tmp_path)
    from app.auth import login, register_user
    from app.tenancy import ensure_tenant_schema

    ensure_tenant_schema()
    register_user(name, "password123", role="admin")
    u, _ = login(name, "password123")
    return u.id


def test_dependency_pack_blocks_pass(tmp_path, monkeypatch):
    uid = _uid(monkeypatch, tmp_path, "crs_deps")
    from app.evidence_spine import (
        evaluate_dependencies,
        ingest_observation_as_evidence,
        reconcile_control,
        seed_default_packs,
    )

    seed_default_packs(uid)
    # AC-1 requires policy (documents) + runtime (satisfies)
    deps = evaluate_dependencies(uid, control_id="AC-1")
    assert deps["required"] is True
    assert deps["complete"] is False

    ingest_observation_as_evidence(
        uid,
        result="pass",
        summary="host_firewall:pass — Firewall enabled",
        agent_id="agent-1",
        test_name="host_firewall",
        controls=[{"control_id": "AC-1", "framework_id": ""}],
    )
    # Observed alone still incomplete vs pack → partial
    out = reconcile_control(uid, control_id="AC-1")
    assert out["dependencies"]["complete"] is False
    assert out["state"]["state"] == "partial"


def test_dependency_pack_complete_allows_pass(tmp_path, monkeypatch):
    uid = _uid(monkeypatch, tmp_path, "crs_full")
    from app.evidence_spine import (
        ingest_document_as_evidence,
        ingest_observation_as_evidence,
        reconcile_control,
        seed_default_packs,
    )

    seed_default_packs(uid)
    ingest_document_as_evidence(
        uid,
        title="Access control policy",
        summary="AC policy",
        control_id="AC-1",
        file_id="f-ac1",
    )
    ingest_observation_as_evidence(
        uid,
        result="pass",
        summary="access observation pass",
        agent_id="agent-2",
        test_name="mfa",
        controls=[{"control_id": "AC-1"}],
    )
    out = reconcile_control(uid, control_id="AC-1")
    assert out["dependencies"]["complete"] is True
    assert out["state"]["state"] == "pass"
    assert int(out["state"]["version"]) >= 1


def test_transition_bumps_version_and_stale_tick(tmp_path, monkeypatch):
    uid = _uid(monkeypatch, tmp_path, "crs_stale")
    from app.evidence_spine.control_state import (
        get_control_state,
        run_stale_tick,
        transition_control_state,
    )

    s1 = transition_control_state(
        uid,
        control_id="host_firewall",
        new_state="pass",
        source="test",
        last_observed_at=time.time() - (20 * 60),  # older than 15m policy
        detail={"test_name": "host_firewall"},
    )
    assert s1["state"] == "pass"
    assert int(s1["version"]) == 1

    tick = run_stale_tick(uid)
    assert tick["stale_transitions"] >= 1
    s2 = get_control_state(uid, control_id="host_firewall")
    assert s2 is not None
    assert s2["state"] == "stale"
    assert int(s2["version"]) == 2
    assert s2["previous_state"] == "pass"


def test_control_state_api(tmp_path, monkeypatch):
    configure_isolated_settings(monkeypatch, tmp_path)
    from fastapi.testclient import TestClient

    from app.auth import login, register_user
    from app.main import app
    from app.tenancy import ensure_tenant_schema

    ensure_tenant_schema()
    register_user("crs_api", "password123", role="admin")
    _, token = login("crs_api", "password123")
    client = TestClient(app)
    headers = {"Authorization": f"Bearer {token}"}

    r = client.post("/api/evidence-spine/dependencies/seed", headers=headers)
    assert r.status_code == 200
    assert r.json()["seeded"] >= 1

    r2 = client.get("/api/evidence-spine/dependencies?control_id=AT-2", headers=headers)
    assert r2.status_code == 200
    assert len(r2.json()["requirements"]) >= 2

    r3 = client.post(
        "/api/evidence-spine/control-state/transition",
        headers=headers,
        json={"control_id": "AT-2", "state": "evaluating", "source": "api"},
    )
    assert r3.status_code == 200
    assert r3.json()["state"]["state"] == "evaluating"

    r4 = client.post(
        "/api/evidence-spine/controls/AT-2/reconcile",
        headers=headers,
        json={},
    )
    assert r4.status_code == 200
    assert r4.json()["ok"] is True

    r5 = client.get("/api/evidence-spine/control-state", headers=headers)
    assert r5.status_code == 200
    assert len(r5.json()["states"]) >= 1
