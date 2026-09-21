"""Multi-source observation reconciliation → canonical / conflict state."""

from __future__ import annotations

from tests._http_test_utils import configure_isolated_settings


def _uid(monkeypatch, tmp_path, name="recon_user"):
    configure_isolated_settings(monkeypatch, tmp_path)
    from app.auth import login, register_user
    from app.tenancy import ensure_tenant_schema

    ensure_tenant_schema()
    register_user(name, "password123", role="admin")
    u, _ = login(name, "password123")
    return u.id


def test_sources_agree_canonical_pass(tmp_path, monkeypatch):
    uid = _uid(monkeypatch, tmp_path, "recon_agree")
    from app.evidence_spine import ingest_observation_as_evidence, reconcile_observations

    host = "lab-fw-01"
    ingest_observation_as_evidence(
        uid,
        result="pass",
        summary="agent firewall on",
        data_source="agent",
        agent_id="ag-1",
        hostname=host,
        test_name="host_firewall",
    )
    ingest_observation_as_evidence(
        uid,
        result="on",
        summary="cloud firewall enabled",
        data_source="cloud",
        source_ref="aws-sg-1",
        hostname=host,
        test_name="host_firewall",
    )
    out = reconcile_observations(uid, check_id="host_firewall", hostname=host)
    assert out["detection"]["conflict_status"] == "agreed"
    assert out["detection"]["canonical_result"] == "pass"
    assert out["state"]["conflict_status"] == "agreed"


def test_sources_conflict_requires_human(tmp_path, monkeypatch):
    uid = _uid(monkeypatch, tmp_path, "recon_conflict")
    from app.evidence_spine import (
        ingest_observation_as_evidence,
        list_canonical_states,
        reconcile_observations,
        resolve_conflict,
    )

    host = "lab-fw-02"
    ingest_observation_as_evidence(
        uid,
        result="pass",
        summary="agent says ON",
        data_source="agent",
        agent_id="ag-2",
        hostname=host,
        test_name="host_firewall",
    )
    ingest_observation_as_evidence(
        uid,
        result="fail",
        summary="cloud says OFF",
        data_source="cloud",
        source_ref="aws-sg-2",
        hostname=host,
        test_name="host_firewall",
    )
    ingest_observation_as_evidence(
        uid,
        result="open",
        summary="scanner port exposed",
        data_source="scanner",
        source_ref="nmap-1",
        hostname=host,
        test_name="host_firewall",
    )
    out = reconcile_observations(uid, check_id="host_firewall", hostname=host)
    assert out["detection"]["conflict_status"] == "conflict"
    assert out["detection"]["canonical_result"] == "conflict"
    assert out["state"]["resolution"] == "pending"

    conflicts = list_canonical_states(uid, conflict_status="conflict")
    assert len(conflicts) >= 1
    sk = out["subject_key"]

    resolved = resolve_conflict(
        uid,
        subject_key_val=sk,
        check_id="host_firewall",
        result="fail",
        resolved_by="analyst",
        note="Cloud + scanner more trustworthy for exposure",
    )
    assert resolved["state"]["conflict_status"] == "agreed"
    assert resolved["state"]["canonical_result"] == "fail"
    assert resolved["state"]["resolution"] == "human"


def test_reconciliation_api(tmp_path, monkeypatch):
    configure_isolated_settings(monkeypatch, tmp_path)
    from fastapi.testclient import TestClient

    from app.auth import login, register_user
    from app.main import app
    from app.tenancy import ensure_tenant_schema

    ensure_tenant_schema()
    register_user("recon_api", "password123", role="admin")
    _, token = login("recon_api", "password123")
    client = TestClient(app)
    headers = {"Authorization": f"Bearer {token}"}

    host = "api-host-1"
    client.post(
        "/api/evidence-spine/observations",
        headers=headers,
        json={
            "result": "pass",
            "data_source": "agent",
            "agent_id": "ag-api",
            "hostname": host,
            "test_name": "host_firewall",
        },
    )
    client.post(
        "/api/evidence-spine/observations",
        headers=headers,
        json={
            "result": "fail",
            "data_source": "cloud",
            "source_ref": "c-1",
            "hostname": host,
            "test_name": "host_firewall",
        },
    )
    r = client.post(
        "/api/evidence-spine/observations/reconcile",
        headers=headers,
        json={"check_id": "host_firewall", "hostname": host},
    )
    assert r.status_code == 200
    body = r.json()
    assert body["detection"]["conflict_status"] == "conflict"
    sk = body["subject_key"]
    r2 = client.post(
        "/api/evidence-spine/observations/resolve",
        headers=headers,
        json={
            "subject_key": sk,
            "check_id": "host_firewall",
            "result": "fail",
            "note": "Prefer cloud",
        },
    )
    assert r2.status_code == 200
    assert r2.json()["state"]["canonical_result"] == "fail"
    r3 = client.get(
        "/api/evidence-spine/observations/canonical?conflict_status=agreed",
        headers=headers,
    )
    assert r3.status_code == 200
    assert len(r3.json()["states"]) >= 1
