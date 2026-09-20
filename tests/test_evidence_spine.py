"""Evidence Spine — Observation + Document → Evidence → Control."""

from __future__ import annotations

from tests._http_test_utils import configure_isolated_settings


def _uid(monkeypatch, tmp_path, name="spine_user"):
    configure_isolated_settings(monkeypatch, tmp_path)
    from app.auth import login, register_user
    from app.tenancy import ensure_tenant_schema

    ensure_tenant_schema()
    register_user(name, "password123", role="admin")
    u, _ = login(name, "password123")
    return u.id


def test_observation_and_document_same_control(tmp_path, monkeypatch):
    uid = _uid(monkeypatch, tmp_path, "spine_same")
    from app.evidence_spine import (
        evaluate_control_from_evidence,
        ingest_document_as_evidence,
        ingest_observation_as_evidence,
    )

    doc = ingest_document_as_evidence(
        uid,
        title="Firewall Policy.pdf",
        summary="Policy requires host firewall enabled",
        control_id="AC-1",
        framework_id="nist-800-53",
        file_id="file-policy-1",
    )
    assert doc["ok"] is True
    assert doc["evidence_id"]
    # Document alone → partial (not runtime proof)
    ev = evaluate_control_from_evidence(uid, control_id="AC-1", framework_id="nist-800-53")
    assert ev["result"] == "partial"
    assert ev["counts"]["documents"] >= 1

    obs = ingest_observation_as_evidence(
        uid,
        result="pass",
        summary="host_firewall:pass — Firewall enabled",
        agent_id="agent-lab-1",
        test_name="host_firewall",
        controls=[{"framework_id": "nist-800-53", "control_id": "AC-1"}],
    )
    assert obs["ok"] is True
    ev2 = evaluate_control_from_evidence(uid, control_id="AC-1", framework_id="nist-800-53")
    assert ev2["result"] == "pass"
    assert ev2["counts"]["observed_fresh_pass"] >= 1
    assert ev2["counts"]["documents"] >= 1

    fail = ingest_observation_as_evidence(
        uid,
        result="fail",
        summary="host_firewall:fail — Firewall disabled",
        agent_id="agent-lab-2",
        test_name="host_firewall",
        controls=[{"framework_id": "nist-800-53", "control_id": "AC-1"}],
    )
    assert fail["ok"] is True
    ev3 = evaluate_control_from_evidence(uid, control_id="AC-1", framework_id="nist-800-53")
    assert ev3["result"] == "fail"


def test_compliance_ops_note_becomes_evidence(tmp_path, monkeypatch):
    uid = _uid(monkeypatch, tmp_path, "spine_co")
    from app.compliance_ops.tasks import create_task, submit_evidence

    task = create_task(
        uid,
        {
            "title": "Attach access review evidence",
            "department": "IT",
            "control_id": "AC-2",
            "framework_id": "nist-800-53",
            "evidence_required": True,
            "due_at": 9999999999,
        },
    )
    out = submit_evidence(uid, task["id"], note="Signed access review spreadsheet")
    assert int(out.get("evidence_attached") or 0) == 1
    assert out.get("evidence_id") or (out.get("meta") or {}).get("evidence_id")


def test_evidence_spine_api(tmp_path, monkeypatch):
    configure_isolated_settings(monkeypatch, tmp_path)
    from fastapi.testclient import TestClient

    from app.auth import login, register_user
    from app.main import app
    from app.tenancy import ensure_tenant_schema

    ensure_tenant_schema()
    register_user("spine_api", "password123", role="admin")
    _, token = login("spine_api", "password123")
    client = TestClient(app)
    headers = {"Authorization": f"Bearer {token}"}
    r = client.post(
        "/api/evidence-spine/documents",
        headers=headers,
        json={
            "title": "Encryption standard",
            "control_id": "SC-13",
            "framework_id": "nist-800-53",
        },
    )
    assert r.status_code == 200
    eid = r.json()["evidence_id"]
    r2 = client.get(
        "/api/evidence-spine/controls/SC-13/evaluate?framework_id=nist-800-53",
        headers=headers,
    )
    assert r2.status_code == 200
    assert r2.json()["result"] == "partial"
    r3 = client.get(f"/api/evidence-spine/evidence/{eid}/controls", headers=headers)
    assert r3.status_code == 200
    assert len(r3.json()["controls"]) >= 1
