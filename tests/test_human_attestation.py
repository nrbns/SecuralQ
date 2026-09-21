"""Human attestation + exception renew + vault review attestation."""

from __future__ import annotations

import time

from tests._http_test_utils import configure_isolated_settings


def _uid(monkeypatch, tmp_path, name="hattest"):
    configure_isolated_settings(monkeypatch, tmp_path)
    from app.auth import login, register_user
    from app.tenancy import ensure_tenant_schema

    ensure_tenant_schema()
    register_user(name, "password123", role="admin")
    u, _ = login(name, "password123")
    return u.id


def test_vault_accept_records_human_attestation(tmp_path, monkeypatch):
    uid = _uid(monkeypatch, tmp_path, "hattest_vault")
    from app.evidence_spine.vault import create_vault_document, set_review_status
    from app.services.human_attestation import list_attestations

    v = create_vault_document(
        uid,
        title="Q1 Access Review",
        filename="access.txt",
        data=b"reviewed users list",
        control_id="AC-2",
        framework_id="nist-800-53",
    )
    vid = v["vault"]["id"]
    set_review_status(uid, vid, status="accepted", note="Looks complete", reviewed_by=uid)
    rows = list_attestations(uid, subject_type="vault", subject_id=vid)
    assert len(rows) >= 1
    assert rows[0]["decision"] == "approved"
    assert rows[0]["reviewed_by"] == uid
    assert rows[0]["comment"] == "Looks complete"


def test_exception_approve_and_renew(tmp_path, monkeypatch):
    uid = _uid(monkeypatch, tmp_path, "hattest_exc")
    from app.services.exceptions import (
        approve_exception,
        create_exception,
        get_exception,
        renew_exception,
    )
    from app.services.human_attestation import list_attestations

    exp = time.time() + 30 * 86400
    ex = create_exception(
        uid,
        title="Temp FW exception",
        reason="Change window",
        risk_accepted="Residual exposure accepted for 30 days",
        owner=uid,
        expiry=exp,
        control_id="host_firewall",
        created_by=uid,
    )
    approved = approve_exception(uid, ex["id"], approved_by=uid)
    assert approved["status"] == "approved"
    atts = list_attestations(uid, subject_type="exception", subject_id=ex["id"])
    assert any(a["decision"] == "approved" for a in atts)

    renewed = renew_exception(
        uid,
        ex["id"],
        new_expiry=time.time() + 60 * 86400,
        renewed_by=uid,
        note="Need another window",
    )
    assert renewed["ok"] is True
    prev = get_exception(uid, ex["id"])
    assert prev["status"] == "revoked"
    assert renewed["exception"]["status"] == "pending_approval"


def test_attestation_api(tmp_path, monkeypatch):
    configure_isolated_settings(monkeypatch, tmp_path)
    from fastapi.testclient import TestClient

    from app.auth import login, register_user
    from app.main import app
    from app.tenancy import ensure_tenant_schema

    ensure_tenant_schema()
    register_user("hattest_api", "password123", role="admin")
    _, token = login("hattest_api", "password123")
    client = TestClient(app)
    headers = {"Authorization": f"Bearer {token}"}
    r = client.post(
        "/api/attestations",
        headers=headers,
        json={
            "subject_type": "framework",
            "decision": "attested",
            "title": "Annual management review",
            "comment": "Board reviewed Q4 posture",
            "framework_id": "iso27001",
        },
    )
    assert r.status_code == 200
    assert r.json()["decision"] == "attested"
    r2 = client.get("/api/attestations", headers=headers)
    assert r2.status_code == 200
    assert len(r2.json()["attestations"]) >= 1
