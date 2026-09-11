"""HTTP-layer tests for the compliance document library
(app.services.compliance_doc_library + app.compliance_doc_library_api).

The behavior under test that matters most: approving a document is not a
status flag flip -- it must produce a real evidence_links row (visible via
GET /api/evidence) backed by a real file written to disk (visible via
GET /api/files), and editing an approved document's content must knock it
back to draft rather than leaving stale "approved" evidence sitting around.
"""

from __future__ import annotations

from tests._http_test_utils import configure_isolated_settings


def _client_and_token(tmp_path, monkeypatch, username="doclib_tester"):
    configure_isolated_settings(monkeypatch, tmp_path)
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    from app.auth import login, register_user
    from app.commercial_api import router as commercial_router
    from app.commercial_ext_api import router as commercial_ext_router
    from app.compliance_doc_library_api import router as doc_router
    from app.tenancy import ensure_tenant_schema

    ensure_tenant_schema()
    register_user(username, "password123", role="admin")
    u, token = login(username, "password123")

    test_app = FastAPI()
    test_app.include_router(doc_router)
    test_app.include_router(commercial_ext_router)  # GET/POST /api/evidence
    test_app.include_router(commercial_router)  # GET /api/files
    client = TestClient(test_app)
    return client, token, u.id


def _auth(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


def test_documents_require_auth(tmp_path, monkeypatch):
    client, _token, _uid = _client_and_token(tmp_path, monkeypatch)
    res = client.get("/api/compliance/documents")
    assert res.status_code == 401


def test_templates_are_listed(tmp_path, monkeypatch):
    client, token, _uid = _client_and_token(tmp_path, monkeypatch)
    res = client.get("/api/compliance/documents/templates", headers=_auth(token))
    assert res.status_code == 200, res.text
    templates = res.json()["templates"]
    assert len(templates) >= 5
    ids = {t["id"] for t in templates}
    assert "access_control_policy" in ids
    assert "blank" in ids
    # Templates are skeletons only -- never pre-filled section content.
    for t in templates:
        assert "sections" not in t  # list endpoint omits body; section_count is the summary
        assert "section_count" in t


def test_create_document_from_template(tmp_path, monkeypatch):
    client, token, _uid = _client_and_token(tmp_path, monkeypatch)
    res = client.post(
        "/api/compliance/documents",
        headers=_auth(token),
        json={
            "title": "Acme Access Control Policy",
            "template_id": "access_control_policy",
            "control_id": "AC.L2-3.1.1",
            "owner": "Jane Admin",
        },
    )
    assert res.status_code == 200, res.text
    doc = res.json()
    assert doc["status"] == "draft"
    assert doc["version"] == 1
    assert doc["template_id"] == "access_control_policy"
    assert doc["family"] == "AC"
    assert len(doc["sections"]) >= 5
    # Skeleton sections start empty -- no invented compliance content.
    assert all(s["content"] == "" for s in doc["sections"])


def test_full_lifecycle_approve_creates_real_evidence(tmp_path, monkeypatch):
    client, token, _uid = _client_and_token(tmp_path, monkeypatch)
    create = client.post(
        "/api/compliance/documents",
        headers=_auth(token),
        json={"title": "Incident Response Plan", "template_id": "incident_response_plan", "control_id": "IR.L2-3.6.1"},
    ).json()
    doc_id = create["id"]

    # Modify: fill in real section content.
    sections = create["sections"]
    for s in sections:
        s["content"] = f"Real text for {s['heading']}."
    patch = client.patch(
        f"/api/compliance/documents/{doc_id}",
        headers=_auth(token),
        json={"sections": sections, "owner": "Security Lead"},
    )
    assert patch.status_code == 200, patch.text
    assert patch.json()["version"] == 2

    # Review: submit -> approve.
    submit = client.post(f"/api/compliance/documents/{doc_id}/submit", headers=_auth(token))
    assert submit.status_code == 200
    assert submit.json()["status"] == "in_review"

    approve = client.post(
        f"/api/compliance/documents/{doc_id}/review",
        headers=_auth(token),
        json={"decision": "approve", "reviewer": "CISO Bob"},
    )
    assert approve.status_code == 200, approve.text
    approved = approve.json()
    assert approved["status"] == "approved"
    assert approved["file_id"]
    assert approved["evidence_link_id"]

    # Real evidence: shows up in the same evidence register the manual
    # upload-and-link flow uses, pointing at a real file with real bytes.
    ev_res = client.get("/api/evidence", headers=_auth(token))
    assert ev_res.status_code == 200
    links = ev_res.json()["evidence"]
    match = next((l for l in links if l["id"] == approved["evidence_link_id"]), None)
    assert match is not None
    assert match["control_id"] == "IR.L2-3.6.1"
    assert match["status"] == "accepted"
    assert match["file_id"] == approved["file_id"]
    assert match["size_bytes"] > 0  # real file, not a zero-byte placeholder

    files_res = client.get("/api/files", headers=_auth(token))
    file_ids = {f["id"] for f in files_res.json().get("files", files_res.json().get("items", []))}
    assert approved["file_id"] in file_ids


def test_editing_approved_document_reverts_to_draft(tmp_path, monkeypatch):
    client, token, _uid = _client_and_token(tmp_path, monkeypatch)
    create = client.post(
        "/api/compliance/documents",
        headers=_auth(token),
        json={"title": "Config Mgmt Policy", "template_id": "configuration_management_policy"},
    ).json()
    doc_id = create["id"]
    client.post(f"/api/compliance/documents/{doc_id}/submit", headers=_auth(token))
    approve = client.post(
        f"/api/compliance/documents/{doc_id}/review",
        headers=_auth(token),
        json={"decision": "approve", "reviewer": "Reviewer"},
    ).json()
    assert approve["status"] == "approved"

    # Any edit to the rendered content (title here) must drop it back to
    # draft -- an "approved" doc whose text no longer matches its evidence
    # file would be exactly the silent drift this product refuses to allow.
    patch = client.patch(
        f"/api/compliance/documents/{doc_id}",
        headers=_auth(token),
        json={"title": "Config Mgmt Policy (revised)"},
    )
    assert patch.status_code == 200
    reverted = patch.json()
    assert reverted["status"] == "draft"
    assert reverted["approved_at"] is None


def test_reject_does_not_create_evidence(tmp_path, monkeypatch):
    client, token, _uid = _client_and_token(tmp_path, monkeypatch)
    create = client.post(
        "/api/compliance/documents",
        headers=_auth(token),
        json={"title": "Risk Assessment Policy", "template_id": "risk_assessment_policy"},
    ).json()
    doc_id = create["id"]
    client.post(f"/api/compliance/documents/{doc_id}/submit", headers=_auth(token))
    reject = client.post(
        f"/api/compliance/documents/{doc_id}/review",
        headers=_auth(token),
        json={"decision": "reject", "reviewer": "Reviewer", "comments": "Needs more detail in Policy section."},
    )
    assert reject.status_code == 200, reject.text
    rejected = reject.json()
    assert rejected["status"] == "rejected"
    assert not rejected["evidence_link_id"]
    assert not rejected["file_id"]

    ev_res = client.get("/api/evidence", headers=_auth(token))
    assert ev_res.json()["evidence"] == []


def test_delete_document(tmp_path, monkeypatch):
    client, token, _uid = _client_and_token(tmp_path, monkeypatch)
    create = client.post(
        "/api/compliance/documents",
        headers=_auth(token),
        json={"title": "Throwaway", "template_id": "blank"},
    ).json()
    doc_id = create["id"]
    res = client.delete(f"/api/compliance/documents/{doc_id}", headers=_auth(token))
    assert res.status_code == 200
    res2 = client.get(f"/api/compliance/documents/{doc_id}", headers=_auth(token))
    assert res2.status_code == 404


def test_documents_are_scoped_per_user(tmp_path, monkeypatch):
    client_a, token_a, _ = _client_and_token(tmp_path, monkeypatch, username="doclib_user_a")
    from app.auth import login, register_user

    register_user("doclib_user_b", "password123", role="admin")
    _u_b, token_b = login("doclib_user_b", "password123")

    created = client_a.post(
        "/api/compliance/documents",
        headers=_auth(token_a),
        json={"title": "User A's policy", "template_id": "blank"},
    ).json()

    # Same TestClient/app, different user's token -- must not see it.
    res = client_a.get(f"/api/compliance/documents/{created['id']}", headers=_auth(token_b))
    assert res.status_code == 404
    list_res = client_a.get("/api/compliance/documents", headers=_auth(token_b))
    assert list_res.json()["documents"] == []
