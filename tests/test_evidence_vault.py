"""Evidence Vault — versioning, SHA-256 integrity, freshness policies."""

from __future__ import annotations

import time

from tests._http_test_utils import configure_isolated_settings


def _uid(monkeypatch, tmp_path, name="vault_user"):
    configure_isolated_settings(monkeypatch, tmp_path)
    from app.auth import login, register_user
    from app.tenancy import ensure_tenant_schema

    ensure_tenant_schema()
    register_user(name, "password123", role="admin")
    u, _ = login(name, "password123")
    return u.id


def test_vault_upload_supersede_preserves_history(tmp_path, monkeypatch):
    uid = _uid(monkeypatch, tmp_path, "vault_hist")
    from app.evidence_spine.vault import create_vault_document, get_vault_item, supersede_vault_document

    v1 = create_vault_document(
        uid,
        title="Information Security Policy",
        filename="policy-v1.pdf",
        data=b"%PDF-1.4 policy version one content",
        control_id="A.5.1",
        framework_id="iso27001",
        notes="Initial policy",
    )
    assert v1["ok"] is True
    vault_id = v1["vault"]["id"]
    eid1 = v1["vault"]["current_evidence_id"]
    assert v1["version_count"] == 1
    sha1 = v1["versions"][0]["content_sha256"]
    assert len(sha1) == 64

    v2 = supersede_vault_document(
        uid,
        vault_id,
        filename="policy-v2.pdf",
        data=b"%PDF-1.4 policy version TWO revised",
        notes="Annual revision",
    )
    assert v2["version_count"] == 2
    eid2 = v2["vault"]["current_evidence_id"]
    assert eid2 != eid1
    assert v2["versions"][0]["version_num"] == 2
    assert v2["versions"][0]["previous_evidence_id"] == eid1
    # Prior version retained and marked superseded
    older = [x for x in v2["versions"] if x["evidence_id"] == eid1][0]
    assert older["superseded_at"] is not None
    assert older["superseded_by"] == eid2
    # History still queryable
    item = get_vault_item(uid, vault_id)
    assert len(item["versions"]) == 2


def test_vault_review_accept_rejects(tmp_path, monkeypatch):
    uid = _uid(monkeypatch, tmp_path, "vault_rev")
    from app.evidence_spine.vault import create_vault_document, set_review_status
    from app.services.evidence import get_evidence

    v = create_vault_document(
        uid,
        title="Training roster",
        filename="roster.txt",
        data=b"employee training completion list\n",
        control_id="AT-2",
    )
    vid = v["vault"]["id"]
    eid = v["vault"]["current_evidence_id"]
    pending = set_review_status(uid, vid, status="pending_review")
    assert pending["vault"]["review_status"] == "pending_review"
    accepted = set_review_status(uid, vid, status="accepted", note="Looks good")
    assert accepted["vault"]["review_status"] == "accepted"
    ev = get_evidence(uid, eid)
    assert ev and ev.get("verified") is True


def test_freshness_policy_marks_stale(tmp_path, monkeypatch):
    uid = _uid(monkeypatch, tmp_path, "vault_fresh")
    from app.evidence_spine.freshness import apply_freshness_to_result, list_freshness_policies

    policies = list_freshness_policies()
    assert any(p["id"] == "host_firewall" for p in policies)
    fresh = apply_freshness_to_result(
        result="pass",
        last_observed=time.time(),
        control_or_test="host_firewall",
    )
    assert fresh["stale"] is False
    assert fresh["effective_result"] == "pass"
    stale = apply_freshness_to_result(
        result="pass",
        last_observed=time.time() - 3600,
        control_or_test="host_firewall",
    )
    assert stale["stale"] is True
    assert stale["effective_result"] == "stale"


def test_vault_api_upload(tmp_path, monkeypatch):
    configure_isolated_settings(monkeypatch, tmp_path)
    from fastapi.testclient import TestClient

    from app.auth import login, register_user
    from app.main import app
    from app.tenancy import ensure_tenant_schema

    ensure_tenant_schema()
    register_user("vault_api", "password123", role="admin")
    _, token = login("vault_api", "password123")
    client = TestClient(app)
    headers = {"Authorization": f"Bearer {token}"}
    files = {"file": ("policy.pdf", b"%PDF-1.4 hello vault", "application/pdf")}
    data = {"title": "API Policy", "control_id": "AC-1", "framework_id": "nist-800-53"}
    r = client.post("/api/evidence-spine/vault/upload", headers=headers, files=files, data=data)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body.get("ok") is True
    assert body["vault"]["current_evidence_id"]
    vid = body["vault"]["id"]
    r2 = client.get(f"/api/evidence-spine/vault/{vid}", headers=headers)
    assert r2.status_code == 200
    r3 = client.get("/api/evidence-spine/freshness-policies", headers=headers)
    assert r3.status_code == 200
    assert len(r3.json()["policies"]) >= 5
