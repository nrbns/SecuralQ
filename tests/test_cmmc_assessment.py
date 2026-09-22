"""CMMC assessment layer — objectives, methods, POA&M policy, SPRS prep."""

from __future__ import annotations

import importlib

from tests._http_test_utils import configure_isolated_settings


def _uid(monkeypatch, tmp_path, name="cmmc_user"):
    configure_isolated_settings(monkeypatch, tmp_path)
    from app.auth import login, register_user
    from app.tenancy import ensure_tenant_schema

    ensure_tenant_schema()
    register_user(name, "password123", role="admin")
    u, _ = login(name, "password123")
    return u.id


def test_seed_objectives_and_control_assessment(tmp_path, monkeypatch):
    uid = _uid(monkeypatch, tmp_path, "cmmc_obj")
    from app.cmmc import (
        get_control_assessment,
        list_objectives,
        seed_objectives_for_framework,
        set_objective_status,
    )

    out = seed_objectives_for_framework("cmmc_l2")
    assert out["ok"] is True
    assert out["seeded"] >= 330  # 110 * 3
    objs = list_objectives("cmmc_l2", control_id="AC.L2-3.1.1")
    assert len(objs) == 3
    methods = {o["method"] for o in objs}
    assert methods == {"examine", "interview", "test"}

    set_objective_status(uid, objs[0]["id"], status="met", reviewer="alice")
    set_objective_status(uid, objs[1]["id"], status="met", reviewer="alice")
    set_objective_status(uid, objs[2]["id"], status="not_met", reviewer="alice")
    detail = get_control_assessment(uid, "cmmc_l2", "AC.L2-3.1.1")
    assert detail["rollup_status"] == "not_met"
    assert detail["counts"]["met"] == 2
    assert detail["counts"]["not_met"] == 1
    assert "poam_policy" in detail


def test_poam_policy_blocks_ineligible_control(tmp_path, monkeypatch):
    uid = _uid(monkeypatch, tmp_path, "cmmc_poam")
    from app.cmmc import open_poam_item, poam_policy_for_control
    from app.controls.catalog import list_framework_controls

    # Find a control with poam_eligible=false
    blocked = None
    allowed = None
    for c in list_framework_controls("cmmc_l2"):
        elig = (c.raw or {}).get("poam_eligible")
        if elig is False and blocked is None:
            blocked = c.id
        if elig is True and allowed is None:
            allowed = c.id
        if blocked and allowed:
            break
    assert blocked and allowed
    pol = poam_policy_for_control("cmmc_l2", blocked)
    assert pol["poam_permitted_for_control"] is False
    import pytest

    with pytest.raises(ValueError, match="not permitted"):
        open_poam_item(
            uid,
            framework_id="cmmc_l2",
            control_id=blocked,
            weakness="gap",
            owner="owner",
        )
    item = open_poam_item(
        uid,
        framework_id="cmmc_l2",
        control_id=allowed,
        weakness="Missing MFA on CUI workstation",
        owner="sec-ops",
    )
    assert item["status"] == "open"
    assert item.get("due_at")


def test_method_evidence_and_sprs_prep(tmp_path, monkeypatch):
    uid = _uid(monkeypatch, tmp_path, "cmmc_meth")
    from app.cmmc import (
        record_method_evidence,
        seed_objectives_for_framework,
        sprs_preparation_snapshot,
        upsert_cui_program,
    )

    seed_objectives_for_framework("cmmc_l2")
    ev = record_method_evidence(
        uid,
        framework_id="cmmc_l2",
        control_id="AC.L2-3.1.1",
        method="examine",
        title="Access control policy",
        detail={"document": "AC-Policy-v3.pdf"},
        result="pass",
        reviewer="auditor",
    )
    assert ev.get("method") == "examine"
    assert ev.get("evidence_id")

    prog = upsert_cui_program(
        uid,
        name="CUI Enclave A",
        boundary_notes="Isolated VLAN + SPA firewall",
        categories=["CUI", "FCI"],
        data_flows=[{"from": "endpoint", "to": "file-share", "data": "CUI"}],
    )
    assert prog["name"] == "CUI Enclave A"

    snap = sprs_preparation_snapshot(uid, framework_id="cmmc_l2")
    assert snap["ok"] is True
    assert snap["requirement_counts"]["total"] == 110
    assert "disclaimer" in snap
    assert "SPRS" in snap["disclaimer"]
    assert snap["framework"]["version"]


def test_cmmc_api_smoke(tmp_path, monkeypatch):
    configure_isolated_settings(monkeypatch, tmp_path)
    from fastapi.testclient import TestClient

    from app.auth import login, register_user
    from app.main import app
    from app.tenancy import ensure_tenant_schema

    ensure_tenant_schema()
    register_user("cmmc_api", "password123", role="admin")
    _, token = login("cmmc_api", "password123")
    client = TestClient(app)
    headers = {"Authorization": f"Bearer {token}"}
    r = client.post("/api/cmmc/objectives/seed?framework_id=cmmc_l2", headers=headers)
    assert r.status_code == 200, r.text
    r2 = client.get(
        "/api/cmmc/controls/AC.L2-3.1.1/assessment?framework_id=cmmc_l2",
        headers=headers,
    )
    assert r2.status_code == 200
    body = r2.json()
    assert body["ok"] is True
    assert len(body["objectives"]) == 3
    r3 = client.get("/api/cmmc/sprs-preparation?framework_id=cmmc_l2", headers=headers)
    assert r3.status_code == 200
    assert r3.json()["requirement_counts"]["total"] == 110
    r4 = client.get("/api/cmmc/version?framework_id=cmmc_l2", headers=headers)
    assert r4.status_code == 200
    assert "status_note" in r4.json()


def test_ssp_readiness_gap_interview_cui(tmp_path, monkeypatch):
    uid = _uid(monkeypatch, tmp_path, "cmmc_tier1b")
    from app.cmmc import (
        build_evidence_gap_plan,
        classify_evidence,
        control_readiness_confidence,
        create_interview,
        get_control_ssp_pack,
        record_method_evidence,
        review_interview,
        seed_objectives_for_framework,
        ssp_engine_snapshot,
        submit_interview_response,
        upsert_cui_program,
        upsert_implementation_statement,
        user_may_access_evidence,
    )

    seed_objectives_for_framework("cmmc_l2")
    upsert_implementation_statement(
        uid,
        framework_id="cmmc_l2",
        control_id="AC.L2-3.1.1",
        statement="MFA enforced via Entra ID Conditional Access for CUI workstations.",
        technology="Entra ID + Intune",
    )
    pack = get_control_ssp_pack(uid, "cmmc_l2", "AC.L2-3.1.1")
    assert pack["implementation"]["source"] == "authored"
    assert "MFA" in pack["implementation"]["statement"]

    record_method_evidence(
        uid,
        framework_id="cmmc_l2",
        control_id="AC.L2-3.1.1",
        method="examine",
        title="AC policy",
        result="pass",
    )
    conf = control_readiness_confidence(uid, "cmmc_l2", "AC.L2-3.1.1")
    assert conf["overall"]["band"] in {"LOW", "MEDIUM", "HIGH"}
    assert "signals" in conf

    plan = build_evidence_gap_plan(uid, "cmmc_l2", owner_default="sec-ops")
    assert plan["ok"] is True
    assert plan["summary"]["tasks_generated"] > 0

    iv = create_interview(
        uid,
        framework_id="cmmc_l2",
        control_id="AC.L2-3.1.1",
        question="How is MFA enforced for CUI users?",
        person="Jane Admin",
        role="Identity Owner",
    )
    submit_interview_response(uid, iv["id"], response="CA policy requires MFA.")
    reviewed = review_interview(
        uid, iv["id"], decision="approved", reviewer="auditor"
    )
    assert reviewed["status"] in {"approved", "attested"}
    assert reviewed.get("evidence_id") or reviewed.get("method_evidence_id")

    prog = upsert_cui_program(
        uid,
        name="CUI Boundary B",
        boundary_notes="VLAN 40",
        categories=["CUI"],
        cui_assets=[{"asset_id": "ws-01", "hostname": "cui-ws-01"}],
        cui_systems=[{"name": "FileShare"}],
        cui_users=[{"name": "Jane", "role": "CUI user"}],
        repositories=[{"name": "SharePoint CUI"}],
    )
    assert prog["scope_summary"]["assets"] == 1
    assert prog["cui_systems"][0]["name"] == "FileShare"

    # CUI evidence ACL
    ev = record_method_evidence(
        uid,
        framework_id="cmmc_l2",
        control_id="AC.L2-3.1.1",
        method="test",
        title="MFA check",
        result="pass",
    )
    eid = ev["evidence_id"]
    classify_evidence(uid, eid, classification="cui", cui_program_id=prog["id"])
    denied = user_may_access_evidence(uid, eid, user_roles=[])
    # owner path allows
    assert denied["allowed"] is True or denied["reason"] == "owner"
    denied2 = user_may_access_evidence(uid, eid, user_roles=["guest"])
    # guest without owner match: if same user_id still owner-allowed
    assert denied2["allowed"] is True  # owner of evidence row

    snap = ssp_engine_snapshot(uid, "cmmc_l2")
    assert snap["ok"] is True
    assert snap["controls_total"] == 110


def test_worm_and_realtime_reconstruct(tmp_path, monkeypatch):
    uid = _uid(monkeypatch, tmp_path, "cmmc_worm")
    from app.evidence_spine.worm import record_worm_lock, worm_backend_status
    from app.realtime_bus import detect_sequence_gaps, publish, replay_with_state

    st = worm_backend_status()
    assert st["configured"] is False
    lock = record_worm_lock(uid, content_hash="a" * 64, vault_id="v1", evidence_id="e1")
    assert lock["status"] == "local_marker"

    publish(type="test", event_type="test.gap", user_id=uid, sequence=1)
    publish(type="test", event_type="test.gap", user_id=uid, sequence=2)
    publish(type="test", event_type="test.gap", user_id=uid, sequence=4)
    pack = replay_with_state(None, limit=50)
    assert pack["ok"] is True
    gaps = detect_sequence_gaps(
        [{"sequence": 1}, {"sequence": 2}, {"sequence": 4}]
    )
    assert gaps["gap_detected"] is True
    assert 3 in gaps["missing"]


def test_management_view_and_audit_pack(tmp_path, monkeypatch):
    uid = _uid(monkeypatch, tmp_path, "cmmc_mgmt")
    from app.cmmc.audit_pack import build_cmmc_audit_pack_zip
    from app.cmmc.management_view import cmmc_management_view
    from app.cmmc.objectives import seed_objectives_for_framework

    seed_objectives_for_framework("cmmc_l2")
    view = cmmc_management_view(uid, framework_id="cmmc_l2")
    assert view["ok"] is True
    assert view["requirements"]["total"] == 110
    assert "assessment_readiness_percent" in view
    assert "disclaimer" in view

    blob = build_cmmc_audit_pack_zip(uid, framework_id="cmmc_l2")
    assert blob[:2] == b"PK"
    assert len(blob) > 1000


def test_cross_framework_propagate_and_scim_groups(tmp_path, monkeypatch):
    configure_isolated_settings(monkeypatch, tmp_path)
    monkeypatch.setenv("SCIM_ENABLED", "true")
    monkeypatch.setenv("SCIM_TOKEN", "test-scim-token")
    from app.config import settings

    settings.scim_enabled = True
    settings.scim_token = "test-scim-token"

    from app.auth import login, register_user
    from app.services.cross_framework_evidence import sibling_controls_via_canonical
    from app.services.evidence import record_evidence
    from app.evidence_spine.mapping import link_evidence_to_control
    from app.tenancy import ensure_tenant_schema
    from fastapi.testclient import TestClient
    from app.main import app

    ensure_tenant_schema()
    register_user("xf_user", "password123", role="admin")
    u, token = login("xf_user", "password123")

    sibs = sibling_controls_via_canonical("cmmc_l2", "IA.L2-3.5.3")
    assert any(s["framework_id"] == "nist_800_171" for s in sibs)

    ev = record_evidence(
        u.id,
        entity_type="policy",
        entity_id="mfa-policy",
        source="declared",
        summary="MFA policy v1",
        verified=True,
    )
    linked = link_evidence_to_control(
        u.id,
        ev["id"],
        control_id="IA.L2-3.5.3",
        framework_id="cmmc_l2",
        role="documents",
        propagate_canonical=True,
    )
    prop = linked.get("canonical_propagation") or {}
    assert prop.get("ok") is True
    assert prop.get("siblings_considered", 0) >= 1

    client = TestClient(app)
    headers = {"Authorization": "Bearer test-scim-token"}
    r = client.post(
        "/scim/v2/Groups",
        headers=headers,
        json={"displayName": "CMMC Team", "members": [{"value": u.id, "display": "xf_user"}]},
    )
    assert r.status_code == 201, r.text
    gid = r.json()["id"]
    r2 = client.get(f"/scim/v2/Groups/{gid}", headers=headers)
    assert r2.status_code == 200
    assert r2.json()["displayName"] == "CMMC Team"
    st = client.get("/scim/v2/status")
    assert "Groups" in st.json()["supported"]
